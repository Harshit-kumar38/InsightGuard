"""
realtime_scoring.py
====================
Lightweight real-time version of the ML detection logic (Isolation Forest +
z-score + rules from detect_anomalies.py), designed to score ONE new event
instantly when it arrives via /api/ingest — instead of needing to re-run
the full batch script.

How it works:
  - On backend startup, we load all existing access_logs + users from the
    database ONCE, and compute each user's personal baseline stats
    (average login hour, average data volume, which resources their
    department normally uses). This is cached in memory.
  - When a new event arrives, we compare it against that user's cached
    baseline using the same z-score + rule-based logic as the batch script,
    and produce a risk_score + reason immediately.

This keeps the same explainable logic as your offline ML script, just
applied to a single incoming event instead of the whole historical dataset.
"""

from sqlalchemy.orm import Session
from sqlalchemy import text
import numpy as np

# ----------------------------------------------------------------------
# In-memory cache — populated once at startup, refreshed periodically
# ----------------------------------------------------------------------
_baseline_cache = {
    "user_stats": {},        # user_id -> {mean_hour, std_hour, mean_volume, std_volume}
    "resource_allowed_depts": {},  # resource_name -> set of departments that normally use it
    "loaded": False,
}


def build_baseline_cache(db: Session):
    """
    Computes per-user behavioral baselines and resource-department mappings
    from all historical access_logs currently in the database. Call this
    once at startup (and optionally re-call periodically to stay fresh).
    """
    rows = db.execute(text("""
        SELECT al.user_id, al.timestamp, al.data_volume_mb, al.resource_accessed,
               al.department, u.typical_login_hour
        FROM access_logs al
        JOIN users u ON al.user_id = u.user_id
    """)).fetchall()

    if not rows:
        _baseline_cache["loaded"] = True
        return

    # --- Per-user stats ---
    from collections import defaultdict
    user_hours = defaultdict(list)
    user_volumes = defaultdict(list)
    resource_dept_counts = defaultdict(lambda: defaultdict(int))

    for row in rows:
        user_id, ts, volume, resource, dept, typical_hour = row
        hour = ts.hour if hasattr(ts, "hour") else int(str(ts).split(" ")[1].split(":")[0])
        hour_deviation = abs(hour - (typical_hour or 9.5))
        user_hours[user_id].append(hour_deviation)
        user_volumes[user_id].append(volume or 0)
        resource_dept_counts[resource][dept] += 1

    user_stats = {}
    for user_id in user_hours:
        hours = np.array(user_hours[user_id])
        volumes = np.array(user_volumes[user_id])
        user_stats[user_id] = {
            "mean_hour_dev": float(hours.mean()),
            "std_hour_dev": float(hours.std()) or 1.0,
            "mean_volume": float(volumes.mean()),
            "std_volume": float(volumes.std()) or 1.0,
        }

    # --- Resource -> allowed departments (>=8% share, same rule as batch script) ---
    resource_allowed = {}
    for resource, dept_counts in resource_dept_counts.items():
        total = sum(dept_counts.values())
        allowed = {dept for dept, count in dept_counts.items() if count / total >= 0.08}
        resource_allowed[resource] = allowed

    _baseline_cache["user_stats"] = user_stats
    _baseline_cache["resource_allowed_depts"] = resource_allowed
    _baseline_cache["loaded"] = True
    print(f"[realtime_scoring] Baseline cache built for {len(user_stats)} users, "
          f"{len(resource_allowed)} resources.")


def score_event(user_id: str, department: str, resource_accessed: str,
                 data_volume_mb: float, resource_sensitivity: int,
                 event_hour: int, typical_login_hour: float,
                 recent_alert_count: int = 0):
    """
    Scores a single new event in real time, combining THREE things:

    1. Event severity — how unusual is THIS specific event, on a smooth
       scale (not a hard on/off switch). A slightly odd hour scores lower
       than an extremely odd hour; a 160MB download scores lower than an
       800MB download.
    2. Statistical deviation (z-score) — how far this event is from the
       user's own personal baseline behavior.
    3. Escalation — if this same person has been flagged recently before,
       each repeat offense pushes their score higher. A first-time minor
       slip looks very different from a fifth flagged event this week.

    `recent_alert_count` = number of alerts already on record for this user
    in the recent window (passed in by the caller, e.g. last 30 days).
    """
    stats = _baseline_cache["user_stats"].get(user_id)
    if stats is None:
        stats = {"mean_hour_dev": 2.0, "std_hour_dev": 1.5, "mean_volume": 10.0, "std_volume": 10.0}

    hour_deviation = abs(event_hour - typical_login_hour)

    # ---- 1. Smooth per-signal severity scores (0-100 each, not hard floors) ----
    # Odd-hour severity: scales smoothly from 0 (on time) to 100 (12h off)
    hour_severity = float(np.clip((hour_deviation / 8) * 100, 0, 100))

    # Volume severity: scales smoothly, 0MB=0, ~500MB+=100
    volume_severity = float(np.clip((data_volume_mb / 500) * 100, 0, 100))

    # Cross-department is more binary in nature, but weight it moderately
    allowed_depts = _baseline_cache["resource_allowed_depts"].get(resource_accessed, {department})
    cross_department = department not in allowed_depts
    dept_severity = 55 if cross_department else 0

    # Sensitivity of the resource itself amplifies whatever else is going on
    sensitivity_multiplier = 0.7 + (resource_sensitivity / 10) * 0.3  # ranges ~0.7-1.0

    # ---- 2. Statistical deviation from this user's own baseline ----
    z_hour = (hour_deviation - stats["mean_hour_dev"]) / stats["std_hour_dev"]
    z_volume = (data_volume_mb - stats["mean_volume"]) / stats["std_volume"]
    z_severity = float(np.clip((abs(z_hour) + abs(z_volume)) / 2 / 4 * 100, 0, 100))

    # ---- Combine event-level signals (weighted average, not max()) ----
    base_score = (
        0.30 * hour_severity +
        0.30 * volume_severity +
        0.25 * dept_severity +
        0.15 * z_severity
    ) * sensitivity_multiplier

    # ---- 3. Escalation for repeat offenders ----
    # Each prior recent alert adds a bonus — a 4th flagged event this month
    # looks meaningfully riskier than someone's very first slip.
    escalation_bonus = min(recent_alert_count * 8, 30)

    risk_score = float(np.clip(base_score + escalation_bonus, 0, 100))

    # ---- Build human-readable, threshold-based reasons ----
    reasons = []
    if hour_deviation > 5:
        reasons.append(f"Access at {event_hour}:00 — far outside normal working hours (typical login ~{typical_login_hour:.1f}h)")
    elif hour_deviation > 2.5:
        reasons.append(f"Access at {event_hour}:00 — somewhat outside normal working hours")
    if data_volume_mb > 250:
        reasons.append(f"Downloaded {data_volume_mb:.1f} MB in a single session — very large volume")
    elif data_volume_mb > 80:
        reasons.append(f"Downloaded {data_volume_mb:.1f} MB — larger than typical session volume")
    if cross_department:
        reasons.append(f"Accessed {resource_accessed} — not a resource normally used by {department} department")
    if recent_alert_count > 0:
        reasons.append(f"{recent_alert_count} prior flagged event(s) for this user recently — escalating pattern")
    if not reasons:
        reasons.append("Minor statistical deviation from personal behavioral baseline")

    signal_count = sum([hour_deviation > 2.5, data_volume_mb > 80, cross_department])
    if signal_count >= 2:
        method = "combined"
    elif cross_department or hour_deviation > 2.5 or data_volume_mb > 80:
        method = "isolation_forest"
    else:
        method = "z_score"

    return round(risk_score, 1), " | ".join(reasons), method
