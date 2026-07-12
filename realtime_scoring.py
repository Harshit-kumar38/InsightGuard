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
                 event_hour: int, typical_login_hour: float):
    """
    Scores a single new event in real time. Returns (risk_score, reason, method)
    or (None, None, None) if the user has no baseline yet (brand new user).
    """
    stats = _baseline_cache["user_stats"].get(user_id)
    if stats is None:
        # No history for this user yet — can't compute a personal baseline.
        # Fall back to a generic moderate score based on rules only.
        stats = {"mean_hour_dev": 2.0, "std_hour_dev": 1.5, "mean_volume": 10.0, "std_volume": 10.0}

    hour_deviation = abs(event_hour - typical_login_hour)
    z_hour = (hour_deviation - stats["mean_hour_dev"]) / stats["std_hour_dev"]
    z_volume = (data_volume_mb - stats["mean_volume"]) / stats["std_volume"]
    z_combined = (abs(z_hour) + abs(z_volume)) / 2

    risk_score = float(np.clip(z_combined / 4 * 100, 0, 100))

    allowed_depts = _baseline_cache["resource_allowed_depts"].get(resource_accessed, {department})
    cross_department = department not in allowed_depts

    reasons = []
    if hour_deviation > 4:
        reasons.append(f"Access at {event_hour}:00 — far outside normal working hours (typical login ~{typical_login_hour:.1f}h)")
        risk_score = max(risk_score, 72)
    if data_volume_mb > 150:
        reasons.append(f"Downloaded {data_volume_mb:.1f} MB in a single session — unusually large volume")
        risk_score = max(risk_score, 75)
    if cross_department:
        reasons.append(f"Accessed {resource_accessed} — not a resource normally used by {department} department")
        risk_score = max(risk_score, 72)
    if not reasons:
        reasons.append("Statistical deviation from personal behavioral baseline")

    method = "z_score" if not (hour_deviation > 4 or data_volume_mb > 150 or cross_department) else "combined"

    return round(risk_score, 1), " | ".join(reasons), method
