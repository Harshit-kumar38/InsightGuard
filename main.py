"""
main.py
=======
The FastAPI backend. This is what your Lovable dashboard will call.

Run it with:
    uvicorn main:app --reload

Then open http://localhost:8000/docs to see and test every endpoint live
in your browser — no frontend needed to try it out.
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import List
import threading
import random
import time

from database import get_db, engine, Base, SessionLocal
import models
import schemas
import realtime_scoring

# Creates tables if they don't exist yet (safe to call every startup)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Insider Threat Detection API")

# Allows your Lovable frontend (running on a different domain/port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # for hackathon simplicity; restrict in real production
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def load_baseline_cache():
    """
    Builds the in-memory user-behavior baseline cache once when the server
    starts, so /api/ingest can score new events instantly without needing
    to re-run the full ML script.
    """
    db = SessionLocal()
    try:
        realtime_scoring.build_baseline_cache(db)
    finally:
        db.close()


# ------------------------------------------------------------------
# USERS
# ------------------------------------------------------------------

@app.get("/api/users", response_model=List[schemas.UserOut])
def get_users(db: Session = Depends(get_db)):
    """List all monitored employees."""
    return db.query(models.User).all()


@app.get("/api/users/{user_id}/activity", response_model=List[schemas.AccessLogOut])
def get_user_activity(user_id: str, db: Session = Depends(get_db)):
    """Full access history for one employee."""
    user = db.query(models.User).filter(models.User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    logs = (
        db.query(models.AccessLog)
        .filter(models.AccessLog.user_id == user_id)
        .order_by(models.AccessLog.timestamp.desc())
        .all()
    )
    return logs


@app.get("/api/users/{user_id}/risk-score")
def get_user_risk_score(user_id: str, db: Session = Depends(get_db)):
    """Current risk score for a user = their highest alert score, or 0 if none."""
    user = db.query(models.User).filter(models.User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    top_alert = (
        db.query(models.Alert)
        .filter(models.Alert.user_id == user_id)
        .order_by(models.Alert.risk_score.desc())
        .first()
    )
    return {
        "user_id": user_id,
        "risk_score": top_alert.risk_score if top_alert else 0,
        "alert_count": db.query(models.Alert).filter(models.Alert.user_id == user_id).count(),
    }


# ------------------------------------------------------------------
# ALERTS
# ------------------------------------------------------------------

@app.get("/api/alerts", response_model=List[schemas.AlertOut])
def get_alerts(limit: int = 50, db: Session = Depends(get_db)):
    """All flagged anomalies, most recent / highest risk first."""
    alerts = (
        db.query(models.Alert)
        .order_by(models.Alert.risk_score.desc())
        .limit(limit)
        .all()
    )
    return alerts


@app.get("/api/alerts/{alert_id}", response_model=schemas.AlertOut)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """Full detail for one specific alert."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# ------------------------------------------------------------------
# DASHBOARD SUMMARY
# ------------------------------------------------------------------

@app.get("/api/dashboard/summary", response_model=schemas.DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Aggregate stats for the main dashboard view."""
    total_users = db.query(models.User).count()
    total_events = db.query(models.AccessLog).count()
    total_alerts = db.query(models.Alert).count()

    high_risk_users = (
        db.query(models.Alert.user_id)
        .filter(models.Alert.risk_score >= 70)
        .distinct()
        .count()
    )

    avg_score = db.query(func.avg(models.Alert.risk_score)).scalar() or 0

    return schemas.DashboardSummary(
        total_users=total_users,
        total_access_events=total_events,
        total_alerts=total_alerts,
        high_risk_users=high_risk_users,
        avg_risk_score=round(avg_score, 1),
    )


# ------------------------------------------------------------------
# LIVE DEMO — manually trigger a new event (e.g. simulate a 2AM bulk download)
# ------------------------------------------------------------------

def process_event(db: Session, user_id: str, resource_accessed: str, action: str,
                   data_volume_mb: float, resource_sensitivity: int, timestamp=None):
    """
    Core event-processing logic: saves the access log, scores it, and
    creates an alert if risky enough. Shared by BOTH the manual
    /api/ingest endpoint AND the background auto-replay thread, so
    there's only one source of truth for how events get processed.
    """
    user = db.query(models.User).filter(models.User.user_id == user_id).first()
    if not user:
        return None

    max_log_id = db.query(func.max(models.AccessLog.log_id)).scalar() or 0
    event_timestamp = timestamp or datetime.now()

    new_log = models.AccessLog(
        log_id=max_log_id + 1,
        user_id=user_id,
        department=user.department,
        timestamp=event_timestamp,
        resource_accessed=resource_accessed,
        action=action,
        data_volume_mb=data_volume_mb,
        resource_sensitivity=resource_sensitivity,
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    window_start = datetime.now() - timedelta(hours=48)
    recent_alert_count = (
        db.query(models.Alert)
        .filter(models.Alert.user_id == user_id)
        .filter(models.Alert.timestamp >= window_start)
        .count()
    )

    risk_score, reason, method = realtime_scoring.score_event(
        user_id=user_id,
        department=user.department,
        resource_accessed=resource_accessed,
        data_volume_mb=data_volume_mb,
        resource_sensitivity=resource_sensitivity,
        event_hour=event_timestamp.hour,
        typical_login_hour=user.typical_login_hour,
        recent_alert_count=recent_alert_count,
    )

    alert_created = False
    ALERT_THRESHOLD = 12
    if risk_score is not None and risk_score >= ALERT_THRESHOLD:
        new_alert = models.Alert(
            log_id=new_log.log_id,
            user_id=user_id,
            timestamp=event_timestamp,
            risk_score=risk_score,
            reason=reason,
            detection_method=method,
        )
        db.add(new_alert)
        db.commit()
        alert_created = True

    return {
        "message": "Event ingested and scored",
        "log_id": new_log.log_id,
        "user_id": user_id,
        "risk_score": risk_score,
        "reason": reason,
        "alert_created": alert_created,
    }


@app.post("/api/ingest")
def ingest_event(event: schemas.IngestEvent, db: Session = Depends(get_db)):
    """
    Push a new access event live, score it INSTANTLY using the cached
    behavioral baselines (see realtime_scoring.py), and — if risky enough —
    create a real alert immediately. This is what powers the
    "Simulate Suspicious Event" button for a genuinely live demo.
    """
    result = process_event(
        db, event.user_id, event.resource_accessed, event.action,
        event.data_volume_mb, event.resource_sensitivity, event.timestamp,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@app.get("/")
def root():
    return {"message": "Insider Threat Detection API is running. Visit /docs to explore."}


# ------------------------------------------------------------------
# AUTO-REPLAY — background "live activity" generator, controllable from
# the dashboard instead of needing to run a separate script on your laptop.
# ------------------------------------------------------------------

RESOURCES_BY_DEPT = {
    "Finance":    ["Payroll_DB", "Invoice_System", "Tax_Records", "Budget_Sheets"],
    "HR":         ["Employee_Records", "Payroll_DB", "Recruitment_System", "Performance_Reviews"],
    "Engineering":["Source_Code_Repo", "CI_CD_Pipeline", "Cloud_Infra_Console", "Bug_Tracker"],
    "Marketing":  ["CRM_System", "Campaign_Dashboard", "Social_Media_Tools", "Analytics_Portal"],
    "Sales":      ["CRM_System", "Customer_Contracts", "Pricing_Sheets", "Sales_Dashboard"],
    "IT_Admin":   ["All_Systems_Console", "User_Access_Manager", "Server_Logs", "Backup_System"],
}
SENSITIVITY_BY_DEPT = {"Finance": 9, "HR": 9, "Engineering": 6, "Marketing": 4, "Sales": 6, "IT_Admin": 10}

_replay_state = {"running": False, "thread": None, "events_sent": 0}


def _generate_replay_event(employee, anomaly_chance=0.15):
    dept = employee.department
    now = datetime.now()

    if random.random() < anomaly_chance:
        kind = random.choice(["odd_hour", "bulk_download", "cross_dept"])
        if kind == "odd_hour":
            resource = random.choice(RESOURCES_BY_DEPT.get(dept, ["CRM_System"]))
            ts = now.replace(hour=random.choice([1, 2, 3, 4]), minute=random.randint(0, 59))
            volume = round(random.uniform(5, 40), 1)
        elif kind == "bulk_download":
            resource = random.choice(RESOURCES_BY_DEPT.get(dept, ["CRM_System"]))
            ts = now
            volume = round(random.uniform(200, 500), 1)
        else:
            other_dept = random.choice([d for d in RESOURCES_BY_DEPT if d != dept])
            resource = random.choice(RESOURCES_BY_DEPT[other_dept])
            ts = now
            volume = round(random.uniform(10, 60), 1)
        action = "download"
    else:
        resource = random.choice(RESOURCES_BY_DEPT.get(dept, ["CRM_System"]))
        hour = max(6, min(int(employee.typical_login_hour) + random.randint(-1, 1), 20))
        ts = now.replace(hour=hour, minute=random.randint(0, 59))
        volume = round(random.uniform(1, 15), 1)
        action = random.choice(["view", "view", "edit"])

    return {
        "resource_accessed": resource,
        "action": action,
        "data_volume_mb": volume,
        "resource_sensitivity": SENSITIVITY_BY_DEPT.get(dept, 5),
        "timestamp": ts,
    }


def _replay_loop(interval_seconds: int):
    """Runs in a background thread, sending one fake event every N seconds."""
    while _replay_state["running"]:
        db = SessionLocal()
        try:
            users = db.query(models.User).all()
            if users:
                employee = random.choice(users)
                event = _generate_replay_event(employee)
                process_event(
                    db, employee.user_id, event["resource_accessed"], event["action"],
                    event["data_volume_mb"], event["resource_sensitivity"], event["timestamp"],
                )
                _replay_state["events_sent"] += 1
        except Exception as e:
            print(f"[auto-replay] error: {e}")
        finally:
            db.close()
        time.sleep(interval_seconds)


@app.post("/api/demo/start")
def start_auto_replay(interval_seconds: int = 20):
    """Starts background auto-replay — sends a realistic event every N seconds."""
    if _replay_state["running"]:
        return {"message": "Auto-replay already running", "events_sent": _replay_state["events_sent"]}

    _replay_state["running"] = True
    _replay_state["events_sent"] = 0
    thread = threading.Thread(target=_replay_loop, args=(interval_seconds,), daemon=True)
    _replay_state["thread"] = thread
    thread.start()
    return {"message": f"Auto-replay started (every {interval_seconds}s)"}


@app.post("/api/demo/stop")
def stop_auto_replay():
    """Stops background auto-replay."""
    _replay_state["running"] = False
    return {"message": "Auto-replay stopped", "events_sent": _replay_state["events_sent"]}


@app.get("/api/demo/status")
def auto_replay_status():
    """Check whether auto-replay is currently running, and how many events it's sent."""
    return {
        "running": _replay_state["running"],
        "events_sent": _replay_state["events_sent"],
    }
