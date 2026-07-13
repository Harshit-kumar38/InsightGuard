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
from datetime import datetime
from typing import List

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

@app.post("/api/ingest")
def ingest_event(event: schemas.IngestEvent, db: Session = Depends(get_db)):
    """
    Push a new access event live, score it INSTANTLY using the cached
    behavioral baselines (see realtime_scoring.py), and — if risky enough —
    create a real alert immediately. This is what powers the
    "Simulate Suspicious Event" button for a genuinely live demo.
    """
    user = db.query(models.User).filter(models.User.user_id == event.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    max_log_id = db.query(func.max(models.AccessLog.log_id)).scalar() or 0
    event_timestamp = event.timestamp or datetime.now()

    new_log = models.AccessLog(
        log_id=max_log_id + 1,
        user_id=event.user_id,
        department=user.department,
        timestamp=event_timestamp,
        resource_accessed=event.resource_accessed,
        action=event.action,
        data_volume_mb=event.data_volume_mb,
        resource_sensitivity=event.resource_sensitivity,
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    # ---- Check how many times this user has been flagged RECENTLY ----
    # Time-windowed (last 48 hours) — NOT all-time — so escalation reflects
    # a genuinely emerging pattern, not someone's entire historical record.
    from datetime import timedelta
    window_start = datetime.now() - timedelta(hours=48)
    recent_alert_count = (
        db.query(models.Alert)
        .filter(models.Alert.user_id == event.user_id)
        .filter(models.Alert.timestamp >= window_start)
        .count()
    )

    # ---- Real-time scoring ----
    risk_score, reason, method = realtime_scoring.score_event(
        user_id=event.user_id,
        department=user.department,
        resource_accessed=event.resource_accessed,
        data_volume_mb=event.data_volume_mb,
        resource_sensitivity=event.resource_sensitivity,
        event_hour=event_timestamp.hour,
        typical_login_hour=user.typical_login_hour,
        recent_alert_count=recent_alert_count,
    )

    alert_created = False
    ALERT_THRESHOLD = 12
    if risk_score is not None and risk_score >= ALERT_THRESHOLD:
        new_alert = models.Alert(
            log_id=new_log.log_id,
            user_id=event.user_id,
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
        "risk_score": risk_score,
        "reason": reason,
        "alert_created": alert_created,
    }


@app.get("/")
def root():
    return {"message": "Insider Threat Detection API is running. Visit /docs to explore."}
