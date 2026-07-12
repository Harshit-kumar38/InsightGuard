"""
schemas.py
==========
These define what the API sends/receives as JSON. FastAPI uses these to:
  1. Validate incoming data
  2. Auto-generate your API docs (the /docs page)
  3. Control exactly what fields go out in each response

Think of these as "the shape of the JSON" for each endpoint.
"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class UserOut(BaseModel):
    user_id: str
    name: str
    department: str
    role: str
    typical_login_hour: float
    typical_files_per_day: int

    class Config:
        from_attributes = True  # lets Pydantic read SQLAlchemy objects directly


class AccessLogOut(BaseModel):
    log_id: int
    user_id: str
    timestamp: datetime
    resource_accessed: str
    action: str
    data_volume_mb: float
    resource_sensitivity: int

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: int
    log_id: int
    user_id: str
    timestamp: datetime
    risk_score: float
    reason: str
    detection_method: str

    class Config:
        from_attributes = True


class DashboardSummary(BaseModel):
    total_users: int
    total_access_events: int
    total_alerts: int
    high_risk_users: int          # users with any alert >= 70 risk score
    avg_risk_score: float


class IngestEvent(BaseModel):
    """
    Used by the /api/ingest endpoint — lets you manually push a new
    (possibly suspicious) event live during your demo.
    """
    user_id: str
    resource_accessed: str
    action: str
    data_volume_mb: float
    resource_sensitivity: int
    timestamp: Optional[datetime] = None
