"""
models.py
=========
Defines your database TABLES as Python classes (this is what "ORM" means —
Object-Relational Mapping. You write Python classes, SQLAlchemy turns them
into SQL tables automatically).

3 tables:
  - User          -> employees being monitored
  - AccessLog     -> every access event (login, file access, download)
  - Alert         -> flagged anomalies (this table gets filled by your ML script)
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True)       # e.g. "EMP001"
    name = Column(String)
    department = Column(String)
    role = Column(String)
    join_date = Column(String)
    typical_login_hour = Column(Float)
    typical_files_per_day = Column(Integer)

    # relationship: lets you do user.access_logs to get all their logs
    access_logs = relationship("AccessLog", back_populates="user")
    alerts = relationship("Alert", back_populates="user")


class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, unique=True, index=True)
    user_id = Column(String, ForeignKey("users.user_id"), index=True)
    department = Column(String)
    timestamp = Column(DateTime, index=True)
    resource_accessed = Column(String)
    action = Column(String)                 # view / edit / download
    data_volume_mb = Column(Float)
    resource_sensitivity = Column(Integer)

    user = relationship("User", back_populates="access_logs")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, ForeignKey("access_logs.log_id"), index=True)
    user_id = Column(String, ForeignKey("users.user_id"), index=True)
    timestamp = Column(DateTime)
    risk_score = Column(Float)              # 0-100, produced by your ML script
    reason = Column(String)                 # human-readable explanation
    detection_method = Column(String)       # "isolation_forest" / "z_score" / "combined"

    user = relationship("User", back_populates="alerts")
