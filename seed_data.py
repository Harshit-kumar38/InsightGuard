"""
seed_data.py
============
Run this ONCE to load your employees.csv and access_logs.csv into PostgreSQL.

Usage:
    python seed_data.py
"""

import pandas as pd
from database import engine, SessionLocal, Base
from models import User, AccessLog

# Point this to wherever you saved the CSVs generated earlier
EMPLOYEES_CSV = "employees.csv"
ACCESS_LOGS_CSV = "access_logs.csv"


def seed():
    print("Creating tables (if they don't already exist)...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # ---- Load employees ----
    print("Loading employees...")
    employees_df = pd.read_csv(EMPLOYEES_CSV)
    for _, row in employees_df.iterrows():
        existing = db.query(User).filter(User.user_id == row["user_id"]).first()
        if existing:
            continue  # skip if already seeded
        user = User(
            user_id=row["user_id"],
            name=row["name"],
            department=row["department"],
            role=row["role"],
            join_date=str(row["join_date"]),
            typical_login_hour=row["typical_login_hour"],
            typical_files_per_day=row["typical_files_per_day"],
        )
        db.add(user)
    db.commit()
    print(f"  {len(employees_df)} employees loaded.")

    # ---- Load access logs ----
    print("Loading access logs (this may take a moment)...")
    logs_df = pd.read_csv(ACCESS_LOGS_CSV, parse_dates=["timestamp"])

    # Only insert logs that don't already exist (safe to re-run)
    existing_log_ids = set(x[0] for x in db.query(AccessLog.log_id).all())

    new_logs = []
    for _, row in logs_df.iterrows():
        if int(row["log_id"]) in existing_log_ids:
            continue
        new_logs.append(AccessLog(
            log_id=int(row["log_id"]),
            user_id=row["user_id"],
            department=row["department"],
            timestamp=row["timestamp"],
            resource_accessed=row["resource_accessed"],
            action=row["action"],
            data_volume_mb=row["data_volume_mb"],
            resource_sensitivity=row["resource_sensitivity"],
        ))

    # Bulk insert in batches for speed
    batch_size = 500
    for i in range(0, len(new_logs), batch_size):
        db.bulk_save_objects(new_logs[i:i + batch_size])
        db.commit()

    print(f"  {len(new_logs)} access logs loaded.")
    db.close()
    print("\nDone. Database is seeded and ready.")


if __name__ == "__main__":
    seed()
