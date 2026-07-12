"""
database.py
============
Sets up the connection to PostgreSQL using SQLAlchemy.
This file rarely needs editing — it just reads your DB connection string
from a .env file and creates the connection.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Reads from .env file. Falls back to a default local Postgres URL if not set.
# Format: postgresql://<username>:<password>@<host>:<port>/<database_name>
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/insider_threat_db"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    Used by FastAPI to give each request its own database session,
    and close it automatically when the request is done.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
