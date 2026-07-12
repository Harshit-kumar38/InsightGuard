# Insider Threat Detection — Backend Setup

This backend is fully built and already tested. Just follow these steps
on your own machine (MacBook Air) to get it running.

## What's in this folder

| File | What it does |
|---|---|
| `database.py` | Connects to PostgreSQL |
| `models.py` | Defines the 3 database tables (users, access_logs, alerts) |
| `schemas.py` | Defines the JSON shape for API responses |
| `seed_data.py` | One-time script to load your CSV data into PostgreSQL |
| `main.py` | The actual API — this is what you run |
| `employees.csv`, `access_logs.csv` | Your generated dataset |

You do NOT need to write or edit any of this. Just follow the steps below.

---

## Step 1: Install PostgreSQL on your Mac

Open Terminal and run:
```bash
brew install postgresql@15
brew services start postgresql@15
```

If you don't have Homebrew, install it first from https://brew.sh

## Step 2: Create the database

```bash
createdb insider_threat_db
```

If that command fails with a "role does not exist" error, run this first:
```bash
psql postgres
```
then inside the psql prompt:
```sql
CREATE USER postgres WITH PASSWORD 'postgres' SUPERUSER;
\q
```
then retry `createdb insider_threat_db`.

## Step 3: Install Python dependencies

Inside this `backend` folder, run:
```bash
pip install -r requirements.txt
```

## Step 4: Set your database connection

Copy the example env file:
```bash
cp .env.example .env
```
Open `.env` in any text editor and replace `YOUR_PASSWORD` with your actual
Postgres password (if you set one — if not, try `postgres` as the password,
matching Step 2 above).

## Step 5: Load your data into the database

Make sure `employees.csv` and `access_logs.csv` are in this same folder
(they already are), then run:
```bash
python3 seed_data.py
```

You should see:
```
50 employees loaded.
6896 access logs loaded.
Done. Database is seeded and ready.
```

## Step 6: Start the API

```bash
uvicorn main:app --reload
```

You'll see:
```
Uvicorn running on http://127.0.0.1:8000
```

## Step 7: Test it

Open your browser to:
```
http://127.0.0.1:8000/docs
```

This shows every endpoint with a "Try it out" button — you can test the
whole API by clicking buttons, no coding needed. Try `GET /api/users` first
to confirm you see your 50 employees.

---

## Endpoints available

| Endpoint | Method | What it returns |
|---|---|---|
| `/api/users` | GET | All monitored employees |
| `/api/users/{user_id}/activity` | GET | Full access history for one employee |
| `/api/users/{user_id}/risk-score` | GET | Current risk score for one employee |
| `/api/alerts` | GET | All flagged anomalies (empty until you run the ML script) |
| `/api/alerts/{alert_id}` | GET | Detail for one specific alert |
| `/api/dashboard/summary` | GET | Aggregate stats for the main dashboard |
| `/api/ingest` | POST | Manually push a new event (for live demo) |

## Important: alerts table is currently empty

This backend stores and serves data, but doesn't generate alerts yet —
that's the ML script (Isolation Forest), which is the next piece to build.
Once that script runs, it will INSERT rows into the `alerts` table, and
`/api/alerts` will start returning real flagged anomalies.

## For your Lovable dashboard

Once this is running, point your Lovable frontend's API calls at:
```
http://127.0.0.1:8000
```
(or wherever you deploy it later, e.g. Render/Railway)

All responses are JSON — Lovable can consume them directly.
