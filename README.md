# Automated Security Policy Compliance Checker

An automated security policy compliance checking platform designed to validate target system configurations against SCAP/NIST/CIS security baselines.

---

## Architecture Overview

The system consists of the following components:
- **Frontend**: React + TypeScript + Vite + Tailwind CSS dashboard (`frontend/`).
- **Backend API**: FastAPI service providing API endpoints (`backend/`).
- **Scanning Engine**: Isolated Docker container for running OpenSCAP and nmap checks (`scanning-engine/`).
- **Worker**: Celery task worker for background scan orchestration (`worker/`).
- **Database**: PostgreSQL storing policy rules, scan requests, and compliance results.
- **Cache/Queue**: Redis backing Celery job queues.

---

## Phase 0 Summary (Scaffolding & Infrastructure)

Phase 0 establishes the base repository structure and Docker Compose environment:
- Repository layout (`frontend/`, `backend/`, `scanning-engine/`, `worker/`, `docs/`).
- FastAPI backend with a `GET /health` endpoint returning `{"status":"ok"}`.
- Vite + React + TypeScript placeholder application.
- Docker Compose setup wiring `postgres`, `redis`, `backend`, and `frontend` with health checks.
- Environment template (`.env.example`) and version control ignores (`.gitignore`).

---

## Phase 1 Summary (Database Models & Migrations)

Phase 1 implements the core database layer:
- SQLAlchemy ORM models for all 6 core tables:
  - `users`
  - `allowed_targets`
  - `policies`
  - `checks`
  - `scans`
  - `scan_results`
- Alembic database migration environment (`backend/alembic/`).
- Dev seed script (`backend/scripts/seed_dev_data.py`) for local testing.

### Running Migrations and Seeding Data

1. **Apply Alembic Migrations:**
   ```bash
   cd backend
   alembic upgrade head
   ```

2. **Seed Local Development Database:**
   ```bash
   python backend/scripts/seed_dev_data.py
   ```

---

## Quick Start (Local Development with Docker Compose)

1. **Create environment configuration file:**
   Before running `docker compose up`, you **must** create a `.env` file from `.env.example` so that required environment variables (such as `POSTGRES_PASSWORD`) are set:
   ```bash
   cp .env.example .env
   ```

2. **Start services:**
   ```bash
   docker compose up --build -d
   ```

3. **Verify running services:**
   - **Backend Health Check:** `http://localhost:8000/health` (returns `{"status":"ok"}`)
   - **Frontend App:** `http://localhost:3000`

4. **Stop services:**
   ```bash
   docker compose down -v
   ```

---

## Testing

Run backend tests using `pytest`:
```bash
python3 -m pytest backend/tests
```
