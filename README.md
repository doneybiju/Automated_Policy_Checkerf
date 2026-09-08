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

## Phase 2 Summary (Auth & Target Allow-Listing)

Phase 2 implements authentication, JWT issuance, and target allow-listing control:
- SQLAlchemy database models for `users`, `allowed_targets`, `policies`, `checks`, `scans`, and `scan_results`.
- Alembic database schema migrations and dev data seed script (`backend/scripts/seed_dev_data.py`).
- Bcrypt password hashing and JWT access token issuance/validation in `backend/auth.py`.
- Mandatory `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` environment variables with fail-fast startup checks.
- API Endpoints:
  - `POST /auth/login`: Issue JWT token upon valid user authentication.
  - `GET /targets`: List allow-listed targets (accessible by any authenticated user).
  - `POST /targets`: Add a target host to allow-list (restricted to `admin` role).
- Unit tests in `backend/tests/test_auth.py` and `backend/tests/test_models.py` verifying JWT authentication, role enforcement (403 for non-admin target creation, 401 for unauthenticated access), and database models.

---

## Quick Start (Local Development with Docker Compose)

1. **Copy environment configuration:**
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
