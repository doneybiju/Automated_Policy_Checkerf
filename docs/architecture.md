# Automated Security Policy Compliance Checker — Architecture & Build Plan

**Status:** Locked spec for v1 (MVP). Do not deviate without updating this doc first.
**Build method:** Phase-gated. One phase = one agent session = one reviewable PR. Never start Phase N+1 until Phase N passes its exit criteria.

---

## 0. Guiding Principles (apply to every phase, every prompt)

These go to the AI agent (Claude Code / Jules) **once**, up front, as a standing instruction, then referenced by number in every phase prompt so you don't have to retype it.

```
CODING STANDARDS — apply to all code in this repo, every phase:

1. Single Responsibility: one function/class does one thing. If a function
   needs "and" to describe it, split it.
2. No duplicate logic: before writing a new function, check if an existing
   one does this. If similar logic appears twice, extract a shared helper.
3. No dead code: no commented-out blocks, no unused imports, no unused
   variables, no placeholder functions that aren't called anywhere yet.
   If a phase's scope doesn't need it, don't write it.
4. Type everything: Python -> full type hints + Pydantic schemas for all
   API I/O. TypeScript -> no `any`, explicit interfaces/types.
5. Docstrings on every public function/class: what it does, params,
   return, and any side effects (network calls, DB writes, file I/O).
6. No god files: if a file exceeds ~300 lines, it's doing too much —
   split it along responsibility lines, not arbitrarily.
7. No premature abstraction: don't build a plugin framework, config
   system, or generic "engine" until at least 2 concrete cases need it.
8. Errors are explicit: no bare `except:`, no swallowed exceptions,
   no silent fallbacks that hide failures.
9. Every phase ends with: a short README section for what was built,
   and tests for the logic added in that phase. No phase is "done"
   without both.
10. Do not touch files outside this phase's stated scope. If you notice
    an unrelated issue, report it, don't fix it inline.
```

---

## 1. System Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌────────────────────┐
│   Web Frontend    │────▶│   Backend API      │────▶│   Scan Orchestrator  │
│  (React + TS)      │◀────│  (FastAPI/Python)  │◀────│  (Celery worker)     │
└─────────────────┘      └──────────────────┘      └────────────────────┘
                                    │                            │
                                    ▼                            ▼
                          ┌──────────────────┐        ┌────────────────────┐
                          │   PostgreSQL       │        │  Scanning Engine     │
                          │ (policies, scans,  │        │  (OpenSCAP + nmap,    │
                          │  results, users)    │        │   containerized)      │
                          └──────────────────┘        └────────────────────┘
                                                                  │
                                                                  ▼
                                                       ┌────────────────────┐
                                                       │  Target Host(s)      │
                                                       │  (allow-listed only) │
                                                       └────────────────────┘
```

**Non-negotiable design rules:**
- The scanning engine never receives raw user input directly — the Backend API validates and normalizes every scan request before it reaches the queue.
- Targets must exist in an `allowed_targets` table before a scan can be queued against them. No free-text IP/hostname scanning. This is the fix for the "internal recon tool" risk flagged earlier.
- The scanning container runs as non-root, with a read-only filesystem except for a scoped `/results` output volume, and no capability to reach anything outside the target network segment.

---

## 2. Tech Stack (locked)

| Layer | Choice | Why |
|---|---|---|
| Frontend | React + TypeScript + Vite + Tailwind | Type safety on compliance status enums |
| Backend API | Python + FastAPI | Pydantic validation, auto OpenAPI docs |
| Job Queue | Celery + Redis | Scans are slow/blocking; must not tie up API |
| Database | PostgreSQL | Relational data (policy -> check -> result -> history) |
| Scanning Engine | OpenSCAP (`oscap`) + python-nmap | Standards-based checks (NIST/CIS/DISA content), not hand-rolled rules |
| Containerization | Docker + docker-compose | Isolation for the scanning engine specifically |
| Migrations | Alembic | Schema versioning from day one |
| Auth | JWT (short-lived) + refresh tokens | Stateless API auth; RBAC added in Phase 8 |

---

## 3. Database Schema (v1)

```
users            (id, email, password_hash, role, created_at)
allowed_targets  (id, hostname_or_ip, label, added_by_user_id, created_at)
policies         (id, name, description, source, version, created_at)
                 -- source: e.g. "NIST-800-53-AC2", "CIS-Benchmark-v8"
checks           (id, policy_id, check_type, expected_state,
                   risk_level, remediation_text)
                 -- check_type: "openscap_rule" | "port_exposure" | "service_check"
scans            (id, target_id, requested_by_user_id, status,
                   queued_at, started_at, completed_at)
                 -- status: queued | running | completed | failed
scan_results     (id, scan_id, check_id, raw_output, status,
                   severity, evaluated_at)
                 -- status: compliant | non_compliant | warning | error
```

Nothing here is speculative — every table maps directly to a feature already in the original project doc (7.1–7.5). No tables for future features (RBAC roles beyond a single `role` column, SIEM integration, etc.) until those phases are actually reached.

---

## 4. API Route Table (v1 scope)

| Method | Route | Purpose |
|---|---|---|
| POST | `/auth/login` | Issue JWT |
| GET | `/targets` | List allow-listed targets |
| POST | `/targets` | Add a target (admin only) |
| GET | `/policies` | List policies + checks |
| POST | `/scans` | Queue a scan against an allow-listed target |
| GET | `/scans/{id}` | Scan status |
| GET | `/scans/{id}/results` | Compliance results for a scan |
| GET | `/scans` | Scan history (filterable by target, date) |

No routes for features not yet built. Add routes in the phase that implements them, not earlier.

---

## 5. Phased Build Plan

Each phase below is a **separate agent session**. Copy the phase's prompt verbatim (it already references the coding standards above), let the agent finish, then verify against the exit criteria before moving on.

---

### Phase 0 — Repo Scaffolding

**Goal:** Empty, correctly structured skeleton. No business logic.

**Deliverables:**
- Folder structure (frontend/, backend/, scanning-engine/, worker/, docs/)
- `docker-compose.yml` wiring frontend + backend + postgres + redis (empty services, health checks only)
- Backend: FastAPI app boots with a single `/health` route
- Frontend: Vite app boots with a placeholder page
- `.env.example` files, `.gitignore`, base `README.md`

**Exit criteria:** `docker-compose up` starts all services; `/health` returns 200; frontend loads in browser. Nothing else exists yet.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0 to everything
you write in this and all future sessions in this repo.

Task (Phase 0 only — scaffolding, no business logic):
Set up the repository structure exactly as defined in docs/architecture.md
section "Proposed Repository Structure". Create:
- A FastAPI backend with a single GET /health endpoint returning {"status":"ok"}
- A Vite + React + TypeScript frontend with one placeholder page
- docker-compose.yml wiring backend, frontend, postgres, and redis containers
  with health checks (no app logic connecting to them yet)
- .env.example, .gitignore, base README.md

Do NOT implement authentication, database models, scanning logic, or any
route beyond /health. Do NOT add dependencies we haven't discussed
(stick to: FastAPI, uvicorn, React, TypeScript, Vite, Tailwind).
Stop after docker-compose up successfully starts all 4 services.
```

---

### Phase 1 — Database Models & Migrations

**Goal:** Schema from section 3, nothing more.

**Deliverables:**
- SQLAlchemy models for all 6 tables in section 3
- Alembic migration that creates them
- One seed script for local dev (a handful of fake rows, clearly marked as dev-only)

**Exit criteria:** `alembic upgrade head` runs clean against a fresh DB; seed script populates without errors; no model exists that isn't in section 3.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 1 only — database layer):
Implement SQLAlchemy models for exactly the 6 tables defined in
docs/architecture.md section 3 (users, allowed_targets, policies, checks,
scans, scan_results). Set up Alembic and generate the initial migration.
Add a dev-only seed script (backend/scripts/seed_dev_data.py) that inserts
a small amount of realistic fake data for local testing.

Do NOT add any table, column, or field not listed in section 3. Do NOT
write any API routes yet — this phase is data layer only. Do NOT add
business logic (no policy evaluation, no scan orchestration).
```

---

### Phase 2 — Auth & Target Allow-Listing

**Goal:** Users can log in; admins can manage the target allow-list. This is the control that prevents unauthorized scanning.

**Deliverables:**
- `/auth/login` issuing JWT
- `/targets` GET (any authenticated user) and POST (admin only)
- Password hashing (bcrypt/argon2), no plaintext anywhere, ever

**Exit criteria:** Cannot add a target without admin role; cannot queue anything against a target not in the table (verified even though scan-queuing doesn't exist yet — write a unit test asserting the DB constraint/lookup path).

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 2 only — auth and target allow-listing):
Implement POST /auth/login (JWT issuance), GET /targets, and POST /targets
(admin-role only) as defined in docs/architecture.md section 4. Use
bcrypt or argon2 for password hashing. Add role-based route protection
(a simple "admin" vs "user" check on the users.role column — do not build
a full RBAC permission system yet, that's Phase 8).

Write tests confirming: a non-admin cannot POST /targets, and an
unauthenticated request to any route is rejected.

Do NOT implement scan queuing, policy routes, or anything scanning-related
in this phase.
```

---

### Phase 3 — Policy & Check Management

**Goal:** CRUD for policies/checks, loaded from real SCAP/NIST baseline content — not invented rules.

**Deliverables:**
- `/policies` GET route
- A loader script that ingests the carried-over `ac2_ac6_tailoring.xml` and any additional SCAP baseline content into the `policies`/`checks` tables
- Basic validation: a check must reference a real policy_id

**Exit criteria:** `/policies` returns real, non-fake data sourced from the SCAP tailoring file, not hardcoded strings.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 3 only — policy management):
Implement GET /policies returning policies with their associated checks
(schema per docs/architecture.md section 3). Write a one-time loader
script (backend/scripts/load_scap_policies.py) that parses
scanning-engine/policies/ac2_ac6_tailoring.xml and inserts corresponding
rows into policies and checks. If the XML structure requires additional
fields to map cleanly, propose the minimal schema addition and stop for
review before writing migration code.

Do NOT write scan orchestration or the OpenSCAP execution wrapper yet —
this phase only loads and serves policy definitions.
```

---

### Phase 4 — Scanning Engine (Isolated Container)

**Goal:** A working, isolated scanner that can run against ONE test target manually (no orchestration/queue integration yet).

**Deliverables:**
- `scanning-engine/` Docker image: non-root user, read-only FS except `/results`
- `openscap_runner.py`: wraps `oscap` CLI, takes a target + profile, returns structured results
- `port_scan.py`: wraps `nmap`, returns structured results
- Both implement a shared `base_check.py` interface (one interface, not two divergent patterns)

**Exit criteria:** Running the container manually against a test VM produces structured JSON output for both check types. Container fails closed (no output, clear error) if it can't reach the target — never silently "passes" on failure.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 4 only — scanning engine, standalone):
Build the scanning-engine/ Docker image as defined in
docs/architecture.md section 1 (non-root, read-only filesystem except a
/results volume). Implement:
- base_check.py: a minimal abstract interface all check types implement
  (e.g. a run(target) -> CheckResult method)
- openscap_runner.py: wraps the `oscap` CLI against a given target and
  SCAP profile, parses output into CheckResult objects
- port_scan.py: wraps `nmap` for open port/service exposure checks,
  returns CheckResult objects in the same shape

This phase does NOT connect to the backend, queue, or database. Test it
by running the container manually against a single test target and
confirming structured JSON output. If the target is unreachable or the
scan errors, the tool must return an explicit error result — never a
false "compliant".
```

---

### Phase 5 — Scan Orchestration (Queue Integration)

**Goal:** Wire Phases 1–4 together: API queues a scan, Celery worker invokes the scanning engine, results land in the DB.

**Deliverables:**
- `POST /scans` (validates target is allow-listed, enqueues Celery task)
- Celery task that invokes the scanning-engine container/logic and writes raw results to `scan_results`
- `GET /scans/{id}` for status polling

**Exit criteria:** End-to-end: queue a scan via API → status moves queued → running → completed → raw results in DB. A scan against a non-allow-listed target is rejected at the API layer, before it ever reaches the queue.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 5 only — orchestration):
Implement POST /scans and GET /scans/{id} per docs/architecture.md
section 4. POST /scans must verify the target exists in allowed_targets
before enqueuing — reject with a clear 403/400 otherwise, and add a test
for this rejection path. Implement the Celery task that invokes the
Phase 4 scanning engine and writes raw results into scan_results with
status "completed" or "failed" (not "compliant/non_compliant" yet — that
mapping is Phase 6).

Do NOT implement compliance evaluation/severity mapping in this phase —
just get raw results reliably from request to database.
```

---

### Phase 6 — Compliance Evaluation Engine

**Goal:** Map raw scan output to policy baselines: compliant / non-compliant / warning + severity.

**Deliverables:**
- Evaluation logic that consumes `scan_results.raw_output` + the matching `checks` row and sets `scan_results.status` and `severity`
- `GET /scans/{id}/results` returning evaluated results

**Exit criteria:** For a known test scan, results match expected compliant/non-compliant/warning labels exactly — write this as a test fixture, not a manual check.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 6 only — compliance evaluation):
Implement the evaluation logic that takes a scan_results row's
raw_output plus its linked checks.expected_state and produces a
status (compliant | non_compliant | warning) and severity, per
docs/architecture.md section 3. Implement GET /scans/{id}/results
returning the evaluated results.

Write a test fixture with known raw output and known expected
policy state, asserting the evaluator produces the exact expected
status/severity. Do NOT touch the frontend or reporting/export
features in this phase.
```

---

### Phase 7 — Frontend Dashboard

**Goal:** Views for everything built so far — scan trigger, status, results, history. No new backend logic.

**Deliverables:**
- Login page
- Dashboard: target list, "run scan" action
- Scan results view: pass/fail per check, severity color-coding, remediation text
- Scan history view

**Exit criteria:** A user can log in, trigger a scan against an allow-listed target, watch status update, and view color-coded results — entirely through the UI.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 7 only — frontend):
Build React pages consuming the existing API (routes from
docs/architecture.md section 4, all implemented in prior phases):
Login, Dashboard (target list + trigger scan), Scan Results (per-check
pass/fail, severity color-coding, remediation text), Scan History.
Use typed API client functions (frontend/src/api/) — no inline fetch()
calls scattered through components.

Do NOT add any backend routes or logic. If a needed field isn't in an
existing API response, stop and report it rather than inventing a
workaround.
```

---

### Phase 8 — Hardening: RBAC, Audit Logging, Container Security Review

**Goal:** Close the gaps flagged in the threat model — this is what makes the "no destructive actions" and "controlled scan execution" claims in your original doc actually true.

**Deliverables:**
- Full RBAC (beyond the single admin/user flag from Phase 2)
- Audit log table + writes on: login, target added, scan queued
- Container security review checklist verified against the running Phase 4 image (non-root confirmed, capabilities dropped, read-only FS confirmed)

**Exit criteria:** A written `docs/threat-model.md` update showing each identified risk mapped to the control that mitigates it.

**Agent prompt:**
```
Apply the CODING STANDARDS from docs/architecture.md section 0.

Task (Phase 8 only — hardening):
Extend the role system from Phase 2 into full RBAC (define at minimum:
admin, analyst, viewer — analyst can queue scans and add targets, viewer
is read-only). Add an audit_log table and write entries on login, target
creation, and scan queuing. Review the Phase 4 scanning-engine Dockerfile
and confirm/enforce: non-root user, dropped Linux capabilities, read-only
filesystem except /results. Document findings in docs/threat-model.md.

Do NOT add new user-facing features in this phase — this is a security
review and hardening pass only.
```

---

### Phase 9 — Tests, CI, and Docs Pass

**Goal:** Everything before this point had per-phase tests; this phase adds CI and closes gaps.

**Deliverables:**
- GitHub Actions CI: lint + test on push
- Coverage check on backend evaluation logic specifically (Phase 6 is the highest-value code to test thoroughly)
- Final README with setup instructions

**Exit criteria:** CI passes green on a clean clone with no manual steps beyond `docker-compose up`.

---

## 6. What's Explicitly Out of Scope for v1

(Matches your original doc's "Future Enhancements" — don't let an agent quietly build these early)

- Scheduled recurring scans
- PDF export
- Custom policy authoring UI
- SIEM integration (Wazuh)
- Multi-host/network-wide scanning

If an agent proposes any of these mid-phase, that's a signal it's scope-creeping — redirect it back to the current phase's prompt.
