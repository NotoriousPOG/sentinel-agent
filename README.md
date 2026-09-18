# Sentinel Agent

Sentinel Agent is an early-stage SOC investigation system. It will accept a security alert, investigate it with a closed set of tools, and hand a structured report to a human analyst. Remediation, if it is ever added, will require an explicit human approval. This repository does not execute response actions.

This branch is the foundation only. Read `docs/architecture.md` for the control-plane decisions and `IMPLEMENTATION_PLAN.md` for milestones 1–10.

## Status

| Area | State |
| --- | --- |
| Configuration, package layout, MIT license | Present |
| Domain schemas, confidence formula, transition guards | Present and tested |
| `GET /health` and OpenAPI | Present |
| `POST /alerts`, investigation, review, and metrics routes | Reserved. They return 501 and do not store or investigate |
| Generic JSON adapter | Validates the normalized alert shape. Does not persist |
| Wazuh, CrowdStrike, GuardDuty, Defender, Elastic, Splunk | Interfaces only. Not integrations |
| LLM and threat-intel clients | Interfaces only. No network calls |
| PostgreSQL wiring | SQLAlchemy engine, session factory, empty Alembic revision |
| Agent loop, tools, evidence correlation, report generation | Not implemented |
| Prompt-injection runtime defenses, evals, tracing | Not implemented |
| `demo_mode` | Flag only. No mock providers |

There are no benchmark numbers because nothing has been measured.

## Local API

Python 3.12 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
uvicorn sentinel.api.app:app --host 127.0.0.1 --port 8091
```

Health: `GET /health`. Interactive API docs: `GET /docs`.

Unit tests use SQLite and do not need PostgreSQL or API keys. SQLite is not a supported deployment. Copy `.env.example` to `.env` if you want local overrides. Do not commit `.env`.

## Docker Compose

Compose starts the API and PostgreSQL 16 for local development. The database password in `docker-compose.yml` is for that local database only.

```bash
docker compose up --build
```

The API listens on `127.0.0.1:8091`. Postgres listens on `127.0.0.1:54329`.

## Tests and CI

```bash
ruff check src tests
ruff format --check src tests
mypy src/sentinel
pytest
bandit -r src -ll
pip-audit
```

GitHub Actions runs the same checks. No API secrets are required.
