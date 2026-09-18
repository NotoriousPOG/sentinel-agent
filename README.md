# Sentinel Agent

Sentinel Agent is an early-stage SOC investigation system. It will accept a security alert, investigate it with a closed set of tools, and hand a structured report to a human analyst. Remediation, if it is ever added, will require an explicit human approval. This repository does not execute response actions.

This repository is the foundation plus alert ingestion. It does not investigate alerts. Read `docs/architecture.md` for the control-plane decisions and `IMPLEMENTATION_PLAN.md` for milestones 1–10.

## Status

| Area | State |
| --- | --- |
| Configuration, package layout, MIT license | Present |
| Domain schemas, confidence formula, transition guards | Present and tested |
| `GET /health` and OpenAPI | Present |
| `POST /alerts`, `GET /alerts/{id}` | Persist a normalized alert. Replaying the same `alert_id` returns the first stored copy |
| Investigation, evidence, report, review, and metrics routes | Reserved. They return 501 and do not investigate or remediate |
| Generic JSON adapter | Maps a JSON object onto `NormalizedAlert`. Unknown keys stay on `raw_event` and `metadata` |
| Wazuh | Normalizes the documented alert JSON cited in `tests/wazuh_fixtures.py`. Not a live manager client |
| CrowdStrike, GuardDuty, Defender, Elastic, Splunk | Interfaces only. They raise |
| LLM and threat-intel clients | Interfaces only. No network calls. `demo_mode` does not invent results |
| PostgreSQL | SQLAlchemy model and Alembic revision `0002_alerts`. Unit tests use SQLite. GitHub Actions runs the alert test against PostgreSQL |
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
alembic upgrade head
pytest
uvicorn sentinel.api.app:app --host 127.0.0.1 --port 8091
```

Health: `GET /health`. Interactive API docs: `GET /docs`.

`POST /alerts` takes `{"source": "generic_json" | "wazuh", "payload": { ... }}`. `source` defaults to `generic_json`. A validation failure is HTTP 422 with `missing_field`, `invalid_field`, `invalid_type`, or `unknown_source`. The response does not echo the submitted value. `GET /alerts/{id}` returns 404 with `alert_not_found` when the id was never stored.

Run `alembic upgrade head` before posting alerts outside the test suite. The API process in Docker Compose does that on startup.

Unit tests use SQLite and do not need PostgreSQL or API keys. SQLite is not a supported deployment. The PostgreSQL alert test runs only when `SENTINEL_TEST_DATABASE_URL` is set. Without that variable, pytest skips that one test and says why. Copy `.env.example` to `.env` if you want local overrides. Do not commit `.env`.

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

GitHub Actions runs the same checks, plus a PostgreSQL 16 service for `tests/test_alert_postgres.py`. No API secrets are required. The database password in that workflow is for the CI database only.
