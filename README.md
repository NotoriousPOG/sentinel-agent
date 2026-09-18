# Sentinel Agent

Sentinel Agent is an early-stage SOC investigation system. It will accept a security alert, investigate it with a closed set of tools, and hand a structured report to a human analyst. Remediation, if it is ever added, will require an explicit human approval. This repository does not execute response actions.

This repository stores normalized alerts, looks up indicators through a closed tool set, and runs a bounded investigation that stops at `VERIFYING` or `FAILED`. It does not write an incident report, store an analyst review, or execute remediation. Read `docs/architecture.md` for the control-plane decisions and `IMPLEMENTATION_PLAN.md` for milestones 1–10.

## Status

| Area | State |
| --- | --- |
| Configuration, package layout, MIT license | Present |
| Domain schemas, confidence formula, transition guards | Present and tested |
| `GET /health` and OpenAPI | Present |
| `POST /alerts`, `GET /alerts/{id}` | Persist a normalized alert. Replaying the same `alert_id` returns the first stored copy |
| `POST /investigations` | Creates a state for a stored `alert_id`, runs the executor synchronously, and returns that state. Stops at `VERIFYING` or `FAILED`. Does not approve a conclusion |
| `GET /investigations/{id}` | Reloads the stored state |
| `GET /investigations/{id}/evidence` | Returns evidence records stored on that state. Does not correlate or verify them |
| Report, review, and metrics routes | Reserved. They return 501 and do not store a report, store a review, or remediate |
| LLM client | OpenAI-compatible HTTP client behind `LlmProvider`, using `httpx2`. No OpenAI SDK. Missing base URL, key, or model is a configuration error. The key is not logged. Tests use a fake transport or an in-process model |
| Agent loop | Calls `transition()` and the budget predicates. Tool calls go through `ToolRegistry`. A tool phase ends at `VERIFYING`. `COMPLETE` is still only after analyst approval, which this release does not do |
| Prompt separation | System prompt is a constant. Alert text, tool results, and rejected model output go in a separate message inside untrusted-data markers. Not a jailbreak detector |
| Evidence correlation, report generation, review storage | Not implemented |
| Generic JSON adapter | Maps a JSON object onto `NormalizedAlert`. Unknown keys stay on `raw_event` and `metadata` |
| Wazuh | Normalizes the documented alert JSON cited in `tests/wazuh_fixtures.py`. Not a live manager client |
| CrowdStrike, GuardDuty, Defender, Elastic, Splunk | Interfaces only. They raise |
| PostgreSQL | SQLAlchemy models and Alembic revisions through `0003_investigations`. Unit tests use SQLite. GitHub Actions runs the alert test against PostgreSQL |
| Threat-intel tools | Closed registry: `lookup_ip`, `lookup_hash`, `lookup_cve`, `search_mitre`, `lookup_domain`. Unknown names are refused. No shell or URL-fetch tool |
| IP reputation | AbuseIPDB when `SENTINEL_ABUSEIPDB_API_KEY` is set. A missing key is a configuration error. No geo API |
| File hash | VirusTotal v3 when `SENTINEL_VIRUSTOTAL_API_KEY` is set. The key is not copied into results or logs |
| CVE | OSV `GET /v1/vulns/{id}`. Numeric CVSS is left unknown; OSV returns a vector, not a base score |
| MITRE ATT&CK | Local subset of Enterprise 19.2. Source and retrieval date are in `src/sentinel/data/attack/README.md`. Not the full catalog |
| DNS | Resolver with a timeout. Tests inject the resolver. The domain is not fetched over HTTP |
| `demo_mode` | Selects mock IP and hash providers tagged `mock:`. Does not start an investigation by itself, and does not replace a failed live call |
| Prompt-injection detection, evals, tracing, remediation | Not implemented. Prompt separation above is not a detector |

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

`POST /investigations` takes `{"alert_id": "..."}` for an alert that was already stored. It runs the executor in the request and returns the investigation state. A missing alert is 404 `alert_not_found`. A missing LLM base URL, key, or model is 503 `not_configured` and nothing is stored. `GET /investigations/{id}` reloads the state. `GET /investigations/{id}/evidence` returns the evidence records on that state and does not correlate them. `GET /investigations/{id}/report` and `POST /investigations/{id}/review` return 501.

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
