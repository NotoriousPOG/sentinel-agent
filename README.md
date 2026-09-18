# Sentinel Agent

Sentinel Agent is an early-stage SOC investigation system. It will accept a security alert, investigate it with a closed set of tools, and hand a structured report to a human analyst. Remediation, if it is ever added, will require an explicit human approval. This repository does not execute response actions.

This repository stores normalized alerts, looks up indicators through a closed set of tools, and writes a verified incident report for a human to approve. Confidence is scored from stored evidence. MITRE techniques are copied only from `search_mitre` results that exist in the local Enterprise ATT&CK subset. Approving the conclusion completes the investigation. Approving remediation stores that decision and does not run it. Read `docs/architecture.md` for the control-plane decisions and `IMPLEMENTATION_PLAN.md` for milestones 1–10.

## Status

| Area | State |
| --- | --- |
| Configuration, package layout, MIT license | Present |
| Domain schemas, confidence formula, transition guards | Present and tested |
| `GET /health` and OpenAPI | Present |
| `POST /alerts`, `GET /alerts/{id}` | Persist a normalized alert. Replaying the same `alert_id` returns the first stored copy |
| `POST /investigations` | Creates a state for a stored `alert_id`, runs the executor synchronously, and returns that state. A verified report ends at `AWAITING_REVIEW`. Otherwise the run is `FAILED`. Does not approve a conclusion |
| `GET /investigations/{id}` | Reloads the stored state |
| `GET /investigations/{id}/evidence` | Returns each stored row, the indicator links, and any contradiction links. Does not merge two providers into one result |
| `GET /investigations/{id}/report` | Returns the stored report after verification accepts it. `404 report_not_found` when no verified report is stored. Does not return a draft |
| `POST /investigations/{id}/review` | Stores an `AnalystReview`. Approving the conclusion is the only path to `COMPLETE`. Rejection stores the decision and moves to `FAILED`. Approving remediation does not run an action |
| `GET /metrics` | Reserved. Returns 501. No metrics payload |
| LLM client | OpenAI-compatible HTTP client behind `LlmProvider`, using `httpx2`. No OpenAI SDK. Missing base URL, key, or model is a configuration error. The key is not logged. Tests use a fake transport or an in-process model |
| Agent loop | Calls `transition()` and the budget predicates. Tool calls go through `ToolRegistry`. The tool phase ends at `VERIFYING`. A verified report then moves to `AWAITING_REVIEW`. `COMPLETE` happens only when an analyst approves the conclusion |
| Prompt separation | System prompt is a constant. The report prompt is a separate constant. Alert text, tool results, evidence, and rejected model output go in a separate message inside untrusted-data markers. A hostile corpus is tested with a fake model that follows the payload. Not a jailbreak detector |
| Evidence correlation | Present. Two provider rows for one indicator stay two rows. A disagreeing value is listed, not dropped |
| Citation verification | Present as a pure function. It does not call a model and does not score confidence. The generator stores a report only when this function accepts it |
| Confidence scoring | `weighted_evidence_v1`. `satisfied` is set from evidence. The model does not choose the percentage. One low-reliability source cannot score 100 |
| MITRE on the report | Technique ids must appear in a cited `search_mitre` result and in the checked-in Enterprise subset. Unknown ids fail. No `search_mitre` row means `mitre_attack` is empty |
| Remediation | Not implemented. No executor, including a stub. Approval of a recommendation is a stored field |
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
| Prompt injection | Not a detector. Hostile alert text stays inside the data markers. `exec`, `run_shell`, and `fetch_url` fail closed and do not call a provider. Classification, confidence, and review do not follow alert text |
| Evals | Offline runner: `python -m sentinel.evals run --output-dir <dir>`. Synthetic dataset. The command prints the counts. This file does not copy them |
| Tracing, remediation | Not implemented. `GET /metrics` is still 501. No OpenTelemetry. No remediation executor |

Evaluation counts come from `python -m sentinel.evals run`. They are not copied into this file.

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

`POST /investigations` takes `{"alert_id": "..."}` for an alert that was already stored. It runs the executor in the request and returns the investigation state. A missing alert is 404 `alert_not_found`. A missing LLM base URL, key, or model is 503 `not_configured` and nothing is stored. `GET /investigations/{id}` reloads the state. `GET /investigations/{id}/evidence` returns each stored evidence row, indicator links, and contradiction links. It does not merge providers. `GET /investigations/{id}/report` returns the verified report, or 404 `report_not_found` when none has been stored. `POST /investigations/{id}/review` stores the analyst decision. Notes are required. `GET /metrics` returns 501.

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
