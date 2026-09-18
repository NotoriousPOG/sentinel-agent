# Implementation plan

Sentinel Agent is an open-source SOC investigation system. This plan is the contract for milestones 1 through 10. Milestone 1 is the only milestone implemented in the foundation branch. Later milestones are specified so the foundation does not paint them into a corner. Acceptance criteria are checks a reviewer can run or read, not slogans.

The product pipeline is:

```text
Security Alert -> Ingestion API -> Schema Validation -> Alert Normalization
  -> AI Investigation Agent -> Tool Selection -> Threat Intelligence Queries
  -> Evidence Correlation -> MITRE ATT&CK Mapping -> Confidence Assessment
  -> Structured Incident Report -> Human Review
  -> Optional Remediation Recommendation (human approval only; no executor)
```

## Repository structure

```text
README.md
LICENSE
.env.example
.gitignore
pyproject.toml
Dockerfile
docker-compose.yml
alembic.ini
alembic/
  env.py
  versions/0001_initial.py
src/sentinel/
  api/                 FastAPI app, health, alert routes, reserved 501 routes
  agents/              status transitions and budget predicates (no loop yet)
  models/              SQLAlchemy declarative base (no tables yet)
  schemas/             Pydantic domain models
  tools/               tool Protocol only
  services/            source adapters, LLM port, TI port
  storage/             engine and session factory
  observability/       package marker; instrumentation is milestone 9
  security/            untrusted-field registry (not a detector)
  config/              pydantic-settings
tests/
evals/README.md        pointer to milestone 8
examples/README.md     pointer only; no sample investigations
docs/
  architecture.md
  threat-model.md      stub
  evaluations.md       stub
  security.md          stub
  adding-tools.md      stub
.github/workflows/test.yml
.github/workflows/security.yml
```

Two layout choices differ from a flat `src/sentinel/<area>` dump:

- Pydantic models are `schemas/`. SQLAlchemy models are `models/`. The alternative, one shared `models` package, couples API contracts to tables.
- Alembic stays at the repository root. That is the layout `alembic upgrade` expects. Reasons are in `docs/architecture.md`.

No other structural deviation. LangGraph is not a package and not a directory.

## Milestone plan

### 1. Foundation (this branch)

Structure, configuration, domain schemas, FastAPI skeleton, database wiring, tests, Docker, CI.

Acceptance:

- `pytest` passes with no API keys and no running PostgreSQL.
- `GET /health` returns 200. Reserved product routes exist. Investigation, review, and metrics routes return 501. They do not create investigations. Milestone 2 replaced the 501 response for alert routes.
- Malformed alerts fail validation. Milestone 1 left a valid `POST /alerts` at 501. Milestone 2 stores a valid alert.
- Illegal investigation transitions and exhausted retries raise. Terminal statuses have no exits.
- `IncidentReport` rejects dangling evidence ids and rejects a confidence score that does not match `weighted_evidence_v1`.
- `alembic upgrade head` applies against SQLite in the test suite. Compose is the PostgreSQL path.
- `ruff check`, `mypy`, and the security workflow do not need secrets.
- README status section matches the code. No benchmark numbers.

### 2. Alert pipeline

Status: done for the criteria below. Milestones 3–10 are not started.

Generic JSON beyond the identity mapping, Wazuh normalization, validation errors with stable codes, persistence.

Acceptance:

- [x] A Wazuh fixture drawn from Wazuh's documented alert shape normalizes into `NormalizedAlert`, including `full_log` preserved on `raw_event`, and a second fixture with a missing `rule` fails closed.
- [x] Generic JSON unknown keys are preserved on `raw_event` or `metadata` and are not promoted to first-class fields.
- [x] `POST /alerts` and `GET /alerts/{id}` persist and reload. Unit tests use SQLite. `tests/test_alert_postgres.py` uses PostgreSQL when `SENTINEL_TEST_DATABASE_URL` is set. GitHub Actions sets that URL and starts PostgreSQL 16. If the variable is missing in GitHub Actions the test fails instead of skipping. On a machine without the variable, pytest skips that one test and prints why.
- [x] Replay of the same `alert_id` is idempotent. The first write wins; a different body does not replace the stored alert.
- [x] Validation errors use stable codes: `missing_field`, `invalid_field`, `invalid_type`, `unknown_source`. A missing alert is `alert_not_found`.
- [x] Tests do not require a live Wazuh manager.

Not done, and not claimed:

- Dynamic decoder fields and Windows/Sysmon shapes are not mapped to first-class fields. They remain on `raw_event`.
- The 2017 dynamic-fields JSON example has no top-level `id`. Normalization fails closed instead of inventing an `alert_id`.
- No Wazuh manager client.
- CrowdStrike, GuardDuty, Defender, Elastic, and Splunk still raise and have no fixtures.
- Tools, the agent loop, report generation, review storage, prompt-injection runtime defenses, evals, tracing, and remediation execution are later milestones.

### 3. Tool system

Tool interface, registry, the five tools, mock providers clearly labeled as mocks.

Acceptance:

- Each tool's input model rejects the wrong shape. The registry refuses unknown names.
- Mock providers return canned data only when `demo_mode` is on, and every mock result is tagged `provider` starting with `mock:`. They are not importable as default.
- Real provider clients (AbuseIPDB, VirusTotal, NVD/OSV, or a local MITRE STIX bundle) sit behind `ThreatIntelProvider`. Missing keys fail with a configuration error, not a fabricated verdict.
- Duplicate `tool_call_key` does not call the provider twice in a unit test with a fake clock and a counting provider.
- No tool accepts a shell command or an arbitrary URL fetch.

### 4. Agent

State, tool selection, loop, budgets, retries, termination.

Acceptance:

- The executor is a function that takes `InvestigationState` and ports (LLM, tools). It is unit-tested with fakes.
- A model that asks for tools forever stops at `max_tool_calls` and ends `FAILED` or moves to `VERIFYING` with partial evidence. It does not hang. A test uses a fake model and asserts the call count.
- Schema-invalid model output is repaired at most `max_repair_attempts` times, then `FAILED`, and no `IncidentReport` is stored.
- Deadline expiry is tested with an injected clock.
- The LLM port is the only network path, and the test suite does not open it.

### 5. Evidence

Correlation, citations, verification.

Acceptance:

- Two provider results for the same indicator become two evidence rows linked to one indicator, not a merged blob.
- A report whose executive summary names an IP absent from the alert and from evidence fails verification.
- Contradicting evidence is visible on the report, not dropped to keep a clean story.
- Reliability comes from the tool policy table. A test shows the model cannot set reliability by putting it in free text.

### 6. Reporting

Structured reports, confidence scoring, MITRE mapping, human review persistence.

Acceptance:

- The scorer sets `satisfied` from evidence and the formula in `docs/architecture.md`. A fixture with one low-reliability source cannot score 100.
- MITRE techniques on the report are a subset of `search_mitre` results (or a local bundle), not free-typed technique ids the model invented. Unknown technique ids fail validation.
- `POST /investigations/{id}/review` stores an `AnalystReview` and is the only path from `AWAITING_REVIEW` to `COMPLETE`.
- Approving remediation writes the decision and does not invoke a side effect. A test spies on a forbidden executor symbol and asserts it does not exist.

### 7. AI security

Prompt-injection defenses, tool authorization, input isolation, security tests.

Acceptance:

- A fixture corpus of alert bodies (instruction overrides, fake tool calls, HTML, long Unicode) is run through normalization and a fake model. None of them add a tool, change the system prompt, or pass schema validation as a tool call unless they are inside the tool-argument channel.
- System prompt construction asserts that untrusted fields appear only inside the data delimiters.
- Tests cover the five untrusted categories named in the product spec: logs, usernames, URLs, domains, process arguments, plus TI `raw`.
- `docs/threat-model.md` and `docs/security.md` are updated from stubs to match the tests. Claims that do not have a test are deleted.

### 8. Evaluations

Synthetic dataset, runner, metrics, CLI.

Acceptance:

- `python -m sentinel.evals run` executes against the mock providers and writes JSON and Markdown under a path the flag selects.
- Metrics are computed from the dataset (schema pass rate, citation resolution, termination, classification agreement with labels shipped in the dataset). The README does not copy those numbers; the command prints them.
- The dataset is synthetic and labeled as such in `evals/README.md`.
- No test or doc invents a detection rate, a benchmark ranking, or a comparison with a vendor product.

### 9. Observability

Tracing, metrics, cost tracking, structured logs, correlation ids.

Acceptance:

- Each investigation emits one correlation id, present on logs and on the trace.
- `GET /metrics` exposes investigation counts, tool errors, and token totals. It does not expose alert bodies or keys.
- A unit test asserts a configured `SecretStr` never appears in a captured log line during a fake investigation.
- OpenTelemetry is added only with an exporter that defaults to off. Tests do not require a collector.
- `docs` describe how to turn it on locally.

### 10. Portfolio polish

README, diagrams, demo, example investigation, docs.

Acceptance:

- A reviewer can clone, start Compose, submit the example synthetic alert, and read tools, evidence, MITRE, report, and confidence without a paid key (`demo_mode` and mock providers from milestone 3).
- The README status section is updated to match what the commands actually do.
- Screenshots are taken from that run, not mocked in an image editor.
- `docs/adding-tools.md` tells a contributor how to add a tool without granting shell or arbitrary HTTP.

Definition of done for the finished product, not for this branch: a reviewer clones the repo, runs it locally without paid API keys, submits a synthetic alert, watches an investigation, inspects tools, evidence, MITRE mapping, the report, and the confidence breakdown, records a review, and runs evals and tests.

## Dependencies

Verified on 2026-09-18 with `pip index versions <name>` against PyPI. Versions below are the current releases observed that day. Lower bounds in `pyproject.toml` match these releases so an install cannot silently resolve to an older major we did not read. They are not a lockfile.

### Runtime

| Package | Version verified | Why it is here |
| --- | --- | --- |
| `fastapi` | 0.141.1 | HTTP API and OpenAPI. Pulls Starlette (observed 1.6.0 transitively; not pinned separately). |
| `pydantic` | 2.13.5 | Domain models. v2 is required. |
| `pydantic-settings` | 2.15.0 | `SENTINEL_*` environment configuration. |
| `uvicorn` | 0.53.0 | ASGI server. The `standard` extra is not used; it pulls optional servers we do not need. |
| `sqlalchemy` | 2.0.54 | Engine, sessions, future ORM. 2.x style only. |
| `alembic` | 1.20.0 | Migrations. |
| `psycopg[binary]` | `psycopg` 3.3.6, extra pulls `psycopg-binary` 3.3.6 | PostgreSQL driver for SQLAlchemy's `postgresql+psycopg` URL. The binary extra avoids compiling `libpq` in the image. |

`setuptools` 84.0.0 is the build backend only (`requires` in `[build-system]`), not an application dependency.

### Development and CI

| Package | Version verified | Why it is here |
| --- | --- | --- |
| `pytest` | 9.1.1 | Test runner. |
| `httpx2` | 2.13.0 | Starlette 1.6's `TestClient` imports `httpx2` and treats `httpx` as a deprecated fallback. Dev-only. A runtime HTTP client waits for milestone 3, when a tool actually calls out. |
| `ruff` | 0.16.8 | Lint and format in CI. |
| `mypy` | 2.3.1 | Type check. Uses the `pydantic.mypy` plugin shipped inside `pydantic`, not a separate package. |
| `bandit` | 1.9.4 | Static checks for obvious dangerous calls in `src/`. |
| `pip-audit` | 2.10.1 | Known-vulnerability check of installed distributions. Uses the public OSV dataset. No API key. |

### Considered and not added

| Package | Decision |
| --- | --- |
| LangGraph / LangChain | Not installed. Orchestration is the explicit state machine in `docs/architecture.md`. Not queried for a pin because it is not a dependency. |
| `openai` or any other LLM SDK | The port is a `Protocol`. An SDK is justified only when a class implements that port and needs the SDK's types. |
| `redis` | No queue and no shared cache. See architecture. |
| `pgvector` | No similarity search. Citations are relational. |
| OpenTelemetry (`opentelemetry-api`, `opentelemetry-sdk`) | Milestone 9, and only with a default-off exporter. A no-op dependency is still a dependency. |
| `prometheus-client` | Same milestone as `GET /metrics`. The route is 501 until then. |
| `structlog` | stdlib logging is enough until milestone 9. |
| `httpx` | The test client does not need it. Runtime HTTP is still milestone 3. |
| Vendor SDKs (VirusTotal, and similar) | HTTP behind `ThreatIntelProvider` when a provider is implemented. No SDK by default. |
| `email-validator` | Not used. `EmailStr` is not a field. |

## Non-goals for this phase

Milestone 1 does not:

- Parse Wazuh into a normalized alert, or talk to a Wazuh manager.
- Implement CrowdStrike, GuardDuty, Defender, Elastic, or Splunk.
- Call an LLM, a threat-intel API, or an arbitrary URL.
- Run an agent loop, select tools, or generate a report.
- Persist alerts, evidence, or reviews.
- Execute or simulate remediation, including "dry run" actions.
- Detect prompt injection at runtime, score a corpus, or emit eval numbers.
- Ship OpenTelemetry, Prometheus, Redis, or pgvector.
- Provide a portfolio README, diagrams, screenshots, or a demo investigation.
- Claim that `demo_mode` does anything.

## Configuration reference

See `.env.example`. All variables are prefixed `SENTINEL_`. Credentials are never defaulted in Python. The Compose file sets a local Postgres URL for local Postgres only.

## Test and CI commands

```text
pip install -e ".[dev]"
ruff check src tests
mypy src
pytest
bandit -r src -ll
pip-audit
```

CI runs those in `.github/workflows/test.yml` and `.github/workflows/security.yml`. A failing test fails the workflow. No API secrets are configured or required.
