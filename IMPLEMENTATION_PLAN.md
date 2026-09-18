# Implementation plan

Sentinel Agent is an open-source SOC investigation system. This plan is the contract for milestones 1 through 10. Milestones 1 and 2 are implemented. Milestone 3 is implemented for the criteria checked below. Milestone 4 is implemented for the criteria checked below. Milestone 5 is implemented for the criteria checked below. Milestones 6–10 are not started. Acceptance criteria are checks a reviewer can run or read, not slogans.

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
  versions/0002_alerts.py
  versions/0003_investigations.py
src/sentinel/
  api/                 FastAPI app, health, alert and investigation routes, reserved 501 routes
  agents/              executor, prompt separation, status transitions, budget predicates
  evidence/            correlation and citation verification; no model call
  models/              SQLAlchemy models for alerts and investigations
  schemas/             Pydantic domain models
  tools/               closed registry and the five tools
  services/            source adapters, LLM port, threat-intel clients
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
  adding-tools.md      how to add a tool without shell or arbitrary HTTP
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

Status: done for the criteria below.

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

Status: done for the criteria below. The investigation loop is milestone 4.

Tool interface, registry, the five tools, mock providers clearly labeled as mocks.

Acceptance:

- [x] Each tool's input model rejects the wrong shape. The registry refuses unknown names. There is no default tool and no shell tool.
- [x] Mock providers return canned data only when `demo_mode` is on, and every mock result is tagged `provider` starting with `mock:`. `build_registry` does not select them when the flag is off.
- [x] Real provider clients sit behind the protocols in `services/threat_intel.py`. AbuseIPDB and VirusTotal run only with their keys. OSV is the public CVE source. MITRE is a local Enterprise ATT&CK 19.2 subset. Missing keys raise `ConfigurationError`, not a fabricated verdict. A timeout or non-200 raises `ProviderError`.
- [x] Duplicate `tool_call_key` does not call the provider twice. The unit test uses a fake clock and a counting provider.
- [x] No tool accepts a shell command or an arbitrary URL fetch. Vendor HTTP hosts are constants, with a timeout.

Not done, and not claimed:

- No agent loop, no report generator, no review storage, no eval runner, no tracing, and no remediation executor.
- Provider transport errors are not retried. Backoff is not implemented.
- NVD is not called. OSV does not provide a numeric CVSS base score, so `cvss_score` stays unknown.
- `demo_mode` mocks only IP and hash. It does not mock CVE, MITRE, or DNS, and it does not replace a failed live call.
- The MITRE file is a subset, not the full Enterprise catalog. A search miss is "not in the subset."
- No HTTP route ran a tool in milestone 3. `POST /investigations` is implemented in milestone 4.

### 4. Agent

Status: done for the criteria below. Evidence correlation and verification are milestone 5.

State, tool selection, loop, budgets, retries, termination. Persistence and the investigation routes that call the executor are included because the executor has to be reachable.

Acceptance:

- [x] The executor is a function that takes `InvestigationState` and ports (LLM, tools). It is unit-tested with fakes.
- [x] A model that asks for tools forever stops at `max_tool_calls` and ends `FAILED` or moves to `VERIFYING` with partial evidence. It does not hang. A test uses a fake model and asserts the call count.
- [x] Schema-invalid model output is repaired at most `max_repair_attempts` times, then `FAILED`, and no `IncidentReport` is stored.
- [x] Deadline expiry is tested with an injected clock.
- [x] The test suite does not open the LLM port and does not call a live model. Executor tests use an in-process fake. The HTTP client is tested with a fake transport. This is not a claim that the LLM is the only network path: milestone 3 threat-intel HTTP remains, and those tests still inject a transport.

Also done in this milestone, because the executor builds prompts and the API has to store the state:

- Tool calls go through `ToolRegistry`. Unknown names and invalid arguments are model-output failures and use the repair budget. They do not call the provider.
- A repeated tool key is returned by the registry cache. The executor does not call the provider again and does not spin.
- A successful tool phase stops at `VERIFYING`. The executor does not enter `AWAITING_REVIEW` or `COMPLETE`.
- Provider and LLM transport errors end `FAILED` without incrementing `retries`. Backoff is not implemented.
- The system prompt is a constant. Alert text, tool results, and rejected model output are in a separate message inside untrusted-data markers. There is no jailbreak detector.
- `0003_investigations` persists the state. `POST /investigations` runs the executor for a stored alert. `GET /investigations/{id}` reloads it. `GET /investigations/{id}/evidence` returned the stored records without correlating them; milestone 5 adds indicator and contradiction links. Report and review stay 501.
- A thin OpenAI-compatible client implements `LlmProvider` with `httpx2`. Missing base URL, key, or model is `ConfigurationError`. The key is not logged and is not put on an exception or a result. The OpenAI SDK is not a dependency.

Not done, and not claimed:

- Evidence correlation and citation verification are milestone 5. Confidence scoring from live evidence, MITRE mapping onto a report, `IncidentReport` generation, and analyst review storage were not part of milestone 4.
- No path from `VERIFYING` back to `INVESTIGATING`. That retry belongs to verification and review, which are later milestones.
- Provider backoff is not implemented. A provider or LLM transport error fails the investigation instead of trying again.
- Prompt-injection detection, a fixture corpus, and updates to `docs/threat-model.md` and `docs/security.md` are milestone 7. Separation is not injection resistance.
- No eval runner, no OpenTelemetry, no remediation execution, no benchmark numbers.
- `GET /investigations/{id}/report` and `POST /investigations/{id}/review` stay 501.

### 5. Evidence

Status: done for the criteria below. Milestones 6–10 are not started.

Correlation, citations, verification. Unit tests use fakes. No network and no live model.

Acceptance:

- [x] Two provider results for the same indicator become two evidence rows linked to one indicator, not a merged blob.
- [x] A report whose executive summary names an IP absent from the alert and from evidence fails verification.
- [x] Contradicting evidence is visible on the report, not dropped to keep a clean story.
- [x] Reliability comes from the tool policy table. A test shows the model cannot set reliability by putting it in free text.

Also done, because the same checks cover the rest of the evidence rules in `docs/architecture.md`:

- Unknown stays unknown. `reported_malicious: null` does not contradict a boolean and does not support `BENIGN`. A failed lookup is not a benign result. A `malicious_count` of 0 without a harmless count is not benign.
- Conclusions the verifier accepts cite evidence ids that were collected. An id that was not collected fails. Conflicting values are a list of observations. They are not averaged, and `weighted_evidence_v1` is not computed.
- A fact must name a tool-output field and match that field. `raw` is not a field. An inference presented as a fact fails when no stored field supports it. The same test shows free text and `raw` cannot set reliability.
- `GET /investigations/{id}/evidence` returns the separate rows, indicator links, and contradiction links. It does not change status.
- `apply_verification` records the result on the state. A pass stays `VERIFYING`. A failure calls `transition()` to `FAILED` only when `retries >= max_retries`. It does not return to `INVESTIGATING` and does not enter `AWAITING_REVIEW` or `COMPLETE`. The executor's stop rules are unchanged.

Not done, and not claimed:

- `weighted_evidence_v1` booleans are not set from live evidence. That is milestone 6.
- MITRE techniques are not mapped onto a report. A `search_mitre` row stays evidence. It is not turned into `mitre_attack`.
- No model generates an `IncidentReport`. The verifier only accepts or rejects an object the caller built.
- `GET /investigations/{id}/report` and `POST /investigations/{id}/review` stay 501. Nothing moves an investigation to `AWAITING_REVIEW` or `COMPLETE`.
- Verification does not spend a retry by returning to `INVESTIGATING`. `transition()` still allows that edge. This milestone does not call it.
- No jailbreak detector, eval runner, OpenTelemetry, or remediation executor.
- Mock providers are still the milestone 3 mocks. Their names still start with `mock:`. This milestone does not invent threat-intelligence results.

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
| `httpx2` | 2.13.0 | HTTP client for AbuseIPDB, VirusTotal, and OSV. Re-verified on PyPI on 2026-09-18. `httpx` 0.28.1 was current the same day and was not added; `httpx2` is the same-API fork Starlette 1.6's `TestClient` already imports. |

`setuptools` 84.0.0 is the build backend only (`requires` in `[build-system]`), not an application dependency.

### Development and CI

| Package | Version verified | Why it is here |
| --- | --- | --- |
| `pytest` | 9.1.1 | Test runner. |
| `httpx2` | 2.13.0 | Also listed under runtime. The dev extra keeps the pin because `TestClient` imports it. |
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
| `httpx` | Not added. `httpx2` 2.13.0 is the HTTP client. |
| Vendor SDKs (VirusTotal, and similar) | HTTP behind the threat-intel protocols. No SDK. |
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
