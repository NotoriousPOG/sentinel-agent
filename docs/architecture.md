# Sentinel Agent architecture

Sentinel Agent investigates a single security alert and produces a structured incident report for a human analyst. This document records the control-plane decisions for that pipeline and the tradeoffs behind them. It describes the system we are building. Milestone 1 shipped typed contracts, configuration, a FastAPI skeleton, and database wiring. Milestone 2 stores a normalized alert. Milestone 3 adds the closed tool registry and the five lookups. The agent loop and the report generator do not exist yet.

The pipeline, once later milestones land, is:

```text
Security alert
  -> ingestion API
  -> schema validation
  -> normalization
  -> explicit investigation state machine
  -> closed set of typed tools
  -> threat-intelligence providers
  -> evidence records
  -> MITRE ATT&CK mapping cited to evidence
  -> deterministic confidence score
  -> IncidentReport (schema-valid or not stored)
  -> human review
  -> optional remediation recommendation (approval recorded, never executed)
```

## Orchestration: explicit state machine, not LangGraph

The investigation controller is a handwritten state machine over a closed status enum. LangGraph was considered and rejected for this product.

LangGraph is a reasonable fit when the graph is large, branches are data-dependent, and the team wants the framework's checkpointer and studio. Sentinel's control flow is the opposite: seven statuses, one bounded cycle (retry), and a hard requirement that every run ends. Putting that graph inside a framework would cost a LangChain-family dependency whose APIs move, and it would move the transition rules out of ordinary unit tests into a runtime we would have to boot to prove termination. A SOC control plane should be auditable by reading a table.

The tradeoff is real. We do not get LangGraph's checkpoint UI, and milestone 4 has to write the executor ourselves. Persistence will be a row in PostgreSQL, not a framework checkpointer. If the graph later grows into open-ended planning with many specialist agents, revisiting a graph library is reasonable. The status enum and `transition()` function are the contract; the executor can be replaced without changing stored state. Until then the dependency is not worth it. LangGraph is not installed.

### Why investigation state is explicit

Implicit agent state (a message list plus "the model will stop") cannot be tested, cannot be resumed, and cannot be explained to an analyst. `InvestigationState` is a Pydantic model with a status, budgets, and counters. The legal edges live in code, not in a prompt:

| From | To | Guard |
| --- | --- | --- |
| `RECEIVED` | `VALIDATING`, `FAILED` | none |
| `VALIDATING` | `INVESTIGATING`, `FAILED` | none |
| `INVESTIGATING` | `VERIFYING`, `FAILED` | tool calls only while `can_call_tool` is true |
| `VERIFYING` | `AWAITING_REVIEW`, `INVESTIGATING`, `FAILED` | return to `INVESTIGATING` only if retries remain |
| `AWAITING_REVIEW` | `COMPLETE`, `INVESTIGATING`, `FAILED` | `COMPLETE` only after an analyst approves the conclusion; return to `INVESTIGATING` only if retries remain |
| `COMPLETE`, `FAILED` | none | terminal |

`COMPLETE` is not "the model finished." It means an analyst approved the conclusion. A report can sit in `AWAITING_REVIEW` indefinitely; that wait is not an agent loop and does not consume tool budget.

Counters on the state (`retries`, `tool_calls_made`, `tokens_used`, `deadline_at`) are part of the state, not ambient globals. Milestone 4's executor must call the predicates in `agents/budgets.py` before every model or tool call. The predicates are implemented and tested now so the termination rules are not prose that a later change can quietly ignore.

## Termination

`COMPLETE` and `FAILED` have no outgoing edges. The only cycles are `VERIFYING -> INVESTIGATING` and `AWAITING_REVIEW -> INVESTIGATING`. Each of those increments `retries`. `transition()` rejects the edge when `retries >= max_retries`. Tool calls cannot occur outside `INVESTIGATING`, and `can_call_tool()` is false once `tool_calls_made` reaches `max_tool_calls`. Token spend and the wall-clock deadline are the same shape: a pure check, then `FAILED` with an explicit error string. Nothing in the transition function increases a budget.

That is a finite graph plus monotone counters. It is not a probabilistic stopping policy. Defaults (overridable by environment, never hardcoded in call sites) are 8 tool calls, 2 investigation retries, 1 schema-repair attempt, 120 seconds, and 24,000 tokens. Eight tool calls is deliberately small: a single alert with the five planned tools fits, and a larger cap mostly buys cost and a longer prompt-injection window. The cost is that a wide incident will end `INCONCLUSIVE` or `FAILED` instead of being "thorough." That is the right failure mode.

The executor itself is milestone 4. Shipping the guards without the loop is intentional. A loop without guards would be the dangerous order.

## Tool calls

Tools are a closed enum: `lookup_ip`, `lookup_hash`, `lookup_cve`, `search_mitre`, `lookup_domain`. Each has its own input and output model (`extra=forbid`). The model may choose a name and a payload. It may not invent a tool, pass a shell string, or pass a URL to fetch.

The call path is:

1. The model returns a tool name and arguments, validated by that tool's input model. Invalid arguments are a model-output failure, not a retry against the provider.
2. `ToolRegistry` maps the name to one of the five tools. Unknown names raise `UnknownTool`. There is no default and no shell tool.
3. The implementation calls a threat-intel provider. Vendor HTTP stays behind `HttpTransport`.
4. The output model is validated. The provider's original JSON is kept on `raw` and is untrusted data. Secrets are redacted before that copy is stored.
5. `tool_call_key(name, arguments)` is a SHA-256 of canonical JSON. The registry keeps an in-process map from that key to the first result. A repeat returns the stored result and does not call the provider. The map is not the investigation state's `seen_tool_calls` list. Milestone 4 still has to record the key on the state. The cache dies with the process; Redis is still not used.

There is no `exec`, no `run_shell`, and no `fetch_url` tool. URLs that appear in alerts or provider payloads are stored as strings. Provider clients build URLs from host constants in `services/http.py` (`api.abuseipdb.com`, `www.virustotal.com`, `api.osv.dev`). The transport rejects any other scheme, host, port, or path, and it sets a timeout. It does not follow redirects. Alert text and tool arguments are not interpolated into those hosts.

`httpx2` 2.13.0 (verified again on PyPI on 2026-09-18; same release already pinned for tests) is the runtime HTTP client. It is a same-API fork of `httpx` 0.28.1, which is what Starlette 1.6 already imports. `httpx` itself is not installed. The client is constructed only when a registry is built without an injected transport. Tests inject a transport and do not open a socket.

## Evidence grounding

An evidence record is what a tool returned, plus who returned it, when, and which claims it supports or contradicts. It is not a sentence the model wrote.

`IncidentReport` refuses to validate unless citations resolve:

- Every indicator, timeline entry, and MITRE technique lists `evidence_ids` that exist on that same report.
- `MALICIOUS`, `SUSPICIOUS`, and `BENIGN` require at least one evidence record. A bare narrative cannot classify.
- `INCONCLUSIVE` is allowed without supporting evidence, but `limitations` must be non-empty.
- Every report carries at least one limitation. "No limitations" is not a valid document.

Reliability is an enum (`high`, `medium`, `low`, `unknown`) set by `reliability_for_provider` in `tools/policy.py`, not by the model and not by text in the provider body. The table is:

| Provider | Reliability | Why |
| --- | --- | --- |
| `mock:*` | `low` | Synthetic. The name is the label. |
| `abuseipdb`, `virustotal` | `medium` | One vendor. Counts and confidence scores are not copied into this field. |
| `osv`, `mitre-attack` | `high` | Primary public record, or the official catalog subset. |
| `dns` | `low` | A resolution is not a reputation verdict. |
| anything else | `unknown` | Fail closed. |

`reported_malicious` stays `None` unless a provider documents a boolean. AbuseIPDB's `abuseConfidenceScore` is not that boolean, and a score of 0 is not stored as "clean." OSV's `severity[].score` is a CVSS vector string, not a numeric base score, so `cvss_score` stays unknown. Computing a number from the vector would invent one. NVD is not called.

These validators are necessary and not sufficient. They stop a report that cites nothing. They do not stop a report that cites a real evidence id and then misstates it. Comparing narrative claims to evidence fields is milestone 5. The schema is the backstop, not the whole control.

## Structured output

Provider outputs and model outputs cross a Pydantic v2 boundary with `extra=forbid` before they are stored or shown. The LLM port is a `Protocol`:

```text
complete_structured(messages, response_model: type[T]) -> T
```

No SDK implements it in this release. When one does, it must return an instance of `response_model` or raise. A dict "we'll validate later" is not an acceptable implementation.

If validation fails at runtime (milestone 4):

1. Persist the failure (status stays non-terminal, error string set, raw model text stored as data, not replayed into the system prompt as instructions).
2. One repair turn. The repair prompt includes the validator's error, which is our text, and the previous output inside the untrusted-data delimiters.
3. Second failure moves the investigation to `FAILED`. No partial report is promoted to `IncidentReport`.

`max_repair_attempts` defaults to 1. More repairs mostly re-expose the model to the same untrusted alert.

## Retries

Three different retries are easy to conflate. They have separate budgets:

| Failure | Budget | Counts as |
| --- | --- | --- |
| Transport error talking to a provider (timeout, 429, 5xx) | one attempt, then `ProviderError` | not an investigation retry |
| Model output fails schema validation | `max_repair_attempts` | repair, then `FAILED` |
| Verification or the analyst rejects the conclusion | `max_retries` on the state machine | the only cycle in the graph |

Provider retries must not replay a non-idempotent remediation call. That constraint is easy to keep because no remediation call exists. Investigation retries re-enter `INVESTIGATING` with the evidence already collected; they do not wipe the record. Duplicate tool keys still apply, so a retry cannot multiply provider cost by repeating the same lookup.

A provider call is a single attempt. Timeout, non-200, and a body that is not the documented object become `ProviderError`. They are not retried and they are not turned into a mock result. Exponential backoff with jitter is still not implemented.

## Confidence

Confidence is an integer from 0 to 100 produced by `weighted_evidence_v1`. It is not a probability and not a number the model may choose.

Five factors, fixed weights, each either satisfied or not:

| Factor | Weight | Satisfied when |
| --- | --- | --- |
| `evidence_coverage` | 30 | every indicator type present on the alert was looked up, or the alert had no lookup-capable indicator |
| `source_reliability` | 25 | supporting evidence used for the classification is `high` or `medium` under tool policy |
| `corroboration` | 20 | at least two different providers support the classification |
| `contradiction_penalty` | 15 | no evidence item contradicts the classification |
| `data_completeness` | 10 | the alert contains at least one of ip, hash, domain, url, cve |

`score` must equal the sum of the weights of satisfied factors. A payload with `score: 95` and factors that sum to 40 does not validate. Weights that differ from the table do not validate. Omitting a factor does not validate. Changing the weights requires a code change and a new `method` literal, so old reports stay interpretable.

The boolean `satisfied` flags are still a judgment until milestone 6 wires them to evidence. The schema can only force the arithmetic and the citations. Positive factors other than `data_completeness` must cite evidence ids. `contradiction_penalty` must cite evidence when it is unsatisfied, and may cite nothing when no contradiction exists. That asymmetry is deliberate: you can show a contradiction; you cannot show a citation for an absence.

This model will under-score sparse alerts. Good. A single low-reliability hit should not read as "90% malicious."

## Human review

`AnalystReview` records two independent decisions: approve or reject the conclusion, and optionally approve or reject a remediation recommendation. Notes are required. Unknown fields are rejected, including anything shaped like `execute` or `auto_remediate`.

`RecommendedAction.requires_human_approval` is typed as the literal `True`. A recommendation cannot be marked as safe to run unattended, even a non-destructive one. Destructive and non-destructive actions share that rule because "non-destructive" is how automatic changes get smuggled in (disabling a user is not a read).

There is no remediation executor, no playbook runner, and no endpoint that applies an action. Approval persists a decision. It does not SSH, call a firewall, or isolate a host. If that capability is ever added, it has to be a separate process that refuses to run unless a stored review has `remediation=approve` for that specific action id. This repository does not contain that process, including as a stub that could be flipped on.

`POST /investigations/{id}/review` returns 501. The model is real; the route is not.

## Provider abstraction

Two ports. The LLM port still has no implementation. Threat-intel clients are behind the second port:

- `LlmProvider` in `services/llm.py`. An OpenAI-compatible HTTP client is the likely first implementation. The OpenAI SDK is not a dependency. The port does not need it, and adding it now would suggest a live client exists.
- `ThreatIntelProvider` is the set of protocols in `services/threat_intel.py` (`IpIntelligence`, `FileIntelligence`, `CveIntelligence`, `MitreCatalog`, `DomainIntelligence`). Clients:
  - AbuseIPDB `GET /api/v2/check` when `SENTINEL_ABUSEIPDB_API_KEY` is set. No geo API is called to fill gaps. Without the key, and with `demo_mode` off, the lookup raises `ConfigurationError`.
  - VirusTotal v3 `GET /api/v3/files/{hash}` when `SENTINEL_VIRUSTOTAL_API_KEY` is set. The key is an `x-apikey` header. It is not written to `raw`, logs, or exception text.
  - OSV `GET /v1/vulns/{id}` (public, no key). Reference URLs are stored and not fetched.
  - A checked-in subset of Enterprise ATT&CK 19.2. See `src/sentinel/data/attack/README.md`. Search does not download the bundle.
  - DNS via an injected resolver. The default uses `socket.getaddrinfo` with a timeout. It does not HTTP-fetch the domain.

  `SENTINEL_DEMO_MODE` selects `mock:abuseipdb` and `mock:virustotal` before the call. It does not replace CVE, MITRE, or DNS, and it does not catch a live failure and return a mock. Mock `raw` payloads are marked synthetic. Keys, when configured, are `SecretStr`. No vendor SDK is installed.

Source adapters are a third port. `GenericJsonAdapter` maps a JSON object onto `NormalizedAlert`. Keys that are not fields of that model are copied onto `raw_event` when the caller did not supply one, and listed under `metadata.unmapped_fields`. They are not promoted to first-class fields. `NormalizedAlert` itself still rejects unknown keys (`extra=forbid`); the split happens in the adapter, not by loosening the model.

`WazuhAdapter` maps the alert object Wazuh documents, not a guessed schema. The fixture is the logtest `data.output` object from [testing a rule](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html), plus the older JSON object on [dynamic fields](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/dynamic-fields.html) which has a numeric `rule.id`, an offset-less timestamp, and no top-level `id`. Static decoder names the mapper reads (`srcip`, `dstip`, `srcuser`, `dstuser`, `user`, `url`) are the ones Wazuh lists as [static fields](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html). `full_log` is preserved on `raw_event` and is not copied into `command_line`. MITRE ids, ports, and dynamic objects such as `audit` stay on `raw_event`. A missing `rule` or a missing top-level `id` fails closed; the adapter does not invent an `alert_id`. Severity bands are Sentinel's mapping of Wazuh's documented 0–15 levels, not names Wazuh defines. There is no Wazuh manager client.

`POST /alerts` accepts `{"source": "generic_json" | "wazuh", "payload": {...}}`, stores the normalized document, and returns it. The same `alert_id` is idempotent: the first write wins, and a later body does not replace it. `GET /alerts/{id}` reloads that row. Validation failures use `missing_field`, `invalid_field`, `invalid_type`, or `unknown_source`, and do not echo the submitted value. A missing id is `alert_not_found`. Windows and Sysmon decoder shapes are not parsed into first-class fields.

`CrowdStrikeFalconAdapter`, `GuardDutyAdapter`, `DefenderAdapter`, `ElasticAdapter`, and `SplunkAdapter` are concrete classes whose only behavior is to raise. They are interfaces with a name you can import, not integrations. No payload fixtures are shipped for them, because a fixture would imply we had specified a vendor contract we have not tested against vendor documentation.

## Prompt injection

Alerts, logs, usernames, hostnames, URLs, domains, process names, command lines, file paths, and threat-intel `raw` blobs are untrusted data. They are never instructions. The field set is `UNTRUSTED_ALERT_FIELDS` in `security/untrusted.py`, and a test fails if a new attacker-controlled alert field is added without being listed. That test is a tripwire, not a filter.

Structural controls, which this design treats as primary:

- The system prompt is a constant owned by the repo. Untrusted fields are not interpolated into it. They go in a separate message, inside delimiters, in milestone 7. There is no prompt template in this release, so there is nothing to inject into yet. The constraint is still binding on later code.
- Tools cannot shell out and cannot fetch arbitrary URLs, so "ignore instructions and curl this host" has no capability to bind to.
- Tool arguments are typed. A command line from the alert cannot become a process argument unless a tool input model explicitly has that field. None of the five tools do.
- Database access goes through SQLAlchemy. Alert strings are not concatenated into SQL.
- `extra=forbid` drops the common trick of an extra JSON field that a loose mapper would copy into a prompt or a tool argument.
- Provider `raw` is stored, not passed to `eval`, YAML load, or a template engine.

What this does not do, and must not be described as doing: detect jailbreaks, strip "ignore previous instructions," or sanitize HTML. Those are milestone 7, they are incomplete even when built, and a regex denylist is the wrong core control. Input isolation plus a closed tool set is the core control.

`NewType` wrappers are not used. They disappear at runtime and create a false sense of a boundary. The boundary is the message channel and the tool schema.

## Observability

Milestone 9 adds tracing, metrics, cost, and structured logs. This release configures stdlib logging at `SENTINEL_LOG_LEVEL` and nothing else. OpenTelemetry is not installed. A no-op tracer would either be untested decoration or a dependency we do not exercise. `GET /metrics` returns 501 so the path is reserved without a fake Prometheus payload.

When instrumentation arrives, the rules are: one investigation id as the correlation id, no API keys in logs, no full command lines at info level (they are credentials and payloads as often as they are evidence), and provider `raw` only at debug behind an explicit flag. `GET /health` is liveness. It does not touch PostgreSQL. A readiness check that fails when the database is down is useful and is deferred so the health test stays free of a database.

## Persistence

PostgreSQL is the system of record for anything that must survive a process restart. SQLAlchemy 2.x and Alembic are wired. Revision `0002_alerts` creates the `alerts` table: `alert_id` (primary key), `source`, `received_at`, and `document` (portable JSON, not JSONB, so the same revision applies on SQLite). Investigation tables are still absent; they arrive with the code that writes them.

`POST /alerts` and `GET /alerts/{id}` read and write that table. The API does not open a database connection at import time. `GET /health` still does not touch the database. Unit tests migrate a temporary SQLite file. A separate test uses `SENTINEL_TEST_DATABASE_URL` and is what GitHub Actions runs against a PostgreSQL 16 service. If that variable is unset in GitHub Actions the test fails rather than skipping. SQLite is not a supported deployment. Docker Compose runs PostgreSQL 16 for local development and applies `alembic upgrade head` before serving.

Alembic lives at the repository root (`alembic.ini`, `alembic/`) rather than under `src/sentinel/storage/`. That is the layout Alembic's own documentation and `alembic upgrade` assume. Moving it inside the package would require a custom `script_location` and would mix migration scripts with importable application code. The ORM base class stays in `src/sentinel/models/`.

Pydantic models live in `schemas/`. SQLAlchemy models will live in `models/`. Sharing one module for both has been a consistent source of import cycles and of API models growing database columns they should not expose.

## Configuration

`pydantic-settings` loads `SENTINEL_*` environment variables. Secrets use `SecretStr`. The API key is not read by any client. `.env.example` contains placeholders. Docker Compose uses a local database password for a local database; it is not a production secret and it is not reused as a default inside Python. The application default database URL is a local SQLite file so `pytest` and a casual import do not attempt to authenticate to PostgreSQL.

`SENTINEL_DEMO_MODE` selects mock IP and hash providers when `build_registry` runs. Loading settings, `GET /health`, and `POST /alerts` do not call a provider. The flag does not start an investigation.

## Intentionally deferred

**Redis.** There is no queue. A single investigation is a short state machine with a hard timeout, and milestone 4 can run it as an in-process task. Redis becomes justified when more than one API replica must share a work queue or a tool-result cache. Adding it now means another service in Compose, a client library, and a cache that can serve stale or attacker-influenced tool output before we have a cache policy. The registry cache is per process only. `tool_call_key` itself is still a pure function.

**pgvector.** Evidence is retrieved by primary key and by investigation id, not by similarity. Semantic search over past incidents would pull other customers' or other analysts' untrusted text into the prompt, which is a prompt-injection path, and it requires an extension the local Postgres image does not need. Relational citations are the grounding model. Vectors can wait until that model works and a real retrieval eval exists.

**OpenTelemetry, Prometheus, LangGraph, OpenAI SDK, vendor TI SDKs.** See the sections above. HTTP to AbuseIPDB, VirusTotal, and OSV uses `httpx2` behind the allowlist. The SDKs are still not dependencies.

## What milestone 1 actually contains

Typed domain models, the transition and budget functions, source-adapter interfaces, provider protocols, settings, `GET /health`, reserved routes that return 501, an Alembic baseline, Docker Compose for the API plus PostgreSQL, and tests that do not need network credentials. No investigation runs. No external security service is contacted. No benchmark number exists.

## What milestone 2 adds

Wazuh and generic JSON normalization, stable validation error codes, the `alerts` table, and `POST /alerts` / `GET /alerts/{id}`. Replay of an `alert_id` is idempotent. Vendor adapters other than Wazuh still raise. Tools are a separate call path; posting an alert does not look anything up.

## What milestone 3 adds

`ToolRegistry` and the five tools: `lookup_ip`, `lookup_hash`, `lookup_cve`, `search_mitre`, `lookup_domain`. AbuseIPDB and VirusTotal run only when their keys are set. OSV, the local ATT&CK subset, and DNS do not need keys. `demo_mode` selects labeled mocks for IP and hash only. There is still no agent loop, no report generator, no review storage, no eval runner, no tracing, and no remediation executor. `POST /investigations` is still 501.
