# Observability

Correlation, logs, process counters, and optional traces. None of this starts a collector. `GET /health` is still liveness and still does not touch PostgreSQL.

## Correlation id

Each call to `run_investigation` has one correlation id: that investigation's `investigation_id`. The same value is:

- the `correlation_id` field on JSON log lines emitted for that run
- the `correlation_id` attribute on the single span named `investigation`

A later log line for a different investigation uses that other id. Lines emitted outside a run have `correlation_id` set to `null`.

## Logs

Investigation and provider events are one JSON object per line. The object carries `event` and `correlation_id`. It does not carry alert bodies, command lines, usernames, tool arguments, or API keys. A configured `SecretStr` is stripped from `sentinel` log lines if it would otherwise appear.

Provider `raw` is not logged at info. `log_raw_payload` is the only helper that may emit it, and only at debug, and only when `SENTINEL_LOG_PROVIDER_RAW` is true. Provider clients do not call that helper, so `raw` is not written during an investigation. Leave the flag false.

`SENTINEL_LOG_LEVEL` is the stdlib level. It is not the trace exporter.

## `GET /metrics`

The route returns JSON for this process:

| Field | Meaning |
| --- | --- |
| `investigations_total` | Investigations this process has finished |
| `investigations_by_status` | Those investigations, by current status |
| `tool_errors` | Failed tool invocations (unknown name, invalid arguments, provider error, provider not configured) |
| `tokens_total` | `tokens_used` summed across those investigations |
| `estimated_cost_usd` | See below |

An analyst review updates the status of an investigation this process already recorded. It does not add a row for an investigation this process never ran.

The counters are in memory. They start at zero when the process starts. They are not read from PostgreSQL, and a restart clears them. The body has no alert text, command line, username, or API key. `prometheus-client` is not installed.

## Cost

`estimated_cost_usd` is `0` unless `SENTINEL_USD_PER_MILLION_TOKENS` is set to a number you choose. The variable is unset by default. This repository does not ship a price for any model, and it does not look one up. Setting the variable means you are supplying the number. A blank value is treated as unset, which is still `0`.

The field is a decimal string. With the variable unset it is the string `0`, not a computed rate.

## Tracing

`opentelemetry-api` 1.44.0 and `opentelemetry-sdk` 1.44.0 are installed. Those versions were the current releases on PyPI on 2026-09-18 (`pip index versions`). The span exporter defaults to off. Tests record spans with the SDK's in-memory exporter. They do not need a collector, and this repository does not start one.

`opentelemetry-exporter-otlp-proto-http` 1.44.0 was also visible on PyPI that day. It is not a dependency. There is no OTLP endpoint, no Jaeger, and no other tracing backend running here.

To print spans locally, set the exporter before the process starts and restart if it is already running. The setting is read at startup.

```bash
SENTINEL_OTEL_EXPORTER=console uvicorn sentinel.api.app:app --host 127.0.0.1 --port 8091
```

`console` uses the SDK `ConsoleSpanExporter` and writes spans to that process's stdout. Nothing else receives them. Unset the variable, or set it to `off`, and no exporter is attached.

`SENTINEL_OTEL_EXPORTER=otlp` is rejected. This build cannot send spans to a collector.
