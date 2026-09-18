"""Observability package.

Tracing, metrics, cost tracking, and structured correlation logs are milestone
9. OpenTelemetry is intentionally not a dependency until that work has a
default-off exporter and tests. Do not log secrets, command lines, or provider
payloads when instrumentation is added.

``GET /metrics`` is reserved and returns 501.
"""
