"""Correlation ids, process metrics, and optional traces.

The correlation id for a run is that run's investigation id. ``GET /metrics``
reads in-process counters. The trace exporter is off unless
``SENTINEL_OTEL_EXPORTER=console``. No collector is started here.
"""
