"""OpenTelemetry traces. The exporter defaults to off.

``console`` prints spans to this process's stdout via the SDK's
``ConsoleSpanExporter``. Nothing in this repository receives those spans.
There is no collector. Tests pass an in-memory exporter and do not open a
socket.
"""

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, SpanExporter
from opentelemetry.trace import Tracer

_SERVICE = Resource({"service.name": "sentinel-agent"})

_provider = TracerProvider(resource=_SERVICE)
_mode = "off"


def configure_tracing(exporter: str) -> None:
    """Install a provider. ``off`` adds no exporter. ``console`` prints spans."""
    global _provider, _mode
    provider = TracerProvider(resource=_SERVICE)
    if exporter == "console":
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        _mode = "console"
    else:
        _mode = "off"
    _provider = provider


def install_span_exporter(exporter: SpanExporter) -> None:
    """Send spans to ``exporter``. Tests use this. It does not dial a collector."""
    global _provider, _mode
    provider = TracerProvider(resource=_SERVICE)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    _provider = provider
    _mode = "test"


def get_tracer() -> Tracer:
    return _provider.get_tracer("sentinel.investigation")


def tracing_mode() -> str:
    """``off``, ``console``, or ``test``. ``off`` means no exporter is attached."""
    return _mode
