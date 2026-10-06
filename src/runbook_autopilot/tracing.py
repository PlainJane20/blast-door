"""OpenTelemetry spans. A no-op unless an SDK TracerProvider is configured.

Only opentelemetry-api is a runtime dependency; the SDK is used by tests with
an in-memory exporter. With no provider configured, every span is a no-op.
"""
from __future__ import annotations

from contextlib import contextmanager

from opentelemetry import trace

_provider = None


def configure(provider) -> None:
    """Use `provider` for this package's spans (None restores the global default)."""
    global _provider
    _provider = provider


def _tracer():
    if _provider is not None:
        return trace.get_tracer("runbook_autopilot", tracer_provider=_provider)
    return trace.get_tracer("runbook_autopilot")


def _clean(v):
    if isinstance(v, (str, bool, int, float)):
        return v
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return str(v)


@contextmanager
def span(name: str, **attrs):
    with _tracer().start_as_current_span(f"runbook.{name}") as s:
        for k, v in attrs.items():
            if v is not None:
                s.set_attribute(k, _clean(v))
        yield s


def set_attrs(s, **attrs) -> None:
    for k, v in attrs.items():
        if v is not None:
            s.set_attribute(k, _clean(v))
