import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from blast_door import tracing

from conftest import approve_pending, runbook, start


@pytest.fixture
def spans():
    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    tracing.configure(provider)
    yield exp
    tracing.configure(None)


def by_name(exp, name):
    return [s for s in exp.get_finished_spans() if s.name == f"runbook.{name}"]


def test_all_span_kinds_emitted(system, spans):
    rb = runbook(("scale", "scale_service", {"service": "auth-svc", "replicas": 3}))
    start(system, rb)
    approve_pending(system)
    system.executor.resume("r1")
    names = {s.name for s in spans.get_finished_spans()}
    assert {"runbook.run", "runbook.step", "runbook.dry_run", "runbook.verify",
            "runbook.approval_wait", "runbook.execute", "runbook.resume"} <= names


def test_verify_span_has_verdict_and_blast_radius(system, spans):
    start(system, runbook(("scale", "scale_service", {"service": "auth-svc", "replicas": 3})))
    [v] = by_name(spans, "verify")
    assert v.attributes["verdict"] == "needs_approval"
    assert v.attributes["blast.count"] == 3
    assert set(v.attributes["blast.services"]) == {"api", "auth-svc", "web"}
    assert v.attributes["run.id"] == "r1" and v.attributes["step.id"] == "scale"


def test_run_span_carries_run_id_and_final_status(system, spans):
    start(system, runbook(("go", "restart_service", {"service": "web"})))
    [r] = by_name(spans, "run")
    assert r.attributes["run.id"] == "r1" and r.attributes["run.status"] == "completed"


def test_step_spans_are_children_of_run(system, spans):
    start(system, runbook(("go", "restart_service", {"service": "web"})))
    [run] = by_name(spans, "run")
    [step] = by_name(spans, "step")
    assert step.parent.span_id == run.context.span_id
    assert step.attributes["step.status"] == "executed"


def test_denied_step_records_deny_verdict(system, spans):
    start(system, runbook(("bad", "drain_host", {"host": "host-a"})))
    [v] = by_name(spans, "verify")
    assert v.attributes["verdict"] == "deny"
    assert "blast_radius_exceeded" in v.attributes["verdict.codes"]


def test_tracing_is_noop_by_default(system):
    tracing.configure(None)
    with tracing.span("x", a=1) as s:
        assert not s.is_recording()
    assert start(system, runbook(("go", "restart_service", {"service": "web"}))).status.value == "completed"
