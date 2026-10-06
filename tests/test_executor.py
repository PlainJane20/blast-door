import sqlite3

import pytest

from blast_door.executor import Executor, PHASES
from blast_door.models import Proposal, RunStatus, StepStatus
from blast_door.planner import RuleBasedPlanner, ScriptedPlanner
from blast_door.verifier import Policy

from conftest import approve_pending, runbook, start


def test_safe_run_completes_and_writes_once(system):
    rb = runbook(("pre", "get_service_status", {"service": "web"}),
                 ("go", "restart_service", {"service": "web"}, ["pre"]))
    state = start(system, rb)
    assert state.status == RunStatus.completed and state.writes_executed == 1
    assert [e["step_id"] for e in system.env.ledger()] == ["go"]
    assert state.steps["pre"].result["name"] == "web"


def test_steps_follow_dependencies_not_listing_order(system):
    rb = runbook(("second", "get_service_status", {"service": "web"}, ["first"]),
                 ("first", "list_services", {}))
    start(system, rb)
    order = [r["data"]["step_id"] for r in system.audit.records() if r["event"] == "step_executed"]
    assert order == ["first", "second"]


def test_dry_run_is_recorded_before_any_write(system):
    rb = runbook(("go", "restart_service", {"service": "web"}))
    start(system, rb)
    events = [r["event"] for r in system.audit.records()]
    assert events.index("plan_created") < events.index("verdict") < events.index("step_executed")
    plan = system.store.get_plan("r1", "go")
    assert plan.dry_run.affected_services == ["web"]


def test_needs_approval_pauses_without_writing(system):
    state = start(system, runbook(("p", "restart_service", {"service": "db"})),
                  Policy(max_affected_services=99))
    assert state.status == RunStatus.awaiting_approval
    assert state.steps["p"].status == StepStatus.awaiting_approval and system.env.ledger() == []


def test_denied_run_halts_and_skips_the_rest(system):
    rb = runbook(("bad", "drain_host", {"host": "host-a"}), ("after", "list_services", {}, ["bad"]))
    state = start(system, rb)
    assert state.status == RunStatus.denied and system.env.ledger() == []
    assert state.steps["bad"].status == StepStatus.failed
    assert state.steps["after"].status == StepStatus.skipped


def test_max_writes_enforced_mid_run(system):
    rb = runbook(("a", "restart_service", {"service": "web"}),
                 ("b", "restart_service", {"service": "metrics-agent"}, ["a"]),
                 ("c", "restart_service", {"service": "batch-report"}, ["b"]))
    state = start(system, rb, Policy(max_writes_per_run=2))
    assert state.status == RunStatus.denied
    assert state.steps["c"].verdict.codes[0] == "max_writes_exceeded" and len(system.env.ledger()) == 2


def test_tampered_plan_after_approval_is_blocked(system):
    rb = runbook(("p", "scale_service", {"service": "auth-svc", "replicas": 3}))
    start(system, rb)
    approve_pending(system)
    plan = system.store.get_plan("r1", "p")
    plan.params["replicas"] = 0   # attacker edits the stored plan, keeps the stored hash
    system.store.conn.execute("UPDATE plans SET plan_json=? WHERE step_id='p'", (plan.model_dump_json(),))
    state = system.executor.resume("r1")
    assert state.status == RunStatus.failed and state.steps["p"].error_code == "plan_tamper_detected"
    assert system.env.ledger() == []
    assert any(r["event"] == "plan_tamper_detected" for r in system.audit.records())


def test_environment_drift_between_plan_and_execute_is_blocked(system):
    rb = runbook(("p", "scale_service", {"service": "auth-svc", "replicas": 3}))
    start(system, rb)
    approve_pending(system)
    system.env.add_dependency("metrics-agent", "auth-svc")   # blast radius grows after approval
    state = system.executor.resume("r1")
    assert state.status == RunStatus.denied and state.steps["p"].error_code == "plan_drift"
    assert system.env.ledger() == []


def test_freeze_starting_after_approval_blocks_execution(system, clock):
    from datetime import datetime, timezone
    from blast_door.verifier import FreezeWindow
    policy = Policy(change_freeze=[FreezeWindow(
        start=datetime.fromtimestamp(clock.t + 600, tz=timezone.utc),
        end=datetime.fromtimestamp(clock.t + 7200, tz=timezone.utc))])
    start(system, runbook(("p", "scale_service", {"service": "auth-svc", "replicas": 3})), policy)
    approve_pending(system)
    clock.advance(700)   # inside the freeze, still inside the 900 s approval TTL
    state = system.executor.resume("r1")
    assert state.status == RunStatus.denied
    assert state.steps["p"].error_code == "reverify_denied"
    assert state.steps["p"].verdict.codes[0] == "change_freeze"
    assert system.env.ledger() == []


def test_scripted_planner_cannot_force_destructive_step(make_system):
    s = make_system("scripted", planner=ScriptedPlanner([
        Proposal(step_id="bad", tool="drain_host", params={"host": "host-a"})]))
    state = start(s, runbook(("placeholder", "list_services", {})))
    assert state.status == RunStatus.denied and s.env.ledger() == []
    assert state.steps["bad"].verdict.decision.value == "deny"


@pytest.mark.parametrize("tool,params,code", [
    ("delete_service", {"service": "web"}, "tool_unknown"),
    ("exec_shell", {"cmd": "rm -rf /"}, "tool_unknown"),
    ("scale_service", {"service": "web", "replicas": -1}, "params_invalid"),
    ("scale_service", {"service": "web", "replicas": 0}, "scale_to_zero"),
    ("restart_service", {"service": "ghost"}, "dry_run_failed"),
])
def test_scripted_unsafe_proposals_overridden(make_system, tool, params, code):
    s = make_system("scripted", planner=ScriptedPlanner([Proposal(step_id="bad", tool=tool, params=params)]))
    state = start(s, runbook(("placeholder", "list_services", {})))
    assert state.status == RunStatus.denied and s.env.ledger() == []
    assert code in state.steps["bad"].verdict.codes


def test_scripted_planner_safe_proposal_still_runs(make_system):
    s = make_system("scripted", planner=ScriptedPlanner([
        Proposal(step_id="ok", tool="restart_service", params={"service": "web"})]))
    state = start(s, runbook(("placeholder", "list_services", {})))
    assert state.status == RunStatus.completed and len(s.env.ledger()) == 1


def test_resume_of_finished_run_is_a_noop(system):
    start(system, runbook(("go", "restart_service", {"service": "web"})))
    before = system.env.ledger()
    state = system.executor.resume("r1")
    assert state.status == RunStatus.completed and system.env.ledger() == before


def test_resume_unknown_run(system):
    with pytest.raises(KeyError):
        system.executor.resume("nope")


def test_bad_crash_spec_rejected(system):
    with pytest.raises(ValueError):
        Executor(system.store, system.env, system.registry, system.audit, system.approvals,
                 RuleBasedPlanner(), crash_at="web:nonsense")


def test_checkpoints_written_at_every_boundary(system):
    start(system, runbook(("go", "restart_service", {"service": "web"})))
    phases = [r[0] for r in system.store.conn.execute(
        "SELECT phase FROM checkpoints WHERE step_id='go' ORDER BY seq")]
    assert phases == ["before_plan", "after_plan", "after_verdict", "before_execute", "after_execute"]


def test_phases_constant_is_documented_set():
    assert PHASES == ("before_plan", "after_plan", "after_verdict", "before_execute",
                      "after_effect", "after_execute")


def test_state_transition_is_atomic_with_its_audit_record(system):
    start(system, runbook(("go", "restart_service", {"service": "web"})))
    n_exec_events = sum(1 for r in system.audit.records() if r["event"] == "step_executed")
    assert n_exec_events == 1
