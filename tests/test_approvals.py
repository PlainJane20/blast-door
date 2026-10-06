import pytest

from blast_door.approvals import ApprovalError
from blast_door.auth import AuthConfig, AuthError
from blast_door.models import ApprovalStatus, RunStatus, StepStatus
from blast_door.verifier import Policy

from conftest import approve_pending, runbook, start

PROTECTED = ("scale", "scale_service", {"service": "auth-svc", "replicas": 3})


def paused(system, **kw):
    state = start(system, runbook(PROTECTED), **kw)
    assert state.status == RunStatus.awaiting_approval
    return state, state.steps["scale"].approval_id


# -- auth --------------------------------------------------------------------
def test_auth_parses_and_identifies():
    a = AuthConfig.from_string("alice:ta, bob:tb")
    assert a.identify("ta") == "alice" and a.identify("tb") == "bob"


@pytest.mark.parametrize("raw", ["alice", "alice:", ":tok", "alice:ta,bob"])
def test_malformed_tokens_rejected(raw):
    with pytest.raises(ValueError):
        AuthConfig.from_string(raw)


@pytest.mark.parametrize("tok", [None, "", "nope"])
def test_unknown_or_missing_token_rejected(tok):
    with pytest.raises(AuthError):
        AuthConfig.from_string("alice:ta").identify(tok)


def test_empty_config_fails_closed():
    with pytest.raises(AuthError):
        AuthConfig.from_string("").identify("anything")


# -- approvals ---------------------------------------------------------------
def test_other_operator_can_approve_and_run_completes(system):
    _, aid = paused(system)
    rec = system.approvals.approve(aid, "bob-secret")
    assert rec.approver == "bob" and rec.status == ApprovalStatus.approved
    assert system.executor.resume("r1").status == RunStatus.completed
    assert len(system.env.ledger()) == 1


def test_self_approval_is_rejected_and_audited(system):
    _, aid = paused(system)
    with pytest.raises(ApprovalError) as e:
        system.approvals.approve(aid, "alice-secret")
    assert e.value.code == "self_approval"
    assert system.executor.resume("r1").status == RunStatus.awaiting_approval
    assert system.env.ledger() == []
    assert any(r["event"] == "approval_rejected" and r["data"]["code"] == "self_approval"
               for r in system.audit.records())


def test_unauthenticated_approval_rejected(system):
    _, aid = paused(system)
    for tok in (None, "wrong"):
        with pytest.raises(ApprovalError) as e:
            system.approvals.approve(aid, tok)
        assert e.value.code == "unauthenticated"
    assert system.store.get_approval(aid).status == ApprovalStatus.pending


def test_no_tokens_configured_means_nobody_can_approve(make_system):
    s = make_system("closed", auth=AuthConfig())
    state = start(s, runbook(PROTECTED))
    with pytest.raises(ApprovalError):
        s.approvals.approve(state.steps["scale"].approval_id, "alice-secret")


def test_approving_twice_is_rejected(system):
    _, aid = paused(system)
    system.approvals.approve(aid, "bob-secret")
    with pytest.raises(ApprovalError) as e:
        system.approvals.approve(aid, "carol-secret")
    assert e.value.code == "not_pending"


def test_unknown_approval_id(system):
    with pytest.raises(ApprovalError) as e:
        system.approvals.approve("ap-nope", "bob-secret")
    assert e.value.code == "not_found"


def test_approval_is_consumed_exactly_once(system):
    _, aid = paused(system)
    system.approvals.approve(aid, "bob-secret")
    system.executor.resume("r1")
    rec = system.store.get_approval(aid)
    assert rec.status == ApprovalStatus.consumed and rec.consumed_at is not None
    with system.store.txn() as c:
        out, _ = system.approvals.consume(c, aid, "r1", "scale", rec.plan_hash)
    assert out == "replayed"


def test_cannot_approve_after_expiry(system, clock):
    _, aid = paused(system)
    clock.advance(Policy().approval_ttl_s + 1)
    with pytest.raises(ApprovalError) as e:
        system.approvals.approve(aid, "bob-secret")
    assert e.value.code == "expired"


def test_approved_but_expired_before_use_is_not_executed_and_is_reissued(system, clock):
    _, aid = paused(system)
    system.approvals.approve(aid, "bob-secret")
    clock.advance(Policy().approval_ttl_s + 1)
    state = system.executor.resume("r1")
    assert state.status == RunStatus.awaiting_approval and system.env.ledger() == []
    new_id = state.steps["scale"].approval_id
    assert new_id != aid and system.store.get_approval(aid).status == ApprovalStatus.expired
    system.approvals.approve(new_id, "bob-secret")
    assert system.executor.resume("r1").status == RunStatus.completed


def test_approval_bound_to_plan_hash(system):
    _, aid = paused(system)
    system.approvals.approve(aid, "bob-secret")
    system.store.conn.execute("UPDATE approvals SET plan_hash='deadbeef' WHERE id=?", (aid,))
    state = system.executor.resume("r1")
    assert state.status == RunStatus.denied
    assert state.steps["scale"].error_code == "approval_invalid" and system.env.ledger() == []


def test_approval_for_another_step_cannot_be_replayed(system):
    rb = runbook(PROTECTED, ("scale2", "scale_service", {"service": "auth-svc", "replicas": 4}, ["scale"]))
    start(system, rb)
    approve_pending(system)
    system.executor.resume("r1")           # scale executes, scale2 now awaits its own approval
    state = system.store.load_state("r1")
    first = state.steps["scale"].approval_id
    second = state.steps["scale2"]
    assert second.status == StepStatus.awaiting_approval and second.approval_id != first
    second.approval_id = first             # attacker re-points scale2 at the spent approval
    with system.store.txn() as c:
        system.store.save_state(c, state)
    out = system.executor.resume("r1")
    assert out.status == RunStatus.denied
    assert out.steps["scale2"].error_code in ("approval_invalid", "approval_replayed")
    assert len(system.env.ledger()) == 1


def test_approval_requested_is_bound_to_requester_identity(system):
    state, aid = paused(system, requester="carol")
    assert system.store.get_approval(aid).requester == "carol"
    with pytest.raises(ApprovalError) as e:
        system.approvals.approve(aid, "carol-secret")
    assert e.value.code == "self_approval"
