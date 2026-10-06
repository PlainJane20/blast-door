"""Shared in-process crash/resume driver (mirrors what evals/crash_matrix.py does with real kills)."""
from pathlib import Path

from blast_door.auth import AuthConfig
from blast_door.executor import SimulatedCrash
from blast_door.models import RunStatus
from blast_door.system import System
from blast_door.verifier import Policy

FIXTURE = Path(__file__).resolve().parents[1] / "evals" / "fixtures" / "crash_matrix.yaml"
TOKENS = "alice:alice-secret,bob:bob-secret"


def _raise(point):
    raise SimulatedCrash(point)


def final_picture(system, run_id="cm"):
    state = system.store.load_state(run_id)
    return {"status": state.status.value,
            "steps": {k: v.status.value for k, v in state.steps.items()},
            "env": system.env.snapshot(), "ledger": system.env.ledger_normalized()}


def drive(state_dir, crash_at=None, idempotency=True, clock=None):
    """Run the matrix runbook, optionally crashing once; then resume to the end."""
    import time
    clock = clock or time.time
    auth = AuthConfig.from_string(TOKENS)
    crashed = False
    s = System(state_dir, clock=clock, auth=auth, crash_at=crash_at, crash_handler=_raise,
               idempotency=idempotency)
    rb = s.load_runbook(FIXTURE)
    try:
        state = s.executor.start(rb, "alice", Policy(), run_id="cm")
    except SimulatedCrash:
        crashed, state = True, None
    s.close()
    for _ in range(10):
        s = System(state_dir, clock=clock, auth=auth, idempotency=idempotency,
                   crash_at=None if crashed else crash_at, crash_handler=_raise)
        try:
            if state is None:
                state = s.executor.resume("cm")
            if state.status == RunStatus.awaiting_approval:
                for aid in state.pending_approval_ids():
                    s.approvals.approve(aid, "bob-secret")
                state = s.executor.resume("cm")
            if state.status in (RunStatus.completed, RunStatus.failed, RunStatus.denied):
                pic = final_picture(s)
                ok = s.audit.verify()
                s.close()
                return crashed, pic, ok
        except SimulatedCrash:
            crashed, state = True, None
        s.close()
    raise AssertionError("did not finish")
