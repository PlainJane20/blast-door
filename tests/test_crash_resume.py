"""Crash/resume: every (step, phase) kill point must end in the same state as an uninterrupted run."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runbook_autopilot.executor import PHASES

from helpers import FIXTURE, drive

STEPS = ["precheck", "restart-metrics", "scale-auth", "rollout-web", "postcheck"]
WRITES = ["restart-metrics", "scale-auth", "rollout-web"]


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    crashed, pic, audit_ok = drive(tmp_path_factory.mktemp("base"))
    assert not crashed and audit_ok == (True, None)
    assert pic["status"] == "completed" and len(pic["ledger"]) == 3
    return pic


@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("phase", PHASES)
def test_kill_point_resumes_to_identical_state(tmp_path, baseline, step, phase):
    crashed, pic, audit_ok = drive(tmp_path, crash_at=f"{step}:{phase}")
    assert crashed, "the kill point was never reached"
    assert pic == baseline
    keys = [e["idem_key"] for e in pic["ledger"]]
    assert len(keys) == len(set(keys)) == 3          # zero duplicate writes
    assert audit_ok == (True, None)


@pytest.mark.parametrize("step", WRITES)
def test_without_idempotency_a_crash_after_effect_double_executes(tmp_path, step):
    """Negative control: proves the ledger can detect a duplicate write."""
    crashed, pic, _ = drive(tmp_path, crash_at=f"{step}:after_effect", idempotency=False)
    assert crashed
    per_step = [e["step_id"] for e in pic["ledger"]]
    assert per_step.count(step) == 2


def test_crash_after_effect_is_recovered_from_ledger_not_replayed(tmp_path):
    _, _, _ = drive(tmp_path, crash_at="restart-metrics:after_effect")
    from runbook_autopilot.system import System
    s = System(tmp_path)
    events = [r["event"] for r in s.audit.records()]
    assert "effect_found_in_ledger" in events
    assert s.env.get_service_status("metrics-agent")["restarts"] == 1
    s.close()


def run_cli(state_dir, *args, crash=None, extra_env=None):
    env = {**os.environ, "RUNBOOK_OPERATOR_TOKENS": "alice:alice-secret,bob:bob-secret",
           "RUNBOOK_STATE_DIR": str(state_dir)}
    env.pop("RUNBOOK_CRASH_AT", None)
    if crash:
        env["RUNBOOK_CRASH_AT"] = crash
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-m", "runbook_autopilot", *args], env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("crash", ["restart-metrics:after_effect", "scale-auth:before_execute",
                                   "rollout-web:after_plan"])
def test_real_process_kill_then_resume(tmp_path, crash):
    r = run_cli(tmp_path, "run", str(FIXTURE), "--as", "alice", "--token", "alice-secret",
                "--run-id", "cm", crash=crash)
    if r.returncode == 3:   # paused for approval before reaching the kill point
        st = json.loads(run_cli(tmp_path, "status", "cm", "--json").stdout)
        aid = [a["id"] for a in st["approvals"] if a["status"] == "pending"][0]
        assert run_cli(tmp_path, "approve", aid, "--as", "bob", "--token", "bob-secret").returncode == 0
        r = run_cli(tmp_path, "resume", "cm", crash=crash)
    assert r.returncode == 137, r.stdout + r.stderr   # os._exit(137): no cleanup ran
    r = run_cli(tmp_path, "resume", "cm")
    if r.returncode == 3:
        st = json.loads(run_cli(tmp_path, "status", "cm", "--json").stdout)
        aid = [a["id"] for a in st["approvals"] if a["status"] == "pending"][0]
        run_cli(tmp_path, "approve", aid, "--as", "bob", "--token", "bob-secret")
        r = run_cli(tmp_path, "resume", "cm")
    assert r.returncode == 0, r.stdout + r.stderr
    st = json.loads(run_cli(tmp_path, "status", "cm", "--json").stdout)
    assert st["state"]["status"] == "completed" and st["ledger_entries"] == 3
    assert run_cli(tmp_path, "verify-audit").returncode == 0
