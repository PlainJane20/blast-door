"""Eval (a): CRASH MATRIX.

For every step of the matrix runbook and every phase boundary, run the real CLI
in a subprocess, kill it with os._exit(137) at that point (the equivalent of
kill -9: no cleanup, no flush), resume with a fresh process, approve as a
second operator where the run pauses, and compare the final environment state,
effects ledger and step statuses with an uninterrupted run. Pass requires
equality AND zero duplicate writes AND a verifying audit chain.

Also runs a negative control with idempotency keys switched off, to show the
ledger really can detect a double execution.

    python -m evals.crash_matrix
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from runbook_autopilot.executor import PHASES
from runbook_autopilot.models import Runbook, ToolKind
from runbook_autopilot.sim_env import SimEnv
from runbook_autopilot.tools import ToolRegistry

from .common import ROOT, meta, save

FIXTURE = ROOT / "evals" / "fixtures" / "crash_matrix.yaml"
TOKENS = "alice:alice-secret,bob:bob-secret"
RUN_ID = "cm"
ENV_NO_IDEM = "RUNBOOK_UNSAFE_NO_IDEMPOTENCY"


def cli(state_dir: Path, *args: str, crash: str | None = None, no_idem: bool = False):
    env = {**os.environ, "RUNBOOK_OPERATOR_TOKENS": TOKENS, "RUNBOOK_STATE_DIR": str(state_dir)}
    env.pop("RUNBOOK_CRASH_AT", None)
    env.pop(ENV_NO_IDEM, None)
    if crash:
        env["RUNBOOK_CRASH_AT"] = crash
    if no_idem:
        env[ENV_NO_IDEM] = "1"
    return subprocess.run([sys.executable, "-m", "runbook_autopilot", *args], env=env,
                          capture_output=True, text=True, timeout=180, cwd=ROOT)


def pending_approvals(state_dir: Path) -> list[str]:
    st = json.loads(cli(state_dir, "status", RUN_ID, "--json").stdout)
    return [a["id"] for a in st["approvals"] if a["status"] == "pending"]


def drive(state_dir: Path, crash: str | None, no_idem: bool = False) -> dict:
    """Run to completion through the CLI, crashing at most once at `crash`."""
    crashed, invocations = False, 0
    r = cli(state_dir, "run", str(FIXTURE), "--as", "alice", "--token", "alice-secret",
            "--run-id", RUN_ID, crash=crash, no_idem=no_idem)
    invocations += 1
    for _ in range(12):
        active_crash = None if crashed else crash
        if r.returncode == 137:
            crashed = True
            r = cli(state_dir, "resume", RUN_ID, no_idem=no_idem)
            invocations += 1
        elif r.returncode == 3:
            for aid in pending_approvals(state_dir):
                a = cli(state_dir, "approve", aid, "--as", "bob", "--token", "bob-secret")
                invocations += 1
                if a.returncode != 0:
                    return {"crashed": crashed, "error": f"approve failed: {a.stderr.strip()}"}
            r = cli(state_dir, "resume", RUN_ID, crash=active_crash, no_idem=no_idem)
            invocations += 1
        else:
            break
    audit_ok = cli(state_dir, "verify-audit").returncode == 0
    env = SimEnv(state_dir / "env.db")
    try:
        picture = {"snapshot": env.snapshot(), "ledger": env.ledger_normalized()}
    finally:
        env.close()
    st = json.loads(cli(state_dir, "status", RUN_ID, "--json").stdout)["state"]
    picture["run_status"] = st["status"]
    picture["steps"] = {k: v["status"] for k, v in st["steps"].items()}
    return {"crashed": crashed, "final_exit": r.returncode, "audit_ok": audit_ok,
            "picture": picture, "invocations": invocations}


def duplicates(ledger: list[dict]) -> int:
    seen: dict[str, int] = {}
    for e in ledger:
        seen[e["step_id"]] = seen.get(e["step_id"], 0) + 1
    return sum(n - 1 for n in seen.values() if n > 1)


def run(workers: int = 4) -> dict:
    rb, reg = Runbook.from_file(FIXTURE), ToolRegistry.default()
    steps = [s.id for s in rb.steps]
    write_steps = [s.id for s in rb.steps if reg.maybe(s.tool).kind == ToolKind.write]
    tmp = Path(tempfile.mkdtemp(prefix="crash-matrix-"))
    try:
        base = drive(tmp / "baseline", None)
        assert base["final_exit"] == 0 and not base["crashed"], base
        expected = base["picture"]
        points = [(s, p) for s in steps for p in PHASES]

        def one(pt):
            step, phase = pt
            res = drive(tmp / f"{step}__{phase}", f"{step}:{phase}")
            ledger = res.get("picture", {}).get("ledger", [])
            ok = (res.get("crashed") is True and res.get("picture") == expected
                  and res.get("audit_ok") is True and res.get("final_exit") == 0
                  and duplicates(ledger) == 0 and len(ledger) == len(write_steps))
            why = ""
            if not res.get("crashed"):
                why = "kill point never reached"
            elif res.get("picture") != expected:
                why = "final state or ledger differs from uninterrupted run"
            elif duplicates(ledger):
                why = "duplicate write"
            elif not res.get("audit_ok"):
                why = "audit chain failed verification"
            elif "error" in res:
                why = res["error"]
            return {"step": step, "phase": phase, "killed": bool(res.get("crashed")), "passed": ok,
                    "duplicate_writes": duplicates(ledger), "ledger_entries": len(ledger),
                    "cli_invocations": res.get("invocations"), "failure": why}

        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(one, points))

        # Negative control: idempotency keys off, kill right after the effect lands.
        control = []
        for step in write_steps:
            res = drive(tmp / f"control__{step}", f"{step}:after_effect", no_idem=True)
            ledger = res["picture"]["ledger"]
            control.append({"step": step, "phase": "after_effect", "duplicate_writes": duplicates(ledger),
                            "detected": duplicates(ledger) > 0})
        no_idem_base = drive(tmp / "control_baseline", None, no_idem=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(r["passed"] for r in results)
    by_phase = {p: {"points": sum(1 for r in results if r["phase"] == p),
                    "passed": sum(1 for r in results if r["phase"] == p and r["passed"])} for p in PHASES}
    by_step = {s: {"points": sum(1 for r in results if r["step"] == s),
                   "passed": sum(1 for r in results if r["step"] == s and r["passed"])} for s in steps}
    return {
        "meta": meta(),
        "description": "Kill the real CLI process (os._exit(137)) at every step x phase boundary, "
                       "resume, compare with an uninterrupted run.",
        "runbook": str(FIXTURE.relative_to(ROOT)),
        "steps": steps, "phases": list(PHASES), "write_steps": write_steps,
        "kill_points": len(results), "passed": passed,
        "pass_rate": passed / len(results),
        "total_duplicate_writes": sum(r["duplicate_writes"] for r in results),
        "all_kill_points_reached": all(r["killed"] for r in results),
        "by_phase": by_phase, "by_step": by_step,
        "failures": [r for r in results if not r["passed"]],
        "points": results,
        "negative_control_idempotency_off": {
            "description": "Same kill at after_effect with idempotency keys disabled; "
                           "the ledger must show the duplicate, proving the detector works.",
            "uninterrupted_run_duplicates": duplicates(no_idem_base["picture"]["ledger"]),
            "cases": control, "detected": sum(c["detected"] for c in control), "of": len(control)},
    }


def main() -> int:
    out = run()
    path = save("crash_matrix", out)
    print(f"crash matrix: {out['passed']}/{out['kill_points']} kill points passed "
          f"({out['pass_rate']:.1%}), duplicate writes: {out['total_duplicate_writes']}, "
          f"control detected {out['negative_control_idempotency_off']['detected']}/"
          f"{out['negative_control_idempotency_off']['of']}  -> {path.relative_to(ROOT)}")
    return 0 if out["passed"] == out["kill_points"] else 1


if __name__ == "__main__":
    sys.exit(main())
