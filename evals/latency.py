"""Eval (c): latency of the verify, dry-run planning and checkpoint steps.

CAVEATS (read before quoting a number):
  * In-process, single thread, warm caches, after a warm-up. No network, no
    real infrastructure, no model call.
  * "dry_run_plan" runs against the SIMULATED SQLite environment, so it says
    nothing about a real cluster's dry-run latency.
  * "checkpoint_commit" is one real transaction (state row + checkpoint row +
    hash-chained audit record) on the local disk of this machine with
    PRAGMA synchronous=FULL. A different disk, filesystem or network volume
    will change it a lot. On macOS, SQLite's fsync() does not force the drive
    cache to flush (the fullfsync pragma is off), so a macOS number is
    optimistic for true durability; the crash tests only prove survival of a
    process kill, not of power loss.
  * Numbers come from one machine; the JSON records which.

    python -m evals.latency
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

from runbook_autopilot.models import RunState, StepState
from runbook_autopilot.system import System
from runbook_autopilot.verifier import Policy, Verifier

from .common import ROOT, meta, pct, save

N_VERIFY, N_PLAN, N_CKPT, WARMUP = 5000, 1000, 500, 100


def summarize(samples_ns: list[int]) -> dict:
    ms = sorted(s / 1e6 for s in samples_ns)
    return {"n": len(ms), "p50_ms": round(pct(ms, .50), 4), "p95_ms": round(pct(ms, .95), 4),
            "p99_ms": round(pct(ms, .99), 4), "max_ms": round(ms[-1], 4)}


def timed(fn, n: int, warmup: int = WARMUP) -> list[int]:
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t)
    return out


def run() -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="latency-"))
    s = System(tmp / "sys")
    try:
        ex = s.executor
        plans = [ex._make_plan("r", "s", t, p) for t, p in [
            ("restart_service", {"service": "web"}),
            ("restart_service", {"service": "cache"}),
            ("scale_service", {"service": "auth-svc", "replicas": 3}),
            ("drain_host", {"host": "host-a"}),
            ("get_metrics", {"service": "db"}),
            ("scale_service", {"service": "web", "replicas": -1})]]
        v = Verifier(Policy(), s.registry)
        i = {"n": 0}

        def verify():
            v.verify(plans[i["n"] % len(plans)], 1_800_000_000.0, 0)
            i["n"] += 1

        j = {"n": 0}
        calls = [("restart_service", {"service": "web"}), ("restart_service", {"service": "cache"}),
                 ("drain_host", {"host": "host-a"})]

        def plan():
            t, p = calls[j["n"] % len(calls)]
            ex._make_plan("r", "s", t, p)
            j["n"] += 1

        state = RunState(run_id="lat", runbook_name="lat", requester="alice")
        state.steps["a"] = StepState(step_id="a", tool="restart_service")
        with s.store.txn() as c:
            s.store.create_run(c, state, "{}", "{}")

        def checkpoint():
            state.updated_at = time.time()
            with s.store.txn() as c:
                s.store.save_state(c, state)
                s.store.add_checkpoint(c, state, "a", "bench")
                s.audit.append(c, "bench", {"run_id": "lat", "step_id": "a"})

        out = {
            "verify": summarize(timed(verify, N_VERIFY)),
            "dry_run_plan": summarize(timed(plan, N_PLAN)),
            "checkpoint_commit": summarize(timed(checkpoint, N_CKPT, warmup=20)),
        }
    finally:
        s.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return {"meta": meta(), "caveats": __doc__.split("CAVEATS (read before quoting a number):")[1]
            .split("python -m")[0].strip().splitlines(), **out}


def main() -> int:
    out = run()
    path = save("latency", out)
    for k in ("verify", "dry_run_plan", "checkpoint_commit"):
        print(f"{k:18s} p50 {out[k]['p50_ms']:.4f} ms  p95 {out[k]['p95_ms']:.4f} ms  (n={out[k]['n']})")
    print(f"-> {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
