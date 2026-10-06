"""Command line: python -m blast_door {run,status,approve,resume,verify-audit}.

Exit codes: 0 completed / ok, 1 failed or denied, 2 usage or validation error,
3 paused awaiting approval.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from pydantic import ValidationError

from .approvals import ApprovalError
from .auth import AuthConfig, AuthError
from .models import RunbookError, RunState, RunStatus
from .system import System
from .verifier import Policy

ENV_TOKEN = "BLAST_DOOR_TOKEN"
ENV_STATE = "BLAST_DOOR_STATE_DIR"
ENV_NO_IDEMPOTENCY = "BLAST_DOOR_UNSAFE_NO_IDEMPOTENCY"  # eval negative control only


def _clock(now_iso: str | None):
    if not now_iso:
        import time
        return time.time
    t = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    ts = (t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t).timestamp()
    return lambda: ts


def _system(args) -> System:
    return System(args.state_dir, clock=_clock(getattr(args, "now", None)),
                  auth=AuthConfig.from_env(),
                  idempotency=not os.environ.get(ENV_NO_IDEMPOTENCY))


def _identity(system: System, name: str | None, token: str | None) -> str:
    """Authenticate `--as name` against its token. No --as means 'anonymous'."""
    if not name:
        return "anonymous"
    who = system.auth.identify(token or os.environ.get(ENV_TOKEN))
    if who != name:
        raise AuthError(f"token belongs to {who!r}, not {name!r}")
    return who


def _describe(system: System, state: RunState) -> list[str]:
    lines = [f"run_id={state.run_id}", f"status={state.status.value}",
             f"writes_executed={state.writes_executed}"]
    for ss in state.steps.values():
        extra = f" ({ss.error_code}: {ss.error})" if ss.error_code else ""
        lines.append(f"  step {ss.step_id}: {ss.status.value}{extra}")
    for aid in state.pending_approval_ids():
        rec = system.store.get_approval(aid)
        ss = next(s for s in state.steps.values() if s.approval_id == aid)
        b = ss.verdict.blast_radius if ss.verdict else None
        lines.append(f"awaiting approval {aid} for step {ss.step_id} "
                     f"(requester={rec.requester}, plan={rec.plan_hash[:12]}, "
                     f"blast={b.count if b else '?'} services {b.services if b else ''}, "
                     f"protected={b.protected if b else []}, status={rec.status.value})")
    return lines


def _exit_for(state: RunState) -> int:
    return {RunStatus.completed: 0, RunStatus.awaiting_approval: 3}.get(state.status, 1)


def cmd_run(args) -> int:
    system = _system(args)
    try:
        runbook = system.load_runbook(args.runbook)
        policy = Policy.from_file(args.policy) if args.policy else Policy()
        requester = _identity(system, args.as_, args.token)
    except (RunbookError, ValidationError, FileNotFoundError, AuthError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    state = system.executor.start(runbook, requester, policy, run_id=args.run_id)
    print("\n".join(_describe(system, state)))
    return _exit_for(state)


def cmd_status(args) -> int:
    system = _system(args)
    state = system.store.load_state(args.run_id)
    if state is None:
        print(f"error: unknown run {args.run_id}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({
            "state": json.loads(state.model_dump_json()),
            "approvals": [json.loads(a.model_dump_json())
                          for a in system.store.approvals_for_run(args.run_id)],
            "ledger_entries": len(system.env.ledger())}, indent=2))
    else:
        print("\n".join(_describe(system, state)))
    return _exit_for(state)


def cmd_approve(args) -> int:
    system = _system(args)
    try:
        who = _identity(system, args.as_, args.token)
        if who == "anonymous":
            raise AuthError("--as <operator> is required to approve")
        rec = system.approvals.approve(args.approval_id, args.token or os.environ.get(ENV_TOKEN))
    except (AuthError, ApprovalError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"approved {rec.id} for run {rec.run_id} step {rec.step_id} by {rec.approver} "
          f"(plan {rec.plan_hash[:12]}, expires_at={rec.expires_at})")
    return 0


def cmd_resume(args) -> int:
    system = _system(args)
    try:
        state = system.executor.resume(args.run_id)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print("\n".join(_describe(system, state)))
    return _exit_for(state)


def cmd_verify_audit(args) -> int:
    system = _system(args)
    ok, bad = system.audit.verify()
    n = len(system.audit.records())
    if ok:
        print(f"audit chain OK ({n} records)")
        return 0
    print(f"audit chain BROKEN at record {bad} of {n}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blast_door",
                                description="Durable runbook agent against a SIMULATED environment")
    p.add_argument("--state-dir", default=os.environ.get(ENV_STATE, ".runbook-state"))
    p.add_argument("--now", help="ISO timestamp to use as 'now' (for change-freeze demos)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="start a run from a runbook YAML")
    r.add_argument("runbook")
    r.add_argument("--policy", help="policy YAML (default: built-in defaults)")
    r.add_argument("--as", dest="as_", help="requester identity (needs its token)")
    r.add_argument("--token", help=f"operator token (or ${ENV_TOKEN})")
    r.add_argument("--run-id")
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("status", help="show a run")
    s.add_argument("run_id")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)

    a = sub.add_parser("approve", help="approve a pending approval as another operator")
    a.add_argument("approval_id")
    a.add_argument("--as", dest="as_", required=True)
    a.add_argument("--token", help=f"operator token (or ${ENV_TOKEN})")
    a.set_defaults(fn=cmd_approve)

    rs = sub.add_parser("resume", help="continue a run from its last checkpoint")
    rs.add_argument("run_id")
    rs.set_defaults(fn=cmd_resume)

    v = sub.add_parser("verify-audit", help="verify the audit hash chain")
    v.set_defaults(fn=cmd_verify_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
