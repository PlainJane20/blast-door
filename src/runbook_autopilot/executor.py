"""Durable executor: a ReAct-style loop where the model only proposes.

Per step: propose -> dry-run -> verify -> (approve) -> re-verify -> execute.
Every transition is one SQLite transaction (state + checkpoint + audit record),
and a write carries an idempotency key that the effects ledger enforces, so a
run killed at any point resumes without double-executing a write.

Crash points (phase boundaries), usable via RUNBOOK_CRASH_AT=<step>:<phase>
("*" matches any step); the process dies with os._exit(137), the equivalent of
kill -9:

  before_plan     intent checkpoint committed, nothing planned yet
  after_plan      plan + dry-run committed
  after_verdict   verdict committed (approval requested, or auto-approved)
  before_execute  approved and re-verified, effect not yet applied
  after_effect    effect applied to the environment, checkpoint NOT yet written
  after_execute   executed checkpoint committed
"""
from __future__ import annotations

import os
import time
import uuid

from . import tracing
from .approvals import ApprovalService
from .audit import AuditLog
from .models import (DryRunResult, Decision, Plan, Runbook, RunState, RunStatus,
                     StepState, StepStatus, TERMINAL_RUN, TERMINAL_STEP, ToolKind, sha256)
from .planner import Planner
from .sim_env import SimEnv, SimError, WriteContext
from .store import RunStore
from .tools import ParamsError, ToolRegistry
from .verifier import Policy, Verifier

ENV_CRASH = "RUNBOOK_CRASH_AT"
PHASES = ("before_plan", "after_plan", "after_verdict", "before_execute",
          "after_effect", "after_execute")


class SimulatedCrash(BaseException):
    """In-process stand-in for a hard kill (BaseException so nothing swallows it)."""


def hard_exit(point: str) -> None:
    os._exit(137)


def idempotency_key(run_id: str, step_id: str, plan_hash: str) -> str:
    return sha256(f"{run_id}|{step_id}|{plan_hash}")[:32]


class Executor:
    def __init__(self, store: RunStore, env: SimEnv, registry: ToolRegistry, audit: AuditLog,
                 approvals: ApprovalService, planner: Planner, clock=time.time,
                 crash_at: str | None = None, crash_handler=hard_exit, idempotency: bool = True):
        self.store, self.env, self.registry = store, env, registry
        self.audit, self.approvals, self.planner = audit, approvals, planner
        self.clock, self.crash_handler, self.idempotency = clock, crash_handler, idempotency
        spec = crash_at if crash_at is not None else os.environ.get(ENV_CRASH, "")
        self._crash_step = self._crash_phase = None
        if spec:
            step, _, phase = spec.rpartition(":")
            if phase not in PHASES or not step:
                raise ValueError(f"bad crash spec {spec!r}; use <step>:<phase>, phase in {PHASES}")
            self._crash_step, self._crash_phase = step, phase

    # -- public API ------------------------------------------------------------
    def start(self, runbook: Runbook, requester: str, policy: Policy,
              run_id: str | None = None) -> RunState:
        run_id = run_id or "run-" + uuid.uuid4().hex[:10]
        now = self.clock()
        state = RunState(run_id=run_id, runbook_name=runbook.name, requester=requester,
                         created_at=now, updated_at=now)
        for s in runbook.steps:
            state.steps[s.id] = StepState(step_id=s.id, tool=s.tool, updated_at=now)
        with tracing.span("run", **{"run.id": run_id, "runbook.name": runbook.name,
                                    "run.requester": requester}) as sp:
            with self.store.txn() as c:
                self.store.create_run(c, state, runbook.model_dump_json(), policy.model_dump_json())
                self.store.add_checkpoint(c, state, None, "run_started")
                self.audit.append(c, "run_started", {
                    "run_id": run_id, "runbook": runbook.name, "requester": requester,
                    "steps": [s.id for s in runbook.steps], "policy_digest": policy.digest()})
            state = self._drive(run_id)
            tracing.set_attrs(sp, **{"run.status": state.status.value})
            return state

    def resume(self, run_id: str) -> RunState:
        state = self.store.load_state(run_id)
        if state is None:
            raise KeyError(f"unknown run {run_id}")
        with tracing.span("resume", **{"run.id": run_id, "run.status_before": state.status.value}) as sp:
            self.audit.append_now("resume", {
                "run_id": run_id, "status_before": state.status.value,
                "steps": {k: v.status.value for k, v in state.steps.items()}})
            state = self._drive(run_id)
            tracing.set_attrs(sp, **{"run.status": state.status.value})
            return state

    # -- internals -------------------------------------------------------------
    def _crash(self, step_id: str, phase: str) -> None:
        if self._crash_phase == phase and self._crash_step in ("*", step_id):
            self.crash_handler(f"{step_id}:{phase}")

    def _commit(self, state: RunState, step_id: str | None, phase: str, events=(), extra=None) -> None:
        state.updated_at = self.clock()
        if step_id and step_id in state.steps:
            state.steps[step_id].updated_at = state.updated_at
        with self.store.txn() as c:
            if extra:
                extra(c)
            self.store.save_state(c, state)
            self.store.add_checkpoint(c, state, step_id, phase)
            for ev, data in events:
                self.audit.append(c, ev, data)

    def _drive(self, run_id: str) -> RunState:
        state = self.store.load_state(run_id)
        rb_json, pol_json = self.store.load_run_blobs(run_id)
        rb = Runbook.model_validate_json(rb_json)
        verifier = Verifier(Policy.model_validate_json(pol_json), self.registry)
        policy = verifier.policy
        while True:
            if state.status in TERMINAL_RUN:
                return state
            if state.status == RunStatus.awaiting_approval:
                state.status = RunStatus.running
            prop = self.planner.next_action(rb, state)
            if prop is None:
                return self._finish(state, rb)
            ss = state.steps.get(prop.step_id)
            if ss is None:
                ss = state.steps[prop.step_id] = StepState(step_id=prop.step_id, tool=prop.tool)
            with tracing.span("step", **{"run.id": run_id, "step.id": ss.step_id,
                                         "step.tool": prop.tool}) as sp:
                outcome = self._process(state, ss, prop, verifier, policy)
                tracing.set_attrs(sp, **{"step.status": ss.status.value,
                                         "step.error_code": ss.error_code})
            if outcome in ("paused", "halt"):
                return state

    def _process(self, state, ss, prop, verifier, policy) -> str | None:
        if ss.status == StepStatus.pending:
            self._commit(state, ss.step_id, "before_plan")
            self._crash(ss.step_id, "before_plan")
            plan = self._make_plan(state.run_id, ss.step_id, prop.tool, prop.params)
            ss.tool, ss.plan_hash, ss.status = prop.tool, plan.plan_hash, StepStatus.planned
            if plan.kind == ToolKind.write and self.idempotency:
                ss.idempotency_key = idempotency_key(state.run_id, ss.step_id, plan.plan_hash)
            dr = plan.dry_run
            self._commit(state, ss.step_id, "after_plan", extra=lambda c: self.store.put_plan(c, plan),
                         events=[("plan_created", {
                             "run_id": state.run_id, "step_id": ss.step_id, "tool": plan.tool,
                             "params": plan.params, "plan_hash": plan.plan_hash,
                             "params_error": plan.params_error,
                             "affected_services": dr.affected_services if dr else []})])
            self._crash(ss.step_id, "after_plan")
        if ss.status == StepStatus.planned:
            r = self._decide(state, ss, verifier, policy)
            if r:
                return r
        if ss.status == StepStatus.awaiting_approval:
            r = self._gate(state, ss, policy)
            if r:
                return r
        if ss.status == StepStatus.approved:
            return self._execute(state, ss, verifier)
        return None

    def _make_plan(self, run_id: str, step_id: str, tool: str, params: dict) -> Plan:
        spec = self.registry.maybe(tool)
        plan = Plan(run_id=run_id, step_id=step_id, tool=tool, params=dict(params))
        if spec is None:
            return plan.seal()
        plan.kind = spec.kind
        try:
            parsed = self.registry.validate_params(tool, params)
        except ParamsError as e:
            plan.params_error = str(e)
            return plan.seal()
        plan.params = parsed.model_dump()
        if spec.kind == ToolKind.write:
            with tracing.span("dry_run", **{"run.id": run_id, "step.id": step_id,
                                            "step.tool": tool}) as sp:
                plan.dry_run = spec.invoke(self.env, parsed, True, None)
                tracing.set_attrs(sp, **{"dry_run.ok": plan.dry_run.ok,
                                         "blast.services": plan.dry_run.affected_services,
                                         "blast.count": len(plan.dry_run.affected_services)})
        else:
            plan.dry_run = DryRunResult(ok=True, tool=tool, params=plan.params)
        return plan.seal()

    def _fail(self, state, ss, code: str, detail: str, run_status=RunStatus.failed, extra_events=()) -> str:
        ss.status, ss.error_code, ss.error = StepStatus.failed, code, detail
        for other in state.steps.values():
            if other is not ss and other.status not in TERMINAL_STEP:
                other.status, other.error_code = StepStatus.skipped, "halted"
        state.status = run_status
        events = [("step_failed", {"run_id": state.run_id, "step_id": ss.step_id,
                                   "code": code, "detail": detail}), *extra_events,
                  ("run_halted", {"run_id": state.run_id, "status": run_status.value})]
        self._commit(state, ss.step_id, "step_failed", events=events)
        return "halt"

    def _verified_plan(self, state, ss):
        """Load the persisted plan and prove its content still matches its hash."""
        plan = self.store.get_plan(state.run_id, ss.step_id)
        if plan is None or plan.plan_hash != ss.plan_hash or plan.compute_hash() != ss.plan_hash:
            self._fail(state, ss, "plan_tamper_detected",
                       "persisted plan does not match the hash it was approved under",
                       extra_events=[("plan_tamper_detected", {
                           "run_id": state.run_id, "step_id": ss.step_id,
                           "expected_hash": ss.plan_hash})])
            return None
        return plan

    def _decide(self, state, ss, verifier: Verifier, policy: Policy) -> str | None:
        plan = self._verified_plan(state, ss)
        if plan is None:
            return "halt"
        with tracing.span("verify", **{"run.id": state.run_id, "step.id": ss.step_id}) as sp:
            verdict = verifier.verify(plan, self.clock(), state.writes_executed)
            b = verdict.blast_radius
            tracing.set_attrs(sp, **{"verdict": verdict.decision.value,
                                     "verdict.codes": verdict.codes,
                                     "blast.count": b.count if b else 0,
                                     "blast.services": b.services if b else []})
        ss.verdict = verdict
        ev = ("verdict", {"run_id": state.run_id, "step_id": ss.step_id, "plan_hash": plan.plan_hash,
                          "decision": verdict.decision.value, "codes": verdict.codes,
                          "blast_services": b.services if b else [],
                          "blast_protected": b.protected if b else []})
        if verdict.decision == Decision.deny:
            return self._fail(state, ss, "verdict_deny", "; ".join(
                f"{r.code}: {r.detail}" for r in verdict.reasons),
                run_status=RunStatus.denied, extra_events=[ev])
        if verdict.decision == Decision.needs_approval:
            ss.status = StepStatus.awaiting_approval
            state.status = RunStatus.awaiting_approval

            def request(c):
                rec = self.approvals.create(c, state.run_id, ss.step_id, plan.plan_hash,
                                            state.requester, policy.approval_ttl_s)
                ss.approval_id = rec.id
            self._commit(state, ss.step_id, "after_verdict", events=[ev], extra=request)
            self._crash(ss.step_id, "after_verdict")
            return "paused"
        ss.status = StepStatus.approved
        self._commit(state, ss.step_id, "after_verdict", events=[ev])
        self._crash(ss.step_id, "after_verdict")
        return None

    def _gate(self, state, ss, policy: Policy) -> str | None:
        plan = self._verified_plan(state, ss)
        if plan is None:
            return "halt"
        with tracing.span("approval_wait", **{"run.id": state.run_id, "step.id": ss.step_id,
                                              "approval.id": ss.approval_id}) as sp:
            outcome, detail, events = "", "", []
            state.updated_at = self.clock()
            with self.store.txn() as c:
                outcome, detail = self.approvals.consume(
                    c, ss.approval_id, state.run_id, ss.step_id, plan.plan_hash)
                if outcome == "ok":
                    ss.status, state.status = StepStatus.approved, RunStatus.running
                    self.audit.append(c, "approval_consumed", {
                        "run_id": state.run_id, "step_id": ss.step_id,
                        "approval_id": ss.approval_id, "approver": detail,
                        "plan_hash": plan.plan_hash})
                elif outcome == "expired":
                    old = ss.approval_id
                    rec = self.approvals.create(c, state.run_id, ss.step_id, plan.plan_hash,
                                                state.requester, policy.approval_ttl_s)
                    ss.approval_id = rec.id
                    self.audit.append(c, "approval_expired", {
                        "run_id": state.run_id, "step_id": ss.step_id,
                        "expired_approval_id": old, "new_approval_id": rec.id})
                if outcome in ("ok", "expired"):
                    ss.updated_at = state.updated_at
                    self.store.save_state(c, state)
                    self.store.add_checkpoint(c, state, ss.step_id,
                                              "after_approval" if outcome == "ok" else "approval_reissued")
            tracing.set_attrs(sp, **{"approval.outcome": outcome})
        if outcome == "ok":
            return None
        if outcome in ("pending", "expired"):
            state.status = RunStatus.awaiting_approval
            return "paused"
        code = {"replayed": "approval_replayed", "invalid": "approval_invalid"}[outcome]
        return self._fail(state, ss, code, detail, run_status=RunStatus.denied)

    def _execute(self, state, ss, verifier: Verifier) -> str | None:
        plan = self._verified_plan(state, ss)
        if plan is None:
            return "halt"
        spec = self.registry.maybe(plan.tool)
        is_write = plan.kind == ToolKind.write
        key = ss.idempotency_key if (is_write and self.idempotency) else None
        already = self.env.ledger_has(key) if key else None
        with tracing.span("execute", **{"run.id": state.run_id, "step.id": ss.step_id,
                                        "step.tool": plan.tool, "step.write": is_write}) as sp:
            if already is not None:
                # The effect landed before the crash but its checkpoint did not.
                result = {"deduplicated": True, "recovered_from_ledger": True,
                          "ledger_seq": already["seq"]}
                self.audit.append_now("effect_found_in_ledger", {
                    "run_id": state.run_id, "step_id": ss.step_id, "idempotency_key": key,
                    "ledger_seq": already["seq"]})
            else:
                # Re-verify against the world as it is NOW (TOCTOU defense).
                fresh = self._make_plan(state.run_id, ss.step_id, plan.tool, plan.params)
                if fresh.plan_hash != plan.plan_hash:
                    return self._fail(state, ss, "plan_drift",
                                      "environment changed since the plan was made; re-plan required",
                                      run_status=RunStatus.denied,
                                      extra_events=[("plan_drift", {
                                          "run_id": state.run_id, "step_id": ss.step_id,
                                          "planned": plan.plan_hash, "now": fresh.plan_hash})])
                v = verifier.verify(fresh, self.clock(), state.writes_executed)
                if v.decision == Decision.deny or (v.decision == Decision.needs_approval
                                                   and not ss.approval_id):
                    ss.verdict = v
                    return self._fail(state, ss, "reverify_denied", "; ".join(
                        f"{r.code}: {r.detail}" for r in v.reasons) or v.decision.value,
                        run_status=RunStatus.denied,
                        extra_events=[("reverify_denied", {
                            "run_id": state.run_id, "step_id": ss.step_id, "codes": v.codes})])
                self._commit(state, ss.step_id, "before_execute", events=[(
                    "execute_started", {"run_id": state.run_id, "step_id": ss.step_id,
                                        "idempotency_key": key, "plan_hash": plan.plan_hash})])
                self._crash(ss.step_id, "before_execute")
                parsed = self.registry.validate_params(plan.tool, plan.params)
                ctx = WriteContext(state.run_id, ss.step_id, key) if is_write else None
                try:
                    raw = spec.invoke(self.env, parsed, False, ctx)
                except (SimError, ParamsError) as e:
                    return self._fail(state, ss, "execution_error", str(e))
                result = raw if isinstance(raw, dict) else {"value": raw}
            self._crash(ss.step_id, "after_effect")
            ss.status, ss.result = StepStatus.executed, result
            if is_write:
                state.writes_executed += 1
            tracing.set_attrs(sp, **{"execute.deduplicated": bool(result.get("deduplicated"))})
        self._commit(state, ss.step_id, "after_execute", events=[(
            "step_executed", {"run_id": state.run_id, "step_id": ss.step_id, "tool": plan.tool,
                              "write": is_write, "idempotency_key": key,
                              "recovered": bool(already)})])
        self._crash(ss.step_id, "after_execute")
        return None

    def _finish(self, state: RunState, rb: Runbook) -> RunState:
        for s in rb.steps:
            ss = state.steps[s.id]
            if ss.status not in TERMINAL_STEP:
                ss.status, ss.error_code = StepStatus.skipped, "not_proposed"
        state.status = RunStatus.completed
        self._commit(state, None, "run_completed", events=[("run_completed", {
            "run_id": state.run_id, "executed": sorted(
                k for k, v in state.steps.items() if v.status == StepStatus.executed),
            "writes": state.writes_executed})])
        return state
