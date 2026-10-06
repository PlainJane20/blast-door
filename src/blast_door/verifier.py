"""Deterministic verifier. No LLM, no randomness, no I/O.

Given a plan (with its dry-run), the policy, the current time and the number of
writes already executed in this run, it returns a Verdict: allow, needs_approval
or deny, with every reason that applied. Same inputs, same output.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import BlastRadius, Decision, Plan, Reason, ToolKind, Verdict, canonical
from .tools import ToolRegistry


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class FreezeWindow(BaseModel):
    start: datetime
    end: datetime
    reason: str = "change freeze"

    @field_validator("start", "end")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _utc(v)

    def active(self, now: float) -> bool:
        t = datetime.fromtimestamp(now, tz=timezone.utc)
        return self.start <= t < self.end


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowlisted_tools: list[str] = Field(default_factory=lambda: [
        "list_services", "get_service_status", "get_metrics",
        "restart_service", "rollout_restart", "scale_service", "drain_host"])
    max_affected_services: int = Field(default=5, ge=0)
    approval_threshold_services: int = Field(default=3, ge=0)
    protected_policy: Literal["needs_approval", "deny"] = "needs_approval"
    deny_scale_to_zero: bool = True
    change_freeze: list[FreezeWindow] = Field(default_factory=list)
    max_writes_per_run: int = Field(default=5, ge=0)
    approval_ttl_s: int = Field(default=900, ge=1)

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        return cls.model_validate(yaml.safe_load(text) or {})

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_yaml(Path(path).read_text())

    def digest(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode="json")).encode()).hexdigest()[:16]


class Verifier:
    def __init__(self, policy: Policy, registry: ToolRegistry):
        self.policy = policy
        self.registry = registry

    def blast_radius(self, plan: Plan) -> BlastRadius:
        spec = self.registry.maybe(plan.tool)
        if spec is None or plan.dry_run is None or not plan.dry_run.ok or plan.params_error:
            return BlastRadius()
        params = self.registry.validate_params(plan.tool, plan.params)
        return spec.blast(params, plan.dry_run)

    def verify(self, plan: Plan, now: float, writes_so_far: int) -> Verdict:
        p = self.policy
        deny: list[Reason] = []
        ask: list[Reason] = []
        spec = self.registry.maybe(plan.tool)
        if spec is None:
            deny.append(Reason(code="tool_unknown", detail=f"tool {plan.tool!r} is not registered"))
            return Verdict(decision=Decision.deny, reasons=deny)
        if plan.tool not in p.allowlisted_tools:
            deny.append(Reason(code="tool_not_allowlisted",
                               detail=f"tool {plan.tool!r} is not on the allowlist"))
        if plan.params_error:
            deny.append(Reason(code="params_invalid", detail=plan.params_error))
            return Verdict(decision=Decision.deny, reasons=deny)
        if spec.kind == ToolKind.read:
            return Verdict(decision=Decision.deny if deny else Decision.allow,
                           reasons=deny, blast_radius=BlastRadius())

        # write tools from here on
        dr = plan.dry_run
        if dr is None or not dr.ok:
            deny.append(Reason(code="dry_run_failed",
                               detail=(dr.error if dr else "no dry-run was produced") or "dry-run failed"))
            return Verdict(decision=Decision.deny, reasons=deny)
        blast = self.blast_radius(plan)
        for w in p.change_freeze:
            if w.active(now):
                deny.append(Reason(code="change_freeze", detail=w.reason))
        if writes_so_far + 1 > p.max_writes_per_run:
            deny.append(Reason(code="max_writes_exceeded",
                               detail=f"{writes_so_far + 1} writes > limit {p.max_writes_per_run}"))
        if blast.count > p.max_affected_services:
            deny.append(Reason(code="blast_radius_exceeded",
                               detail=f"{blast.count} affected services > limit {p.max_affected_services}"))
        if "scale_to_zero" in blast.flags and p.deny_scale_to_zero:
            deny.append(Reason(code="scale_to_zero", detail="scaling a service to zero replicas"))
        if blast.protected:
            r = Reason(code="protected_resource",
                       detail=f"touches protected: {', '.join(blast.protected)}")
            (deny if p.protected_policy == "deny" else ask).append(r)
        if blast.count > p.approval_threshold_services:
            ask.append(Reason(code="blast_radius_over_threshold",
                              detail=f"{blast.count} affected services > approval threshold "
                                     f"{p.approval_threshold_services}"))
        if deny:
            return Verdict(decision=Decision.deny, reasons=deny + ask, blast_radius=blast)
        if ask:
            return Verdict(decision=Decision.needs_approval, reasons=ask, blast_radius=blast)
        return Verdict(decision=Decision.allow,
                       reasons=[Reason(code="within_policy", detail="within every policy limit")],
                       blast_radius=blast)
