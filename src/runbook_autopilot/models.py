"""Typed schemas: runbooks, plans, dry-run results, verdicts, approvals, run state.

A runbook is a typed state machine: each step has a status that only moves
forward (pending -> planned -> awaiting_approval/approved -> executed, or
failed/skipped). Validation rejects duplicate ids, unknown dependencies and
cycles at load time; unknown tools are rejected against a registry.
"""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class RunbookError(ValueError):
    """Raised for an invalid runbook. The message starts with a stable code."""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class StepStatus(str, Enum):
    pending = "pending"
    planned = "planned"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    executed = "executed"
    failed = "failed"
    skipped = "skipped"


TERMINAL_STEP = {StepStatus.executed, StepStatus.failed, StepStatus.skipped}


class RunStatus(str, Enum):
    running = "running"
    awaiting_approval = "awaiting_approval"
    completed = "completed"
    failed = "failed"
    denied = "denied"


TERMINAL_RUN = {RunStatus.completed, RunStatus.failed, RunStatus.denied}


class Decision(str, Enum):
    allow = "allow"
    needs_approval = "needs_approval"
    deny = "deny"


class ToolKind(str, Enum):
    read = "read"
    write = "write"


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    description: str = ""
    tool: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)


class Runbook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    description: str = ""
    steps: list[Step] = Field(min_length=1)

    @model_validator(mode="after")
    def _graph_is_valid(self) -> "Runbook":
        ids = [s.id for s in self.steps]
        seen: set[str] = set()
        for i in ids:
            if i in seen:
                raise ValueError(f"duplicate_id: step id {i!r} appears more than once")
            seen.add(i)
        for s in self.steps:
            for d in s.depends_on:
                if d == s.id:
                    raise ValueError(f"cycle: step {s.id!r} depends on itself")
                if d not in seen:
                    raise ValueError(f"unknown_dependency: step {s.id!r} depends on {d!r}")
        # Kahn's algorithm: anything left over is on a cycle.
        indeg = {s.id: len(set(s.depends_on)) for s in self.steps}
        children: dict[str, list[str]] = {s.id: [] for s in self.steps}
        for s in self.steps:
            for d in set(s.depends_on):
                children[d].append(s.id)
        ready = [i for i, n in indeg.items() if n == 0]
        done = 0
        while ready:
            cur = ready.pop()
            done += 1
            for ch in children[cur]:
                indeg[ch] -= 1
                if indeg[ch] == 0:
                    ready.append(ch)
        if done != len(self.steps):
            stuck = sorted(i for i, n in indeg.items() if n > 0)
            raise ValueError(f"cycle: dependency cycle among steps {stuck}")
        return self

    def step(self, step_id: str) -> Step | None:
        return next((s for s in self.steps if s.id == step_id), None)

    def check_tools(self, known_tools: set[str]) -> None:
        for s in self.steps:
            if s.tool not in known_tools:
                raise RunbookError(f"unknown_tool: step {s.id!r} uses unregistered tool {s.tool!r}")

    @classmethod
    def from_yaml(cls, text: str, known_tools: set[str] | None = None) -> "Runbook":
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise RunbookError("invalid_runbook: top level must be a mapping")
        rb = cls.model_validate(data)
        if known_tools is not None:
            rb.check_tools(known_tools)
        return rb

    @classmethod
    def from_file(cls, path: str | Path, known_tools: set[str] | None = None) -> "Runbook":
        return cls.from_yaml(Path(path).read_text(), known_tools)


class Proposal(BaseModel):
    """What a planner suggests doing next. It is only a suggestion."""

    step_id: str
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class DryRunResult(BaseModel):
    ok: bool = True
    error: str | None = None
    tool: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    affected_services: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    transitive_dependents: list[str] = Field(default_factory=list)
    protected: list[str] = Field(default_factory=list)
    changes: list[str] = Field(default_factory=list)


class BlastRadius(BaseModel):
    services: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    protected: list[str] = Field(default_factory=list)
    transitive: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.services)


class Plan(BaseModel):
    run_id: str
    step_id: str
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    kind: ToolKind | None = None  # None means the tool is not registered
    params_error: str | None = None
    dry_run: DryRunResult | None = None
    plan_hash: str = ""

    def compute_hash(self) -> str:
        """Hash of everything an approval must be bound to."""
        dr = self.dry_run
        body = {
            "run_id": self.run_id,
            "step_id": self.step_id,
            "tool": self.tool,
            "params": self.params,
            "kind": self.kind.value if self.kind else None,
            "params_error": self.params_error,
            "dry_run": None if dr is None else {
                "ok": dr.ok,
                "services": sorted(dr.affected_services),
                "hosts": sorted(dr.affected_hosts),
                "protected": sorted(dr.protected),
            },
        }
        return sha256(canonical(body))

    def seal(self) -> "Plan":
        self.plan_hash = self.compute_hash()
        return self


class Reason(BaseModel):
    code: str
    detail: str = ""


class Verdict(BaseModel):
    decision: Decision
    reasons: list[Reason] = Field(default_factory=list)
    blast_radius: BlastRadius | None = None

    @property
    def codes(self) -> list[str]:
        return [r.code for r in self.reasons]


class ApprovalStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    consumed = "consumed"
    expired = "expired"


class ApprovalRecord(BaseModel):
    id: str
    run_id: str
    step_id: str
    plan_hash: str
    requester: str
    approver: str | None = None
    status: ApprovalStatus = ApprovalStatus.pending
    created_at: float
    expires_at: float
    approved_at: float | None = None
    consumed_at: float | None = None


class StepState(BaseModel):
    step_id: str
    tool: str
    status: StepStatus = StepStatus.pending
    plan_hash: str | None = None
    approval_id: str | None = None
    idempotency_key: str | None = None
    verdict: Verdict | None = None
    result: dict[str, Any] | None = None
    error_code: str | None = None
    error: str | None = None
    updated_at: float = 0.0


class RunState(BaseModel):
    run_id: str
    runbook_name: str
    requester: str
    status: RunStatus = RunStatus.running
    steps: dict[str, StepState] = Field(default_factory=dict)
    writes_executed: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0

    def pending_approval_ids(self) -> list[str]:
        return [s.approval_id for s in self.steps.values()
                if s.status == StepStatus.awaiting_approval and s.approval_id]
