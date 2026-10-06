"""Planner interface. A planner PROPOSES; it never decides.

RuleBasedPlanner follows the runbook. ScriptedPlanner is a test double that
proposes arbitrary (including unsafe) actions, to prove the verifier overrides
the "model". A live LLM planner is NOT built.
"""
from __future__ import annotations

from typing import Protocol

from .models import TERMINAL_STEP, Proposal, Runbook, RunState, StepStatus


class Planner(Protocol):
    def next_action(self, runbook: Runbook, state: RunState) -> Proposal | None:
        """Return the next thing to try, or None when there is nothing left.

        Must be a pure function of (runbook, state) so a resumed run asks the
        same question and gets the same answer.
        """
        ...


class RuleBasedPlanner:
    """Deterministic: runs the first runnable step in runbook order."""

    def next_action(self, runbook: Runbook, state: RunState) -> Proposal | None:
        for step in runbook.steps:
            ss = state.steps.get(step.id)
            status = ss.status if ss else StepStatus.pending
            if status in TERMINAL_STEP:
                continue
            deps_done = all(
                (state.steps.get(d) and state.steps[d].status == StepStatus.executed)
                for d in step.depends_on)
            if deps_done:
                return Proposal(step_id=step.id, tool=step.tool, params=dict(step.params),
                                description=step.description)
        return None


class ScriptedPlanner:
    """Test double: proposes a fixed script, ignoring the runbook's steps."""

    def __init__(self, proposals: list[Proposal]):
        self.proposals = proposals

    def next_action(self, runbook: Runbook, state: RunState) -> Proposal | None:
        for p in self.proposals:
            ss = state.steps.get(p.step_id)
            if ss is None or ss.status not in TERMINAL_STEP:
                return p
        return None
