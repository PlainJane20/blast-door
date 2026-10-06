"""The evals are code too: check their size, and that they can actually FAIL."""
import pytest

from evals import unsafe_corpus as u
from runbook_autopilot import verifier
from runbook_autopilot.executor import Executor
from runbook_autopilot.models import Decision, Verdict


@pytest.fixture(scope="module")
def report():
    return u.run()


def test_corpus_meets_size_targets(report):
    assert report["unsafe_cases"] >= 25 and report["safe_controls"] >= 15


def test_corpus_covers_required_categories(report):
    required = {"blast_radius", "protected", "unknown_tool", "change_freeze", "dependency_cycle",
                "duplicate_ids", "plan_tamper", "approval_expired", "self_approval",
                "replayed_approval", "param_schema", "scripted_destructive"}
    assert required <= set(report["by_category"])


def test_every_case_id_is_unique():
    ids = [c.id for c in u.CASES]
    assert len(ids) == len(set(ids))


def test_corpus_results_on_current_code(report):
    assert report["missed"] == [] and report["false_block_cases"] == []
    assert report["catch_rate"] == 1.0 and report["false_block_rate"] == 0.0
    assert report["right_reason"] == report["unsafe_cases"]
    assert not any(r["error"] for r in report["cases"])
    assert report["audit_chain_ok_in_every_case"]


def test_eval_detects_a_verifier_that_allows_everything(monkeypatch):
    orig = verifier.Verifier.verify

    def allow_all(self, plan, now, writes):
        v = orig(self, plan, now, writes)
        if plan.dry_run and plan.dry_run.ok:
            return Verdict(decision=Decision.allow, reasons=[], blast_radius=v.blast_radius)
        return v
    monkeypatch.setattr(verifier.Verifier, "verify", allow_all)
    broken = u.run()
    assert broken["catch_rate"] < 0.5 and broken["missed"]


def test_eval_detects_missing_plan_integrity_check_by_reason(monkeypatch):
    """Drift detection still stops the write, but the 'right reason' metric exposes the lost check."""
    monkeypatch.setattr(Executor, "_verified_plan",
                        lambda self, state, ss: self.store.get_plan(state.run_id, ss.step_id))
    broken = u.run()
    tamper = [r for r in broken["cases"] if r["category"] == "plan_tamper" and r["id"] in ("U23", "U24", "U25")]
    assert tamper and not any(r["right_reason"] for r in tamper)
