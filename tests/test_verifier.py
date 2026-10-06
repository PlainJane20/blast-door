from datetime import datetime, timezone

import pytest

from blast_door.models import Decision
from blast_door.verifier import FreezeWindow, Policy, Verifier

from conftest import T0


@pytest.fixture
def plan_for(system):
    def make(tool, params):
        return system.executor._make_plan("r1", "s1", tool, params)
    return make


def verdict(system, plan, policy=None, now=T0, writes=0):
    return Verifier(policy or Policy(), system.registry).verify(plan, now, writes)


def test_leaf_restart_is_allowed(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "web"}))
    assert v.decision == Decision.allow and v.blast_radius.count == 1


def test_protected_needs_approval_by_default(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "db"}), Policy(max_affected_services=99))
    assert v.decision == Decision.needs_approval and "protected_resource" in v.codes


def test_protected_denied_when_policy_says_deny(system, plan_for):
    v = verdict(system, plan_for("scale_service", {"service": "auth-svc", "replicas": 3}),
                Policy(protected_policy="deny"))
    assert v.decision == Decision.deny and "protected_resource" in v.codes


def test_blast_over_threshold_needs_approval(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "cache"}))  # 5 services
    assert v.decision == Decision.needs_approval and "blast_radius_over_threshold" in v.codes


def test_blast_over_max_is_denied(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "cache"}),
                Policy(max_affected_services=4))
    assert v.decision == Decision.deny and "blast_radius_exceeded" in v.codes


def test_blast_exactly_at_max_is_not_denied(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "cache"}),
                Policy(max_affected_services=5))
    assert v.decision != Decision.deny


def test_drain_host_a_is_denied(system, plan_for):
    v = verdict(system, plan_for("drain_host", {"host": "host-a"}))
    assert v.decision == Decision.deny
    assert {"blast_radius_exceeded", "protected_resource"} <= set(v.codes)


def test_change_freeze_denies_writes_inside_window(system, plan_for):
    w = FreezeWindow(start=datetime(2027, 1, 14, tzinfo=timezone.utc),
                     end=datetime(2027, 1, 16, tzinfo=timezone.utc), reason="release freeze")
    v = verdict(system, plan_for("restart_service", {"service": "web"}), Policy(change_freeze=[w]))
    assert v.decision == Decision.deny and v.codes[0] == "change_freeze"


def test_outside_freeze_window_is_allowed(system, plan_for):
    w = FreezeWindow(start=datetime(2027, 2, 1, tzinfo=timezone.utc),
                     end=datetime(2027, 2, 2, tzinfo=timezone.utc))
    assert verdict(system, plan_for("restart_service", {"service": "web"}),
                   Policy(change_freeze=[w])).decision == Decision.allow


def test_freeze_does_not_block_reads(system, plan_for):
    w = FreezeWindow(start=datetime(2027, 1, 1, tzinfo=timezone.utc),
                     end=datetime(2027, 2, 1, tzinfo=timezone.utc))
    assert verdict(system, plan_for("list_services", {}), Policy(change_freeze=[w])).decision == Decision.allow


def test_naive_freeze_datetimes_are_treated_as_utc():
    w = FreezeWindow(start=datetime(2027, 1, 15), end=datetime(2027, 1, 16))
    assert w.start.tzinfo is not None and w.active(T0)


def test_max_writes_per_run(system, plan_for):
    p = Policy(max_writes_per_run=2)
    plan = plan_for("restart_service", {"service": "web"})
    assert verdict(system, plan, p, writes=1).decision == Decision.allow
    v = verdict(system, plan, p, writes=2)
    assert v.decision == Decision.deny and "max_writes_exceeded" in v.codes


def test_allowlist_denies_unlisted_tool(system, plan_for):
    p = Policy(allowlisted_tools=["restart_service", "list_services"])
    v = verdict(system, plan_for("drain_host", {"host": "host-d"}), p)
    assert v.decision == Decision.deny and "tool_not_allowlisted" in v.codes


def test_unknown_tool_denied(system, plan_for):
    v = verdict(system, plan_for("delete_service", {"service": "web"}))
    assert v.decision == Decision.deny and v.codes == ["tool_unknown"]


def test_invalid_params_denied(system, plan_for):
    v = verdict(system, plan_for("scale_service", {"service": "web", "replicas": -4}))
    assert v.decision == Decision.deny and "params_invalid" in v.codes


def test_scale_to_zero_denied_unless_policy_allows(system, plan_for):
    plan = plan_for("scale_service", {"service": "web", "replicas": 0})
    v = verdict(system, plan)
    assert v.decision == Decision.deny and "scale_to_zero" in v.codes
    assert verdict(system, plan, Policy(deny_scale_to_zero=False)).decision == Decision.allow


def test_failed_dry_run_denied(system, plan_for):
    v = verdict(system, plan_for("restart_service", {"service": "ghost"}))
    assert v.decision == Decision.deny and v.codes == ["dry_run_failed"]


def test_read_tool_allowed_with_empty_blast(system, plan_for):
    v = verdict(system, plan_for("get_metrics", {"service": "db"}))
    assert v.decision == Decision.allow and v.blast_radius.count == 0


def test_all_applicable_reasons_are_reported(system, plan_for):
    v = verdict(system, plan_for("drain_host", {"host": "host-a"}), Policy(protected_policy="deny"))
    assert len(set(v.codes)) >= 3


def test_verifier_is_deterministic(system, plan_for):
    plan = plan_for("restart_service", {"service": "cache"})
    first = verdict(system, plan).model_dump()
    assert all(verdict(system, plan).model_dump() == first for _ in range(50))


def test_policy_from_yaml_and_digest():
    p = Policy.from_yaml("max_affected_services: 2\nchange_freeze:\n"
                         "  - {start: 2027-01-01T00:00:00Z, end: 2027-01-02T00:00:00Z}\n")
    assert p.max_affected_services == 2 and len(p.change_freeze) == 1
    assert p.digest() == Policy.from_yaml("max_affected_services: 2\nchange_freeze:\n"
                                          "  - {start: 2027-01-01T00:00:00Z, end: 2027-01-02T00:00:00Z}\n").digest()
    assert p.digest() != Policy().digest()


def test_policy_rejects_unknown_keys():
    with pytest.raises(Exception):
        Policy.from_yaml("max_affected_servces: 2\n")
