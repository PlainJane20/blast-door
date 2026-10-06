from pathlib import Path

import pytest
from pydantic import ValidationError

from blast_door.models import Plan, Runbook, RunbookError, ToolKind
from blast_door.tools import ToolRegistry

KNOWN = ToolRegistry.default().names()
EX = Path(__file__).resolve().parents[1] / "examples"


def yaml_rb(steps: str) -> str:
    return "name: t\nsteps:\n" + steps


def test_valid_runbook_loads():
    rb = Runbook.from_yaml(yaml_rb("""
  - {id: a, tool: list_services}
  - {id: b, tool: get_service_status, params: {service: web}, depends_on: [a]}
"""), KNOWN)
    assert [s.id for s in rb.steps] == ["a", "b"]


def test_duplicate_ids_rejected():
    with pytest.raises(ValidationError, match="duplicate_id"):
        Runbook.from_yaml(yaml_rb("  - {id: a, tool: list_services}\n  - {id: a, tool: list_services}\n"))


def test_unknown_dependency_rejected():
    with pytest.raises(ValidationError, match="unknown_dependency"):
        Runbook.from_yaml(yaml_rb("  - {id: a, tool: list_services, depends_on: [zzz]}\n"))


def test_self_dependency_is_a_cycle():
    with pytest.raises(ValidationError, match="cycle"):
        Runbook.from_yaml(yaml_rb("  - {id: a, tool: list_services, depends_on: [a]}\n"))


def test_two_step_cycle_rejected():
    with pytest.raises(ValidationError, match="cycle"):
        Runbook.from_yaml(yaml_rb("""
  - {id: a, tool: list_services, depends_on: [b]}
  - {id: b, tool: list_services, depends_on: [a]}
"""))


def test_long_cycle_behind_a_valid_prefix_rejected():
    with pytest.raises(ValidationError, match="cycle"):
        Runbook.from_yaml(yaml_rb("""
  - {id: root, tool: list_services}
  - {id: a, tool: list_services, depends_on: [root, c]}
  - {id: b, tool: list_services, depends_on: [a]}
  - {id: c, tool: list_services, depends_on: [b]}
"""))


def test_diamond_dag_is_valid():
    Runbook.from_yaml(yaml_rb("""
  - {id: a, tool: list_services}
  - {id: b, tool: list_services, depends_on: [a]}
  - {id: c, tool: list_services, depends_on: [a]}
  - {id: d, tool: list_services, depends_on: [b, c]}
"""))


def test_unknown_tool_rejected_against_registry():
    with pytest.raises(RunbookError, match="unknown_tool"):
        Runbook.from_yaml(yaml_rb("  - {id: a, tool: delete_everything}\n"), KNOWN)


def test_unknown_tool_not_checked_without_registry():
    assert Runbook.from_yaml(yaml_rb("  - {id: a, tool: delete_everything}\n")).steps[0].tool


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        Runbook.from_yaml(yaml_rb("  - {id: a, tool: list_services, sudo: true}\n"))


def test_bad_step_id_rejected():
    with pytest.raises(ValidationError):
        Runbook.from_yaml(yaml_rb("  - {id: 'bad id!', tool: list_services}\n"))


def test_empty_steps_rejected():
    with pytest.raises(ValidationError):
        Runbook.from_yaml("name: t\nsteps: []\n")


def test_non_mapping_yaml_rejected():
    with pytest.raises(RunbookError, match="invalid_runbook"):
        Runbook.from_yaml("- just\n- a list\n")


@pytest.mark.parametrize("name", ["safe_restart", "protected_needs_approval", "unsafe_denied"])
def test_example_runbooks_load(name):
    assert Runbook.from_file(EX / f"{name}.yaml", KNOWN).steps


def test_plan_hash_is_deterministic_and_content_sensitive():
    base = dict(run_id="r", step_id="s", tool="restart_service", params={"service": "web"},
                kind=ToolKind.write)
    a, b = Plan(**base).seal(), Plan(**base).seal()
    assert a.plan_hash == b.plan_hash and len(a.plan_hash) == 64
    c = Plan(**{**base, "params": {"service": "db"}}).seal()
    assert c.plan_hash != a.plan_hash
    d = Plan(**{**base, "step_id": "other"}).seal()
    assert d.plan_hash != a.plan_hash
