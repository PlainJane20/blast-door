import pytest

from blast_door.models import ToolKind
from blast_door.tools import ParamsError, ToolRegistry

REG = ToolRegistry.default()


def test_registry_has_the_documented_tools():
    assert REG.names() == {"list_services", "get_service_status", "get_metrics",
                           "restart_service", "rollout_restart", "scale_service", "drain_host"}


def test_kinds():
    reads = {n for n in REG.names() if REG.maybe(n).kind == ToolKind.read}
    assert reads == {"list_services", "get_service_status", "get_metrics"}


def test_unknown_tool_is_absent():
    assert REG.maybe("rm_rf") is None


def test_valid_params_parse():
    assert REG.validate_params("scale_service", {"service": "web", "replicas": 3}).replicas == 3


@pytest.mark.parametrize("tool,params", [
    ("scale_service", {"service": "web", "replicas": -1}),
    ("scale_service", {"service": "web", "replicas": "many"}),
    ("scale_service", {"service": "web", "replicas": "3"}),   # strict int: no coercion
    ("scale_service", {"service": "web", "replicas": 3.5}),
    ("scale_service", {"service": "web", "replicas": 999}),
    ("scale_service", {"service": "web"}),
    ("restart_service", {}),
    ("restart_service", {"service": "web", "force": True}),   # extra field
    ("restart_service", {"service": "Web; rm -rf /"}),
    ("drain_host", {"host": ""}),
    ("list_services", {"verbose": True}),
])
def test_bad_params_rejected(tool, params):
    with pytest.raises(ParamsError):
        REG.validate_params(tool, params)


def test_scale_to_zero_flag_in_blast_radius():
    from blast_door.models import DryRunResult
    spec = REG.maybe("scale_service")
    p = REG.validate_params("scale_service", {"service": "web", "replicas": 0})
    b = spec.blast(p, DryRunResult(affected_services=["web"]))
    assert "scale_to_zero" in b.flags
    p2 = REG.validate_params("scale_service", {"service": "web", "replicas": 2})
    assert not spec.blast(p2, DryRunResult(affected_services=["web"])).flags


def test_read_tools_have_empty_blast_radius():
    from blast_door.models import DryRunResult
    b = REG.maybe("get_metrics").blast(REG.validate_params("get_metrics", {"service": "web"}),
                                       DryRunResult())
    assert b.count == 0
