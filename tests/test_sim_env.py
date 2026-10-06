import sqlite3

import pytest

from blast_door.sim_env import SimEnv, SimError, WriteContext


@pytest.fixture
def env(tmp_path):
    e = SimEnv(tmp_path / "env.db", clock=lambda: 1.0)
    yield e
    e.close()


def ctx(key="k1", step="s1"):
    return WriteContext("r1", step, key)


def test_default_topology_has_protected_services(env):
    prot = {s["name"] for s in env.list_services() if s["protected"]}
    assert prot == {"db", "auth-svc"}


def test_transitive_dependents(env):
    assert env.dependents("cache") == ["api", "search", "web", "worker"]
    assert env.dependents("web") == []
    assert env.dependents("db") == ["api", "auth-svc", "batch-report", "web", "worker"]


def test_dry_run_changes_nothing(env):
    before = env.snapshot()
    for call in (lambda: env.restart_service("cache", dry_run=True),
                 lambda: env.scale_service("api", 9, dry_run=True),
                 lambda: env.rollout_restart("api", dry_run=True),
                 lambda: env.drain_host("host-a", dry_run=True)):
        assert call().ok
    assert env.snapshot() == before and env.ledger() == []


def test_dry_run_includes_transitive_dependents(env):
    dr = env.restart_service("cache", dry_run=True)
    assert dr.affected_services == ["api", "cache", "search", "web", "worker"]
    assert dr.transitive_dependents == ["api", "search", "web", "worker"]


def test_drain_host_dry_run_reports_protected_and_dependents(env):
    dr = env.drain_host("host-a", dry_run=True)
    assert set(dr.protected) == {"db", "auth-svc"}
    assert "web" in dr.affected_services and "host-a" in dr.affected_hosts


def test_dry_run_unknown_service_is_not_ok(env):
    dr = env.restart_service("nope", dry_run=True)
    assert not dr.ok and "unknown service" in dr.error


def test_dry_run_unknown_host_is_not_ok(env):
    assert not env.drain_host("host-zz", dry_run=True).ok


def test_restart_changes_state_and_appends_ledger(env):
    out = env.restart_service("web", ctx=ctx())
    assert out["deduplicated"] is False
    assert env.get_service_status("web")["restarts"] == 1
    [e] = env.ledger()
    assert (e["tool"], e["params"], e["step_id"]) == ("restart_service", {"service": "web"}, "s1")


def test_scale_rollout_and_drain_apply(env):
    env.scale_service("web", 7, ctx=ctx("a"))
    env.rollout_restart("api", ctx=ctx("b"))
    env.drain_host("host-d", ctx=ctx("c"))
    assert env.get_service_status("web")["replicas"] == 7
    assert env.get_service_status("api")["generation"] == 2
    assert env.get_service_status("search")["status"] == "evicted"
    assert {h["name"]: h["drained"] for h in env.snapshot()["hosts"]}["host-d"] is True


def test_same_idempotency_key_is_applied_once(env):
    env.restart_service("web", ctx=ctx("same"))
    again = env.restart_service("web", ctx=ctx("same"))
    assert again["deduplicated"] is True
    assert len(env.ledger()) == 1 and env.get_service_status("web")["restarts"] == 1


def test_without_key_double_execution_is_visible_in_ledger(env):
    env.restart_service("web", ctx=WriteContext("r1", "s1", None))
    env.restart_service("web", ctx=WriteContext("r1", "s1", None))
    assert len(env.ledger()) == 2 and env.get_service_status("web")["restarts"] == 2


def test_ledger_rejects_update_and_delete(env):
    env.restart_service("web", ctx=ctx())
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        env.conn.execute("UPDATE ledger SET tool='x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        env.conn.execute("DELETE FROM ledger")


def test_state_persists_across_reopen(tmp_path):
    a = SimEnv(tmp_path / "e.db")
    a.restart_service("web", ctx=ctx())
    a.close()
    b = SimEnv(tmp_path / "e.db")
    assert b.get_service_status("web")["restarts"] == 1 and len(b.ledger()) == 1
    assert len(b.list_services()) == 9  # reopening does not re-seed
    b.close()


def test_metrics_are_deterministic_and_distinct(env):
    assert env.get_metrics("api") == env.get_metrics("api")
    assert env.get_metrics("api") != env.get_metrics("web")


def test_real_write_requires_context(env):
    with pytest.raises(SimError):
        env.restart_service("web")


def test_real_write_to_unknown_service_fails_and_leaves_no_ledger(env):
    with pytest.raises(SimError):
        env.restart_service("nope", ctx=ctx())
    assert env.ledger() == []


def test_unknown_service_status_raises(env):
    with pytest.raises(SimError):
        env.get_service_status("nope")
