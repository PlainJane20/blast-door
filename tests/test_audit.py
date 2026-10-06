import pytest
import sqlite3

from runbook_autopilot.audit import AuditLog
from runbook_autopilot.store import RunStore

from conftest import approve_pending, runbook, start


def test_chain_verifies(tmp_path):
    st = RunStore(tmp_path / "a.db")
    log = AuditLog(st)
    for i in range(4):
        log.append_now("e", {"i": i})
    assert log.verify() == (True, None) and len(log.records()) == 4


def test_update_is_blocked_by_trigger(tmp_path):
    st = RunStore(tmp_path / "a.db")
    AuditLog(st).append_now("e", {"i": 1})
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        st.conn.execute("UPDATE audit SET data='{}'")


def test_edit_after_dropping_trigger_is_detected(tmp_path):
    st = RunStore(tmp_path / "a.db")
    log = AuditLog(st)
    for i in range(3):
        log.append_now("e", {"i": i})
    st.conn.execute("DROP TRIGGER audit_no_update")
    st.conn.execute("UPDATE audit SET data='{\"i\": 99}' WHERE seq=2")
    assert log.verify() == (False, 1)


def test_deleted_record_is_detected(tmp_path):
    st = RunStore(tmp_path / "a.db")
    log = AuditLog(st)
    for i in range(3):
        log.append_now("e", {"i": i})
    st.conn.execute("DROP TRIGGER audit_no_delete")
    st.conn.execute("DELETE FROM audit WHERE seq=2")
    assert log.verify() == (False, 1)


def test_chain_survives_reopen(tmp_path):
    AuditLog(RunStore(tmp_path / "a.db")).append_now("e", {})
    log2 = AuditLog(RunStore(tmp_path / "a.db"))
    log2.append_now("e", {})
    assert log2.verify() == (True, None)


def test_audit_record_rolls_back_with_its_transaction(tmp_path):
    st = RunStore(tmp_path / "a.db")
    log = AuditLog(st)
    with pytest.raises(RuntimeError):
        with st.txn() as c:
            log.append(c, "e", {})
            raise RuntimeError("boom")
    assert log.records() == []


def test_full_flow_audits_every_stage(system):
    rb = runbook(("a", "scale_service", {"service": "auth-svc", "replicas": 3}))
    start(system, rb)
    approve_pending(system)
    system.executor.resume("r1")
    events = [r["event"] for r in system.audit.records()]
    for expected in ("run_started", "plan_created", "verdict", "approval_requested",
                     "approval_granted", "resume", "approval_consumed", "step_executed",
                     "run_completed"):
        assert expected in events, expected
    assert system.audit.verify() == (True, None)
