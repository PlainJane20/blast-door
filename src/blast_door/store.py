"""SQLite checkpoint store: runs, plans, approvals, checkpoints, audit.

Every state transition is one transaction (BEGIN IMMEDIATE ... COMMIT), so a
hard kill leaves either the old state or the new state, never half of one.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .models import ApprovalRecord, Plan, RunState

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY, runbook_json TEXT NOT NULL, policy_json TEXT NOT NULL,
  state_json TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS plans(
  run_id TEXT NOT NULL, step_id TEXT NOT NULL, plan_hash TEXT NOT NULL, plan_json TEXT NOT NULL,
  PRIMARY KEY(run_id, step_id));
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, step_id TEXT NOT NULL, plan_hash TEXT NOT NULL,
  requester TEXT NOT NULL, approver TEXT, status TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, consumed_at REAL);
CREATE TABLE IF NOT EXISTS checkpoints(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, step_id TEXT, phase TEXT NOT NULL,
  ts REAL NOT NULL, state_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL,
  data TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

APPROVAL_COLS = ("id, run_id, step_id, plan_hash, requester, approver, status, "
                 "created_at, expires_at, approved_at, consumed_at")


class RunStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def txn(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # runs ------------------------------------------------------------------
    def create_run(self, c, state: RunState, runbook_json: str, policy_json: str) -> None:
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",
                  (state.run_id, runbook_json, policy_json, state.model_dump_json(),
                   state.created_at, state.updated_at))

    def save_state(self, c, state: RunState) -> None:
        c.execute("UPDATE runs SET state_json=?, updated_at=? WHERE run_id=?",
                  (state.model_dump_json(), state.updated_at, state.run_id))

    def load_state(self, run_id: str) -> RunState | None:
        row = self.conn.execute("SELECT state_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return RunState.model_validate_json(row[0]) if row else None

    def load_run_blobs(self, run_id: str) -> tuple[str, str]:
        row = self.conn.execute("SELECT runbook_json, policy_json FROM runs WHERE run_id=?",
                                (run_id,)).fetchone()
        if not row:
            raise KeyError(run_id)
        return row

    # plans -----------------------------------------------------------------
    def put_plan(self, c, plan: Plan) -> None:
        c.execute("INSERT OR REPLACE INTO plans VALUES (?,?,?,?)",
                  (plan.run_id, plan.step_id, plan.plan_hash, plan.model_dump_json()))

    def get_plan(self, run_id: str, step_id: str) -> Plan | None:
        row = self.conn.execute("SELECT plan_json FROM plans WHERE run_id=? AND step_id=?",
                                (run_id, step_id)).fetchone()
        return Plan.model_validate_json(row[0]) if row else None

    # checkpoints -----------------------------------------------------------
    def add_checkpoint(self, c, state: RunState, step_id: str | None, phase: str) -> None:
        c.execute("INSERT INTO checkpoints(run_id, step_id, phase, ts, state_json) VALUES (?,?,?,?,?)",
                  (state.run_id, step_id, phase, state.updated_at, state.model_dump_json()))

    def checkpoint_count(self, run_id: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM checkpoints WHERE run_id=?",
                                 (run_id,)).fetchone()[0]

    # approvals -------------------------------------------------------------
    @staticmethod
    def _approval(row) -> ApprovalRecord:
        keys = ("id", "run_id", "step_id", "plan_hash", "requester", "approver", "status",
                "created_at", "expires_at", "approved_at", "consumed_at")
        return ApprovalRecord(**dict(zip(keys, row)))

    def get_approval(self, approval_id: str, c=None) -> ApprovalRecord | None:
        row = (c or self.conn).execute(
            f"SELECT {APPROVAL_COLS} FROM approvals WHERE id=?", (approval_id,)).fetchone()
        return self._approval(row) if row else None

    def approvals_for_run(self, run_id: str) -> list[ApprovalRecord]:
        return [self._approval(r) for r in self.conn.execute(
            f"SELECT {APPROVAL_COLS} FROM approvals WHERE run_id=? ORDER BY created_at, id",
            (run_id,))]

    def count_approvals(self, c, run_id: str, step_id: str) -> int:
        return c.execute("SELECT COUNT(*) FROM approvals WHERE run_id=? AND step_id=?",
                         (run_id, step_id)).fetchone()[0]
