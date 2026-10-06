"""Hash-chained append-only audit log (adapted from edge-sentinel/agent/audit.py).

Same chain as edge-sentinel (each record stores the SHA-256 of the previous
one), but stored in the run database so an audit record is written in the same
transaction as the state change it describes: a hard kill can never leave a
committed transition without its audit record, or the reverse.

This detects tampering; it does not prevent it. Anyone with file access can
drop the append-only triggers and rewrite the whole chain.
"""
from __future__ import annotations

import hashlib
import json
import time

from .store import RunStore

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class AuditLog:
    def __init__(self, store: RunStore, clock=time.time):
        self.store = store
        self.clock = clock

    def append(self, c, event: str, data: dict) -> dict:
        """Append inside the caller's open transaction `c`."""
        row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        ts = self.clock()
        data_json = json.dumps(data, sort_keys=True, default=str)
        body = {"ts": ts, "event": event, "data": json.loads(data_json)}
        h = _digest(prev, body)
        c.execute("INSERT INTO audit(ts, event, data, prev, hash) VALUES (?,?,?,?,?)",
                  (ts, event, data_json, prev, h))
        return {**body, "prev": prev, "hash": h}

    def append_now(self, event: str, data: dict) -> dict:
        with self.store.txn() as c:
            return self.append(c, event, data)

    def records(self) -> list[dict]:
        rows = self.store.conn.execute("SELECT ts, event, data, prev, hash FROM audit ORDER BY seq")
        return [{"ts": ts, "event": e, "data": json.loads(d), "prev": p, "hash": h}
                for ts, e, d, p, h in rows]

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index of first bad record)."""
        prev = GENESIS
        for i, rec in enumerate(self.records()):
            body = {k: rec[k] for k in ("ts", "event", "data")}
            if rec["prev"] != prev or rec["hash"] != _digest(prev, body):
                return False, i
            prev = rec["hash"]
        return True, None
