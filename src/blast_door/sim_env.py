"""SIMULATED infrastructure: services, hosts, replicas, and an effects ledger.

Nothing here talks to real infrastructure. State lives in SQLite so it
survives a hard kill, which is what lets tests prove a resumed run never
double-executes a write: every real write appends to an append-only EFFECTS
LEDGER (SQLite triggers reject UPDATE and DELETE) in the same transaction as
the state change. A write carrying an idempotency key that is already in the
ledger is a no-op.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import DryRunResult


class SimError(Exception):
    pass


# service -> (replicas, protected, host, depends_on)
DEFAULT_TOPOLOGY: dict[str, dict[str, Any]] = {
    "db":             {"replicas": 3, "protected": True,  "host": "host-a", "depends_on": []},
    "cache":          {"replicas": 2, "protected": False, "host": "host-a", "depends_on": []},
    "auth-svc":       {"replicas": 2, "protected": True,  "host": "host-b", "depends_on": ["db"]},
    "api":            {"replicas": 4, "protected": False, "host": "host-b",
                       "depends_on": ["db", "cache", "auth-svc"]},
    "web":            {"replicas": 4, "protected": False, "host": "host-c", "depends_on": ["api"]},
    "worker":         {"replicas": 2, "protected": False, "host": "host-c",
                       "depends_on": ["db", "cache"]},
    "search":         {"replicas": 2, "protected": False, "host": "host-d", "depends_on": ["cache"]},
    "batch-report":   {"replicas": 1, "protected": False, "host": "host-d", "depends_on": ["db"]},
    "metrics-agent":  {"replicas": 1, "protected": False, "host": "host-d", "depends_on": []},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS services(
  name TEXT PRIMARY KEY, replicas INTEGER NOT NULL, protected INTEGER NOT NULL,
  host TEXT NOT NULL, status TEXT NOT NULL, restarts INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS deps(service TEXT NOT NULL, depends_on TEXT NOT NULL,
  PRIMARY KEY(service, depends_on));
CREATE TABLE IF NOT EXISTS hosts(name TEXT PRIMARY KEY, drained INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, idem_key TEXT UNIQUE, run_id TEXT, step_id TEXT,
  tool TEXT NOT NULL, params TEXT NOT NULL, affected TEXT NOT NULL, ts REAL NOT NULL);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
  BEGIN SELECT RAISE(ABORT, 'effects ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
  BEGIN SELECT RAISE(ABORT, 'effects ledger is append-only'); END;
"""


@dataclass(frozen=True)
class WriteContext:
    run_id: str
    step_id: str
    idempotency_key: str | None


class SimEnv:
    def __init__(self, path: str | Path, clock=time.time, topology: dict | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)
        self._seed(topology or DEFAULT_TOPOLOGY)

    def close(self) -> None:
        self.conn.close()

    def _seed(self, topo: dict) -> None:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if self.conn.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
                for name, s in topo.items():
                    self.conn.execute(
                        "INSERT INTO services(name, replicas, protected, host, status) "
                        "VALUES (?,?,?,?, 'running')",
                        (name, s["replicas"], int(s["protected"]), s["host"]))
                    for d in s["depends_on"]:
                        self.conn.execute("INSERT INTO deps VALUES (?,?)", (name, d))
                    self.conn.execute("INSERT OR IGNORE INTO hosts(name) VALUES (?)", (s["host"],))
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    # -- graph helpers -------------------------------------------------------
    def _exists(self, name: str) -> bool:
        return self.conn.execute("SELECT 1 FROM services WHERE name=?", (name,)).fetchone() is not None

    def dependents(self, name: str) -> list[str]:
        """Services that (transitively) depend on `name`, sorted."""
        out: set[str] = set()
        frontier = [name]
        while frontier:
            cur = frontier.pop()
            for (svc,) in self.conn.execute("SELECT service FROM deps WHERE depends_on=?", (cur,)):
                if svc not in out:
                    out.add(svc)
                    frontier.append(svc)
        return sorted(out)

    def services_on(self, host: str) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT name FROM services WHERE host=? ORDER BY name", (host,))]

    # -- READ tools ----------------------------------------------------------
    def list_services(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT name, replicas, protected, host, status FROM services ORDER BY name")
        return [{"name": n, "replicas": r, "protected": bool(p), "host": h, "status": s}
                for n, r, p, h, s in rows]

    def get_service_status(self, service: str) -> dict:
        row = self.conn.execute(
            "SELECT name, replicas, protected, host, status, restarts, generation "
            "FROM services WHERE name=?", (service,)).fetchone()
        if not row:
            raise SimError(f"unknown service: {service}")
        deps = [r[0] for r in self.conn.execute(
            "SELECT depends_on FROM deps WHERE service=? ORDER BY depends_on", (service,))]
        return {"name": row[0], "replicas": row[1], "protected": bool(row[2]), "host": row[3],
                "status": row[4], "restarts": row[5], "generation": row[6], "depends_on": deps}

    def get_metrics(self, service: str) -> dict:
        """Deterministic synthetic metrics derived from the service name."""
        if not self._exists(service):
            raise SimError(f"unknown service: {service}")
        d = hashlib.sha256(service.encode()).digest()
        return {"service": service,
                "cpu_pct": round(10 + d[0] / 255 * 60, 1),
                "mem_pct": round(20 + d[1] / 255 * 55, 1),
                "error_rate": round(d[2] / 255 * 0.02, 4),
                "p95_ms": 40 + d[3]}

    # -- dry-run -------------------------------------------------------------
    def _dry(self, tool: str, params: dict) -> DryRunResult:
        base = {"tool": tool, "params": dict(params)}
        try:
            if tool == "drain_host":
                host = params["host"]
                if not self.conn.execute("SELECT 1 FROM hosts WHERE name=?", (host,)).fetchone():
                    return DryRunResult(ok=False, error=f"unknown host: {host}", **base)
                direct = self.services_on(host)
                affected = set(direct)
                for s in direct:
                    affected.update(self.dependents(s))
                transitive = sorted(affected - set(direct))
                changes = [f"drain {host}"] + [f"evict {s}" for s in direct]
                extra_hosts = {host}
            else:
                svc = params["service"]
                if not self._exists(svc):
                    return DryRunResult(ok=False, error=f"unknown service: {svc}", **base)
                transitive = self.dependents(svc)
                affected = {svc, *transitive}
                verb = {"restart_service": "restart", "rollout_restart": "rolling restart",
                        "scale_service": f"scale to {params.get('replicas')} replicas"}[tool]
                changes = [f"{verb} {svc}"]
                extra_hosts = set()
        except KeyError as e:
            return DryRunResult(ok=False, error=f"missing param: {e.args[0]}", **base)
        hosts = {r[0] for s in affected for r in self.conn.execute(
            "SELECT host FROM services WHERE name=?", (s,))} | extra_hosts
        prot = [s for s in sorted(affected) if self.conn.execute(
            "SELECT protected FROM services WHERE name=?", (s,)).fetchone()[0]]
        return DryRunResult(ok=True, affected_services=sorted(affected),
                            affected_hosts=sorted(hosts), transitive_dependents=transitive,
                            protected=prot, changes=changes, **base)

    # -- WRITE tools ---------------------------------------------------------
    def _write(self, tool: str, params: dict, dry_run: bool, ctx: WriteContext | None):
        if dry_run:
            return self._dry(tool, params)
        if ctx is None:
            raise SimError("a real write needs a WriteContext")
        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            if ctx.idempotency_key:
                row = c.execute("SELECT seq FROM ledger WHERE idem_key=?",
                                (ctx.idempotency_key,)).fetchone()
                if row:
                    c.execute("COMMIT")
                    return {"deduplicated": True, "ledger_seq": row[0]}
            dr = self._dry(tool, params)
            if not dr.ok:
                raise SimError(dr.error or "dry-run failed")
            if tool == "restart_service":
                c.execute("UPDATE services SET restarts=restarts+1, status='running' WHERE name=?",
                          (params["service"],))
            elif tool == "rollout_restart":
                c.execute("UPDATE services SET restarts=restarts+1, generation=generation+1, "
                          "status='running' WHERE name=?", (params["service"],))
            elif tool == "scale_service":
                c.execute("UPDATE services SET replicas=? WHERE name=?",
                          (params["replicas"], params["service"]))
            elif tool == "drain_host":
                c.execute("UPDATE hosts SET drained=1 WHERE name=?", (params["host"],))
                c.execute("UPDATE services SET status='evicted' WHERE host=?", (params["host"],))
            else:
                raise SimError(f"unsupported write tool {tool}")
            cur = c.execute(
                "INSERT INTO ledger(idem_key, run_id, step_id, tool, params, affected, ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (ctx.idempotency_key, ctx.run_id, ctx.step_id, tool,
                 json.dumps(params, sort_keys=True), json.dumps(dr.affected_services),
                 self.clock()))
            c.execute("COMMIT")
            return {"deduplicated": False, "ledger_seq": cur.lastrowid,
                    "affected": dr.affected_services}
        except BaseException:
            c.execute("ROLLBACK")
            raise

    def restart_service(self, service: str, dry_run: bool = False, ctx: WriteContext | None = None):
        return self._write("restart_service", {"service": service}, dry_run, ctx)

    def rollout_restart(self, service: str, dry_run: bool = False, ctx: WriteContext | None = None):
        return self._write("rollout_restart", {"service": service}, dry_run, ctx)

    def scale_service(self, service: str, replicas: int, dry_run: bool = False,
                      ctx: WriteContext | None = None):
        return self._write("scale_service", {"service": service, "replicas": replicas}, dry_run, ctx)

    def drain_host(self, host: str, dry_run: bool = False, ctx: WriteContext | None = None):
        return self._write("drain_host", {"host": host}, dry_run, ctx)

    # -- inspection (tests and evals) ---------------------------------------
    def ledger(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT seq, idem_key, run_id, step_id, tool, params, affected, ts "
            "FROM ledger ORDER BY seq")
        return [{"seq": s, "idem_key": k, "run_id": r, "step_id": st, "tool": t,
                 "params": json.loads(p), "affected": json.loads(a), "ts": ts}
                for s, k, r, st, t, p, a, ts in rows]

    def ledger_normalized(self) -> list[dict]:
        return [{k: v for k, v in e.items() if k not in ("seq", "ts")} for e in self.ledger()]

    def ledger_has(self, idem_key: str) -> dict | None:
        row = self.conn.execute(
            "SELECT seq, tool, params, affected FROM ledger WHERE idem_key=?", (idem_key,)).fetchone()
        if not row:
            return None
        return {"seq": row[0], "tool": row[1], "params": json.loads(row[2]),
                "affected": json.loads(row[3])}

    def snapshot(self) -> dict:
        svcs = [dict(zip(("name", "replicas", "protected", "host", "status", "restarts", "generation"), r))
                for r in self.conn.execute(
                    "SELECT name, replicas, protected, host, status, restarts, generation "
                    "FROM services ORDER BY name")]
        hosts = [{"name": n, "drained": bool(d)} for n, d in self.conn.execute(
            "SELECT name, drained FROM hosts ORDER BY name")]
        return {"services": svcs, "hosts": hosts}

    def add_dependency(self, service: str, depends_on: str) -> None:
        """Test/eval hook: change the topology out from under a plan (drift)."""
        self.conn.execute("INSERT OR IGNORE INTO deps VALUES (?,?)", (service, depends_on))
