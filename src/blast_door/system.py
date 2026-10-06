"""Wires the store, simulated environment, audit log, approvals and executor together."""
from __future__ import annotations

import time
from pathlib import Path

from .approvals import ApprovalService
from .audit import AuditLog
from .auth import AuthConfig
from .executor import Executor, hard_exit
from .models import Runbook
from .planner import Planner, RuleBasedPlanner
from .sim_env import SimEnv
from .store import RunStore
from .tools import ToolRegistry
from .verifier import Policy


class System:
    def __init__(self, state_dir: str | Path, *, clock=time.time, auth: AuthConfig | None = None,
                 planner: Planner | None = None, crash_at: str | None = None,
                 crash_handler=hard_exit, idempotency: bool = True,
                 registry: ToolRegistry | None = None, topology: dict | None = None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.registry = registry or ToolRegistry.default()
        self.env = SimEnv(self.state_dir / "env.db", clock=clock, topology=topology)
        self.store = RunStore(self.state_dir / "runs.db")
        self.audit = AuditLog(self.store, clock=clock)
        self.auth = auth or AuthConfig()
        self.approvals = ApprovalService(self.store, self.audit, self.auth, clock=clock)
        self.executor = Executor(self.store, self.env, self.registry, self.audit, self.approvals,
                                 planner or RuleBasedPlanner(), clock=clock, crash_at=crash_at,
                                 crash_handler=crash_handler, idempotency=idempotency)

    def load_runbook(self, path: str | Path) -> Runbook:
        return Runbook.from_file(path, self.registry.names())

    def close(self) -> None:
        self.env.close()
        self.store.close()
