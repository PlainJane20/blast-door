import pytest

from blast_door.auth import AuthConfig
from blast_door.models import Runbook
from blast_door.system import System
from blast_door.verifier import Policy

T0 = 1_800_000_000.0  # fixed, simulated "now" (2027-01-15 UTC)
TOKENS = "alice:alice-secret,bob:bob-secret,carol:carol-secret"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make_system(tmp_path, clock):
    made = []

    def factory(name="sys", **kw):
        kw.setdefault("clock", clock)
        kw.setdefault("auth", AuthConfig.from_string(TOKENS))
        s = System(tmp_path / name, **kw)
        made.append(s)
        return s

    yield factory
    for s in made:
        s.close()


@pytest.fixture
def system(make_system):
    return make_system()


def runbook(*steps, name="rb") -> Runbook:
    """Build a Runbook from (id, tool, params[, depends_on]) tuples."""
    out = []
    for st in steps:
        sid, tool, params, *rest = st
        out.append({"id": sid, "tool": tool, "params": params, "depends_on": rest[0] if rest else []})
    return Runbook.model_validate({"name": name, "steps": out})


def start(system, rb, policy=None, requester="alice", run_id="r1"):
    return system.executor.start(rb, requester, policy or Policy(), run_id=run_id)


def approve_pending(system, who="bob"):
    """Approve every pending approval for the (single) run as `who`."""
    recs = []
    for st in system.store.conn.execute("SELECT id FROM approvals WHERE status='pending'").fetchall():
        recs.append(system.approvals.approve(st[0], f"{who}-secret"))
    return recs
