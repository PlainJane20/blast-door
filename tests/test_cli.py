import json
from pathlib import Path

import pytest

from runbook_autopilot.cli import main

EX = Path(__file__).resolve().parents[1] / "examples"
POLICY = str(EX / "policy.yaml")


@pytest.fixture(autouse=True)
def tokens(monkeypatch):
    monkeypatch.setenv("RUNBOOK_OPERATOR_TOKENS", "alice:alice-secret,bob:bob-secret")
    monkeypatch.delenv("RUNBOOK_CRASH_AT", raising=False)
    monkeypatch.delenv("RUNBOOK_TOKEN", raising=False)


def cli(tmp_path, *args):
    return main(["--state-dir", str(tmp_path), *args])


def test_safe_example_completes(tmp_path, capsys):
    assert cli(tmp_path, "run", str(EX / "safe_restart.yaml"), "--policy", POLICY) == 0
    assert "status=completed" in capsys.readouterr().out


def test_denied_example_exits_1_and_changes_nothing(tmp_path, capsys):
    assert cli(tmp_path, "run", str(EX / "unsafe_denied.yaml"), "--policy", POLICY,
               "--run-id", "u") == 1
    out = capsys.readouterr().out
    assert "status=denied" in out and "blast_radius_exceeded" in out
    capsys.readouterr()
    cli(tmp_path, "status", "u", "--json")
    assert json.loads(capsys.readouterr().out)["ledger_entries"] == 0


def test_protected_example_full_approval_flow(tmp_path, capsys):
    assert cli(tmp_path, "run", str(EX / "protected_needs_approval.yaml"), "--policy", POLICY,
               "--as", "alice", "--token", "alice-secret", "--run-id", "p") == 3
    capsys.readouterr()
    cli(tmp_path, "status", "p", "--json")
    aid = json.loads(capsys.readouterr().out)["approvals"][0]["id"]
    assert cli(tmp_path, "approve", aid, "--as", "alice", "--token", "alice-secret") == 1   # self
    assert cli(tmp_path, "resume", "p") == 3
    assert cli(tmp_path, "approve", aid, "--as", "bob", "--token", "bob-secret") == 0
    assert cli(tmp_path, "resume", "p") == 0
    assert cli(tmp_path, "verify-audit") == 0
    assert "audit chain OK" in capsys.readouterr().out


def test_approve_uses_env_token(tmp_path, capsys, monkeypatch):
    cli(tmp_path, "run", str(EX / "protected_needs_approval.yaml"), "--as", "alice",
        "--token", "alice-secret", "--run-id", "p")
    capsys.readouterr()
    cli(tmp_path, "status", "p", "--json")
    aid = json.loads(capsys.readouterr().out)["approvals"][0]["id"]
    monkeypatch.setenv("RUNBOOK_TOKEN", "bob-secret")
    assert cli(tmp_path, "approve", aid, "--as", "bob") == 0


def test_wrong_token_for_claimed_identity_is_rejected(tmp_path):
    cli(tmp_path, "run", str(EX / "protected_needs_approval.yaml"), "--as", "alice",
        "--token", "alice-secret", "--run-id", "p")
    assert cli(tmp_path, "approve", "ap-anything", "--as", "bob", "--token", "alice-secret") == 1


def test_run_with_bad_requester_token_exits_2(tmp_path):
    assert cli(tmp_path, "run", str(EX / "safe_restart.yaml"), "--as", "alice",
               "--token", "nope") == 2


def test_cycle_runbook_rejected_with_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nsteps:\n  - {id: a, tool: list_services, depends_on: [b]}\n"
                   "  - {id: b, tool: list_services, depends_on: [a]}\n")
    assert cli(tmp_path / "s", "run", str(bad)) == 2
    assert "cycle" in capsys.readouterr().err


def test_unknown_tool_runbook_rejected_with_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nsteps:\n  - {id: a, tool: format_disk}\n")
    assert cli(tmp_path / "s", "run", str(bad)) == 2
    assert "unknown_tool" in capsys.readouterr().err


def test_status_unknown_run(tmp_path):
    assert cli(tmp_path, "status", "nope") == 2


def test_resume_unknown_run(tmp_path):
    assert cli(tmp_path, "resume", "nope") == 2


def test_verify_audit_detects_tampering(tmp_path, capsys):
    import sqlite3
    cli(tmp_path, "run", str(EX / "safe_restart.yaml"), "--run-id", "s")
    con = sqlite3.connect(tmp_path / "runs.db")
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit SET data='{}' WHERE seq=3")
    con.commit()
    con.close()
    assert cli(tmp_path, "verify-audit") == 1
    assert "BROKEN at record 2" in capsys.readouterr().err


def test_change_freeze_via_now_flag(tmp_path):
    pol = tmp_path / "freeze.yaml"
    pol.write_text("change_freeze:\n  - {start: 2030-01-01T00:00:00Z, end: 2030-01-02T00:00:00Z}\n")
    assert main(["--state-dir", str(tmp_path / "a"), "--now", "2030-01-01T12:00:00Z", "run",
                 str(EX / "safe_restart.yaml"), "--policy", str(pol)]) == 1
    assert main(["--state-dir", str(tmp_path / "b"), "--now", "2030-02-01T12:00:00Z", "run",
                 str(EX / "safe_restart.yaml"), "--policy", str(pol)]) == 0
