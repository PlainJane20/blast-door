"""Shared helpers for the evals: metadata and JSON output."""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
ROOT = Path(__file__).resolve().parents[1]


def meta() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    return {"environment": "SIMULATED (in-memory/SQLite fake infrastructure, synthetic data)",
            "python": sys.version.split()[0], "platform": platform.platform(),
            "machine": platform.machine(), "timestamp_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"), "git_commit": commit}


def save(name: str, payload: dict) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    return path


def pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    idx = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]
