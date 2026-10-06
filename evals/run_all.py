"""Run all three evals and save JSON to evals/results/. One command:

    python -m evals.run_all

Exits non-zero if the crash matrix is below 100%, any unsafe case is missed, or
any safe control is blocked. Those are regression gates for CI on a corpus the
author wrote, not a claim about real-world performance.
"""
from __future__ import annotations

import sys

from . import crash_matrix, latency, unsafe_corpus
from .common import save


def main() -> int:
    rc = 0
    rc |= crash_matrix.main()
    rc |= unsafe_corpus.main()
    rc |= latency.main()
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
