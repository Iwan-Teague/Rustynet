#!/usr/bin/env python3
"""Compatibility wrapper for Rust fresh-install OS-matrix report generation.

Security hardening note:
- Report generation logic is implemented only in rustynet-cli ops.
- This wrapper preserves legacy script usage while forcing the Rust path.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root_dir = Path(__file__).resolve().parents[2]
    command = [
        "cargo",
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--",
        "ops",
        "generate-linux-fresh-install-os-matrix-report",
        *sys.argv[1:],
    ]
    return subprocess.call(command, cwd=str(root_dir))


if __name__ == "__main__":
    raise SystemExit(main())
