"""Build the Lambda deployment package for AgentFence.

Portable replacement for `zip` so packaging works on Windows, macOS and Linux
(the AWS console upload path needs a real .zip).

Layout inside the archive — web/ MUST be included, because the Lambda serves
index.html itself. That is how the demo runs on a single origin with no CORS:

    agentfence/__init__.py
    agentfence/api.py        <- handler: agentfence.api.lambda_handler
    agentfence/core.py
    agentfence/gate.py
    agentfence/policy.py
    web/index.html           <- the single-page demo

Usage:
    python scripts/package.py            # builds ./function.zip
"""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "function.zip"

INCLUDE_DIRS = ["agentfence", "web"]
INCLUDE_FILES: list[str] = []  # runtime has zero third-party deps
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".venv", "venv", "node_modules", ".aws"}


def main() -> int:
    init = ROOT / "agentfence" / "__init__.py"
    if not init.exists():
        init.write_text('"""AgentFence — authorization-bound execution for AI agents."""\n', encoding="utf-8")

    if OUT.exists():
        OUT.unlink()

    added = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for d in INCLUDE_DIRS:
            base = ROOT / d
            if not base.is_dir():
                print(f"ERROR: missing directory {base}", file=sys.stderr)
                return 1
            for p in sorted(base.rglob("*")):
                if not p.is_file() or p.is_symlink():
                    continue
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                if p.suffix == ".pyc":
                    continue
                z.write(p, p.relative_to(ROOT).as_posix())
                added += 1
        for f in INCLUDE_FILES:
            p = ROOT / f
            if p.is_file():
                z.write(p, p)
                added += 1

    size = OUT.stat().st_size
    print(f"built {OUT.name}  ({added} files, {size:,} bytes)")
    with zipfile.ZipFile(OUT) as z:
        for n in z.namelist():
            print("  ", n)

    # Fail loudly if the handler or the page is missing — both are required.
    names = set(zipfile.ZipFile(OUT).namelist())
    required = {"agentfence/api.py", "agentfence/core.py", "agentfence/gate.py",
                "agentfence/policy.py", "web/index.html"}
    missing = required - names
    if missing:
        print(f"ERROR: package is missing {sorted(missing)}", file=sys.stderr)
        return 1
    print("\nverified: handler modules + web/index.html present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
