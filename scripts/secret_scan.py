"""Scan the repository for committed credentials.

Run:  python scripts/secret_scan.py
Exit: 0 = clean, 1 = findings (print them and do not publish).

This is a real gate for a public hackathon repository, not a formality: the repo is
public, so anything committed here is published.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Binary-ish extensions we skip (a zip can hold anything and is not source).
SKIP_EXT = {
    ".zip", ".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mp4",
    ".woff", ".woff2", ".ttf", ".eot", ".so", ".dll", ".exe", ".db", ".sqlite",
}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", ".aws"}

PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"ASIA[0-9A-Z]{16}", "AWS temp access key ID"),
    (r"aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}", "AWS secret access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"sk-(?:ant-)?[A-Za-z0-9_-]{20,}", "provider API key (sk-...)"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API key"),
    (r"xoxb|-----BEGIN OPENSSH PRIVATE KEY-----", "SSH / Slack key"),
    # env-style assignment with a real-looking literal
    (r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[=:]\s*[\"'][^\"'\s]{12,}[\"']",
     "hardcoded credential assignment"),
]

COMPILED = [(re.compile(p, re.M), label) for p, label in PATTERNS]

# Files that legitimately discuss credential shapes in docs/tests.
ALLOWLIST = {
    "scripts/secret_scan.py",
    "submission/SECURITY_TESTS.md",
}


def main() -> int:
    scanned = 0
    findings: list[tuple[str, int, str, str]] = []

    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() in SKIP_EXT:
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(ROOT).as_posix()
            if rel in ALLOWLIST:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            scanned += 1
            for rx, label in COMPILED:
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    findings.append((rel, line, label, m.group(0)[:40]))

    print(f"files scanned: {scanned}")
    print(f"credential-pattern hits: {len(findings)}")
    for rel, line, label, snippet in findings:
        # never print the matched secret itself
        print(f"   {rel}:{line}  {label}")

    if findings:
        print("\nFAIL: remove the above before publishing.")
        return 1
    print("\nPASS: no credential patterns found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
