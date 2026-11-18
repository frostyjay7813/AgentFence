"""Mint a caller credential for the AgentFence API — operator tool, not a service.

Since the authorization-boundary hardening, ``POST /api/authorize``,
``GET /api/state``, ``GET /api/expire`` and ``POST /api/approve`` require an
authenticated caller. This script is how an operator obtains one.

The signing secret is read from the environment and is never written, printed, or
committed. If it is absent the script refuses to run: there is no local default and no
development bypass, because a default secret would be a published key.

Usage:
    export AGENTFENCE_AUTH_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
    python scripts/mint_credential.py svc-research
    python scripts/mint_credential.py human.jay --ttl-seconds 600

    # then open the demo with the credential:
    #   http://127.0.0.1:8099/?token=<printed token>
    #   http://127.0.0.1:8099/?token=<svc token>&approver_token=<human token>

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.auth import ENV_AUTH_SECRET, MAX_CREDENTIAL_TTL_MS, sign_credential  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Mint an AgentFence caller credential.")
    ap.add_argument("principal", help="principal the credential is for, e.g. svc-research")
    ap.add_argument(
        "--ttl-seconds",
        type=int,
        default=300,
        help=f"credential lifetime in seconds (max {MAX_CREDENTIAL_TTL_MS // 1000})",
    )
    args = ap.parse_args(argv)

    if not os.environ.get(ENV_AUTH_SECRET, "").strip():
        print(
            f"{ENV_AUTH_SECRET} is not set. Generate one and export it, e.g.\n"
            f'  export {ENV_AUTH_SECRET}="$(python -c '
            "'import secrets;print(secrets.token_hex(32))')\"",
            file=sys.stderr,
        )
        return 2

    ttl_ms = max(1, args.ttl_seconds) * 1000
    # sign_credential reads the secret itself; passing nothing here keeps the value out
    # of this process's argument list and out of any shell history.
    token = sign_credential(args.principal, secret=os.environ[ENV_AUTH_SECRET], ttl_ms=ttl_ms)
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
