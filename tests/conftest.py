"""
Shared test configuration for the authorization-boundary hardening.

Two rules this file exists to enforce:

1. **No key material in the repository.** The receipt-sealing key and the credential
   signing secret are generated with ``secrets.token_hex(32)`` at test time and live
   only in the process environment for the duration of a test. There is no fixture
   constant to copy, no ``.env`` file, and nothing to redact from a published log.

2. **Tests do not leak state into each other.** Single-use consumption and the receipt
   chain are process-local singletons by design (a per-call store would make single-use
   a fiction), so each test starts from a clean store. Isolation here is what lets the
   replay tests assert a second use is denied without depending on test ordering.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence import store as store_module  # noqa: E402


@pytest.fixture(scope="session")
def receipt_key() -> str:
    """Ephemeral HMAC key for receipt sealing. Different on every test run."""
    return secrets.token_hex(32)


@pytest.fixture(scope="session")
def auth_secret() -> str:
    """Ephemeral credential signing secret. Different on every test run."""
    return secrets.token_hex(32)


@pytest.fixture(autouse=True)
def boundary_env(monkeypatch, receipt_key, auth_secret):
    """
    Configure the boundary for every test.

    Autouse so that no test can accidentally run against an unconfigured boundary and
    silently assert the wrong thing (e.g. that a missing key yields ALLOW).
    """
    monkeypatch.setenv("AGENTFENCE_RECEIPT_HMAC_KEY", receipt_key)
    monkeypatch.setenv("AGENTFENCE_AUTH_SECRET", auth_secret)
    monkeypatch.setenv("AGENTFENCE_MODE", "DEMO")
    monkeypatch.delenv("AGENTFENCE_CONSUME_TABLE", raising=False)
    monkeypatch.delenv("AGENTFENCE_RECEIPT_TABLE", raising=False)
    monkeypatch.delenv("AGENTFENCE_CLOCK_SKEW_MS", raising=False)
    store_module.reset_default_stores()
    yield
    store_module.reset_default_stores()
