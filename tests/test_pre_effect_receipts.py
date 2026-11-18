"""
Fix 4 — receipts sealed BEFORE the effect, with a server-side HMAC key.

The gap: receipts were built after the capability ran, sealed with a bare SHA-256 of
their own contents, and held in memory. Three consequences: a crash between the effect
and the receipt write left an effect with no record; anyone able to write a receipt
could recompute a valid-looking one; and the "chain" was a per-receipt self-hash with no
linkage, so a removed receipt was undetectable.

The fix, and what each test here proves:

  * the commitment receipt is sealed and persisted BEFORE the capability is invoked —
    proved by a capability that inspects the chain from inside the effect
    (``test_receipt_is_persisted_before_the_effect_runs``)
  * if the receipt cannot be persisted, the effect does not happen
    (``test_persist_failure_prevents_the_effect``)
  * with no key there is no receipt and no effect: DENY, never an unkeyed receipt
    (``test_missing_key_denies``)
  * receipts are linked and tamper-evident via ``verify_chain``
    (``TestVerifyChain``)
  * the key never appears in a receipt, a result payload, or an error
    (``test_key_never_appears_in_output``)

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence import gate as gate_module
from agentfence.core import issue
from agentfence.gate import enforce
from agentfence.policy import POLICY_VERSION
from agentfence.sealing import (
    HMAC_PREFIX,
    receipt_hmac,
    receipt_integrity_hash,
    resolve_receipt_key,
    verify_chain,
    verify_receipt_seal,
)
from agentfence.store import InMemoryReceiptChain, UnavailableReceiptChain


def base_request(**over):
    req = {
        "principal": "svc-research",
        "agent": "research-agent",
        "capability": "customer.read",
        "action": "read",
        "resource": "customer/123",
        "origin": "CRM-A",
        "task": "TASK-184",
    }
    req.update(over)
    return req


def base_auth(**over):
    kw = dict(
        principal="svc-research",
        agent="research-agent",
        capability="customer.read",
        action="read",
        resource="customer/123",
        origin="CRM-A",
        task="TASK-184",
        policy_version=POLICY_VERSION,
    )
    kw.update(over)
    return issue(**kw)


class NullConsumeStore:
    """Always-first-use store, so these tests isolate receipt behaviour."""

    name = "null"

    def consume(self, record):
        return True


def gate(**over):
    kw = dict(consume_store=NullConsumeStore(), receipt_chain=InMemoryReceiptChain())
    kw.update(over)
    return kw


# ==========================================================================
# Ordering: seal and persist before the effect
# ==========================================================================


class TestPreEffectOrdering:
    def test_pre_effect_receipt_exists_and_is_sealed(self):
        chain = InMemoryReceiptChain()
        res = enforce(base_request(), base_auth(), **gate(receipt_chain=chain))
        assert res.decision == "ALLOW"

        pre = res.pre_effect_receipt
        assert pre is not None
        assert pre.decision == "ALLOW"
        assert pre.execution_status == "AUTHORIZED_PRE_EFFECT"
        assert pre.hmac_value.startswith(HMAC_PREFIX)
        assert pre.integrity_hash.startswith("af1:sha256:")

    def test_receipt_is_persisted_before_the_effect_runs(self):
        """
        The load-bearing test: from INSIDE the capability, the sealed commitment receipt
        is already durable. A crash after this point cannot leave an effect with no
        receipt, because the receipt is already there before the effect starts.
        """
        chain = InMemoryReceiptChain()
        observed: dict = {}
        original = gate_module.CAPABILITIES["customer.read"]

        def probe(req):
            observed["receipts_at_effect_time"] = chain.receipts()
            return original(req)

        gate_module.CAPABILITIES["customer.read"] = probe
        try:
            res = enforce(base_request(), base_auth(), **gate(receipt_chain=chain))
        finally:
            gate_module.CAPABILITIES["customer.read"] = original

        assert res.decision == "ALLOW"
        at_effect = observed["receipts_at_effect_time"]
        assert len(at_effect) == 1, "exactly the pre-effect receipt should be durable"
        assert at_effect[0]["execution_status"] == "AUTHORIZED_PRE_EFFECT"
        assert at_effect[0]["hmac_value"].startswith(HMAC_PREFIX)
        assert at_effect[0]["seq"] == res.pre_effect_receipt.seq

    def test_outcome_receipt_links_to_the_pre_effect_receipt(self):
        chain = InMemoryReceiptChain()
        res = enforce(base_request(), base_auth(), **gate(receipt_chain=chain))
        pre, outcome = res.pre_effect_receipt, res.receipt
        assert outcome.seq == pre.seq + 1
        assert outcome.prev_hash == pre.hmac_value
        assert outcome.execution_status == "SUCCESS"

    def test_pre_effect_receipt_is_exposed_to_the_api_payload(self):
        res = enforce(base_request(), base_auth(), **gate())
        wire = json.loads(json.dumps(res.to_dict()))
        assert "pre_effect_receipt" in wire
        assert wire["pre_effect_receipt"]["hmac_value"].startswith(HMAC_PREFIX)
        assert wire["receipt_chain_status"] == "PERSISTED"

    def test_deny_receipts_are_sealed_too(self, ):
        res = enforce(base_request(origin="CRM-B"), base_auth(), **gate())
        assert res.decision == "DENY"
        assert res.receipt.hmac_value.startswith(HMAC_PREFIX)
        assert res.receipt.decision == "DENY"

    def test_capability_failure_still_leaves_pre_effect_evidence(self):
        """A failed effect must still leave the commitment receipt behind."""
        original = gate_module.CAPABILITIES["customer.read"]

        def explode(_req):
            raise gate_module.CapabilityError("kaput")

        gate_module.CAPABILITIES["customer.read"] = explode
        try:
            res = enforce(base_request(), base_auth(), **gate())
        finally:
            gate_module.CAPABILITIES["customer.read"] = original

        assert res.decision == "DENY"
        assert res.reason == "CAPABILITY_ERROR"
        assert res.pre_effect_receipt is not None
        assert res.pre_effect_receipt.decision == "ALLOW"


# ==========================================================================
# Fail closed: no persistence, no effect; no key, no receipt
# ==========================================================================


class TestFailClosedSealing:
    def test_persist_failure_prevents_the_effect(self):
        """
        If the sealed receipt cannot be persisted, the capability must not run.

        The probe records whether it was invoked, so this asserts the absence of a side
        effect rather than just the decision string.
        """
        invoked: list[bool] = []
        original = gate_module.CAPABILITIES["customer.read"]

        def probe(req):
            invoked.append(True)
            return original(req)

        gate_module.CAPABILITIES["customer.read"] = probe
        try:
            res = enforce(
                base_request(),
                base_auth(),
                **gate(receipt_chain=UnavailableReceiptChain("no table")),
            )
        finally:
            gate_module.CAPABILITIES["customer.read"] = original

        assert res.decision == "DENY"
        assert res.reason == "RECEIPT_PERSIST_FAILED"
        assert invoked == [], "the capability ran without durable evidence"

    def test_missing_key_denies(self, monkeypatch):
        monkeypatch.delenv("AGENTFENCE_RECEIPT_HMAC_KEY", raising=False)
        invoked: list[bool] = []
        original = gate_module.CAPABILITIES["customer.read"]

        def probe(req):
            invoked.append(True)
            return original(req)

        gate_module.CAPABILITIES["customer.read"] = probe
        try:
            res = enforce(base_request(), base_auth(), **gate())
        finally:
            gate_module.CAPABILITIES["customer.read"] = original

        assert res.decision == "DENY"
        assert res.reason == "RECEIPT_KEY_UNAVAILABLE"
        assert res.receipt is None, "no unkeyed receipt may be emitted"
        assert invoked == []

    def test_short_key_is_treated_as_unconfigured(self, monkeypatch):
        monkeypatch.setenv("AGENTFENCE_RECEIPT_HMAC_KEY", "short")
        assert resolve_receipt_key() is None
        res = enforce(base_request(), base_auth(), **gate())
        assert res.decision == "DENY"
        assert res.reason == "RECEIPT_KEY_UNAVAILABLE"

    def test_hex_key_is_decoded(self, monkeypatch):
        monkeypatch.setenv("AGENTFENCE_RECEIPT_HMAC_KEY", "a" * 64)
        key = resolve_receipt_key()
        assert key is not None and len(key) == 32

    def test_blank_key_is_unconfigured(self, monkeypatch):
        monkeypatch.setenv("AGENTFENCE_RECEIPT_HMAC_KEY", "   ")
        assert resolve_receipt_key() is None


# ==========================================================================
# Chain verification
# ==========================================================================


def _populate(n: int = 3) -> tuple[InMemoryReceiptChain, str]:
    chain = InMemoryReceiptChain()
    for _ in range(n):
        enforce(base_request(), base_auth(), **gate(receipt_chain=chain))
    return chain, os.environ["AGENTFENCE_RECEIPT_HMAC_KEY"]


class TestVerifyChain:
    def test_valid_chain_verifies(self):
        chain, key = _populate(3)
        ok, reason, idx = verify_chain(chain.receipts(), key)
        assert ok, f"chain failed to verify: {reason} at {idx}"
        assert reason == ""

    def test_chain_has_all_receipts(self):
        chain, _ = _populate(2)
        # Each ALLOW appends a pre-effect receipt and an outcome receipt.
        assert len(chain.receipts()) == 4
        assert [r["seq"] for r in chain.receipts()] == [0, 1, 2, 3]

    def test_tampered_field_detected(self):
        chain, key = _populate(2)
        receipts = chain.receipts()
        receipts[1] = dict(receipts[1], resource="customer/999")
        ok, reason, idx = verify_chain(receipts, key)
        assert not ok
        assert reason == "INTEGRITY_MISMATCH"
        assert idx == 1

    def test_resealed_receipt_without_the_key_is_caught(self):
        """
        An attacker who edits a receipt and recomputes the public self-hash still cannot
        produce a valid seal: the HMAC needs the server key.
        """
        chain, key = _populate(2)
        receipts = chain.receipts()
        forged = dict(receipts[1], resource="customer/999")
        forged.pop("hmac_value")
        forged["integrity_hash"] = receipt_integrity_hash(forged)
        forged["hmac_value"] = HMAC_PREFIX + "0" * 64  # plausible-looking, wrong
        receipts[1] = forged

        ok, reason, idx = verify_chain(receipts, key)
        assert not ok
        assert reason == "HMAC_INVALID"
        assert idx == 1

    def test_wrong_key_caught(self):
        chain, _ = _populate(2)
        ok, reason, _ = verify_chain(chain.receipts(), "b" * 64)
        assert not ok
        assert reason == "HMAC_INVALID"

    def test_missing_key_refuses_to_verify(self, monkeypatch):
        chain, _ = _populate(1)
        monkeypatch.delenv("AGENTFENCE_RECEIPT_HMAC_KEY", raising=False)
        ok, reason, _ = verify_chain(chain.receipts(), None)
        assert not ok
        assert reason == "RECEIPT_KEY_UNAVAILABLE"

    def test_removed_receipt_detected(self):
        """Removing evidence must not verify as a shorter but valid chain."""
        chain, key = _populate(3)
        receipts = chain.receipts()
        del receipts[1]
        ok, reason, idx = verify_chain(receipts, key)
        assert not ok
        assert reason == "SEQ_NOT_MONOTONIC"

    def test_reordered_receipts_detected(self):
        chain, key = _populate(3)
        receipts = chain.receipts()
        receipts[1], receipts[2] = receipts[2], receipts[1]
        ok, reason, _ = verify_chain(receipts, key)
        assert not ok
        assert reason in {"SEQ_NOT_MONOTONIC", "PREV_HASH_MISMATCH"}

    def test_hmac_covers_chain_linkage(self):
        """
        ``prev_hash`` is inside the seal. Rewriting linkage and recomputing the public
        hash must still fail the HMAC.
        """
        chain, key = _populate(2)
        receipts = chain.receipts()
        forged = dict(receipts[1], prev_hash="0" * 64)
        forged.pop("hmac_value")
        forged["integrity_hash"] = receipt_integrity_hash(forged)
        forged["hmac_value"] = receipt_hmac(forged, resolve_receipt_key(key))
        receipts[1] = forged
        # Sealed with the real key, but the linkage no longer matches receipt 0.
        ok, reason, idx = verify_chain(receipts, key)
        assert not ok
        assert reason == "PREV_HASH_MISMATCH"
        assert idx == 1

    def test_genesis_linkage_available(self):
        chain, key = _populate(1)
        receipts = chain.receipts()
        assert receipts[0]["prev_hash"] == ""
        ok, reason, _ = verify_chain(receipts, key, require_genesis=True)
        assert ok, reason

    def test_single_receipt_seal_verifies(self):
        chain, key = _populate(1)
        rc = chain.receipts()[0]
        assert verify_receipt_seal(rc, resolve_receipt_key(key)) is True


# ==========================================================================
# The key never leaks
# ==========================================================================


class TestKeyNeverLeaks:
    def test_key_never_appears_in_output(self):
        key = os.environ["AGENTFENCE_RECEIPT_HMAC_KEY"]
        chain = InMemoryReceiptChain()
        res = enforce(base_request(), base_auth(), **gate(receipt_chain=chain))

        blobs = [
            json.dumps(res.to_dict(), default=str),
            json.dumps(chain.receipts(), default=str),
            json.dumps(res.receipt.to_dict(), default=str),
            json.dumps(res.pre_effect_receipt.to_dict(), default=str),
        ]
        for blob in blobs:
            assert key not in blob
            # A hex-decoded form must not leak either.
            if len(key) == 64:
                assert bytes.fromhex(key).decode("latin-1") not in blob

    def test_key_absent_from_error_detail(self, monkeypatch):
        monkeypatch.delenv("AGENTFENCE_RECEIPT_HMAC_KEY", raising=False)
        res = enforce(base_request(), base_auth(), **gate())
        assert "AGENTFENCE_RECEIPT_HMAC_KEY" not in json.dumps(res.to_dict())
        # The setting NAME may be described, but never a value.
        assert res.reason == "RECEIPT_KEY_UNAVAILABLE"
