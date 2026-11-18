"""
Fix 3 — single-use, expiring authorizations.

The gap: nothing consumed an authorization. A captured authorization replayed freely,
for as long as its validity window lasted. The existing suite did not catch this, and
one test was actively misleading: ``test_recomputed_hash_without_secret_is_still_caught``
only shows that a re-sealed authorization fails against an *unchanged* request. An
attacker who mints both sides consistently is invisible to the gate. That test is kept
(it still proves the binding layer) but it is NOT replay protection, and the replay tests
below are what actually establish the property.

What must hold, and where it is proved:

  * first use succeeds, every later use is DENY/AUTHORIZATION_ALREADY_CONSUMED
    (``TestConsumeOnce``)
  * consumption is atomic under concurrency — within the guarantee the store can make
    (``TestStoreAtomicity``)
  * a store that cannot answer produces DENY, never allow
    (``TestFailClosedStores``)
  * a production mode with no store configured DENY
    (``test_production_mode_without_store_denies``)
  * clock skew is explicit and can only narrow the window
    (``TestClockSkew``)

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.api import lambda_handler
from agentfence.auth import sign_credential
from agentfence.core import Authorization, check_validity, integrity, issue
from agentfence.gate import enforce
from agentfence.policy import POLICY_VERSION, create_approval
from agentfence.store import (
    ConsumeRecord,
    DynamoDBConsumeStore,
    InMemoryConsumeStore,
    StoreUnavailable,
    resolve_consume_store,
    resolve_receipt_chain,
)


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


def base_auth(ttl_ms: int = 900_000, **over):
    kw = dict(
        principal="svc-research",
        agent="research-agent",
        capability="customer.read",
        action="read",
        resource="customer/123",
        origin="CRM-A",
        task="TASK-184",
        policy_version=POLICY_VERSION,
        ttl_ms=ttl_ms,
    )
    kw.update(over)
    return issue(**kw)


def write_auth():
    return issue(
        principal="svc-research", agent="research-agent", capability="customer.write",
        action="write", resource="customer/123", origin="CRM-A", task="TASK-184",
        policy_version=POLICY_VERSION,
    )


def write_request():
    return base_request(capability="customer.write", action="write")


# ==========================================================================
# Consume once
# ==========================================================================


class TestConsumeOnce:
    def test_first_use_allowed(self):
        res = enforce(base_request(), base_auth())
        assert res.decision == "ALLOW"
        assert res.receipt_consume_status == "CONSUMED"

    def test_second_use_denied(self):
        """The headline property: an authorization is spent by its first use."""
        auth = base_auth()
        first = enforce(base_request(), auth)
        assert first.decision == "ALLOW"

        second = enforce(base_request(), auth)
        assert second.decision == "DENY"
        assert second.reason == "AUTHORIZATION_ALREADY_CONSUMED"
        assert second.stage == "11-consume"
        assert second.receipt.execution_status == "NOT_EXECUTED"
        assert second.receipt_consume_status == "ALREADY_CONSUMED"

    def test_second_use_returns_no_result(self):
        auth = base_auth()
        enforce(base_request(), auth)
        second = enforce(base_request(), auth)
        assert second.result is None

    def test_many_replays_all_denied(self):
        auth = base_auth()
        assert enforce(base_request(), auth).decision == "ALLOW"
        for _ in range(5):
            replay = enforce(base_request(), auth)
            assert replay.decision == "DENY"
            assert replay.reason == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_replay_with_fresh_approval_still_denied(self):
        """A new approval does not resurrect a spent authorization."""
        auth = write_auth()
        ap1 = create_approval(auth, approver="human.jay")
        first = enforce(write_request(), auth, approval=ap1)
        assert first.decision == "ALLOW"

        ap2 = create_approval(auth, approver="human.jay")
        replay = enforce(write_request(), auth, approval=ap2)
        assert replay.decision == "DENY"
        assert replay.reason == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_json_round_trip_replay_denied(self):
        """A captured authorization replayed as raw JSON is the same denial."""
        auth = base_auth()
        wire = json.loads(json.dumps(auth.to_dict()))
        assert enforce(base_request(), wire).decision == "ALLOW"
        replay = enforce(base_request(), wire)
        assert replay.decision == "DENY"
        assert replay.reason == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_denied_request_does_not_consume(self):
        """
        A rejected request must not burn the authorization: consumption is a commit,
        not a side effect of being looked at.
        """
        auth = base_auth()
        bad = base_request(origin="CRM-B")
        denied = enforce(bad, auth)
        assert denied.decision == "DENY"
        assert denied.reason == "ORIGIN_MISMATCH"

        good = enforce(base_request(), auth)
        assert good.decision == "ALLOW", f"denial consumed the authorization: {good.reason}"

    def test_policy_denial_does_not_consume(self):
        auth = issue(
            principal="svc-research", agent="research-agent", capability="customer.delete",
            action="delete", resource="customer/123", origin="CRM-A", task="TASK-184",
            policy_version=POLICY_VERSION,
        )
        denied = enforce(base_request(capability="customer.delete", action="delete"), auth)
        assert denied.decision == "DENY"
        assert denied.reason == "POLICY_DENY"

        # Reuse the same authorization for the read it also cannot do -> still not consumed.
        again = enforce(base_request(), auth)
        assert again.reason != "AUTHORIZATION_ALREADY_CONSUMED"

    def test_missing_approval_does_not_consume(self):
        auth = write_auth()
        denied = enforce(write_request(), auth)
        assert denied.reason == "APPROVAL_MISSING"

        ap = create_approval(auth, approver="human.jay")
        assert enforce(write_request(), auth, approval=ap).decision == "ALLOW"

    def test_expired_authorization_never_consumed(self):
        auth = base_auth(ttl_ms=1)
        import time

        time.sleep(0.02)
        res = enforce(base_request(), auth)
        assert res.decision == "DENY"
        assert res.reason == "AUTHORIZATION_EXPIRED"
        # And it is still refused for the same reason, not for being consumed.
        again = enforce(base_request(), auth)
        assert again.reason == "AUTHORIZATION_EXPIRED"

    def test_capability_failure_spends_the_authorization(self):
        """
        A capability fault is a use: the authorization was committed and executed. It is
        not re-useable, which is the conservative choice (a failure must not hand the
        caller a retry token).
        """
        from agentfence import gate as gate_module

        original = gate_module.CAPABILITIES["customer.read"]

        def explode(_req):
            raise gate_module.CapabilityError("boom")

        gate_module.CAPABILITIES["customer.read"] = explode
        try:
            auth = base_auth()
            first = enforce(base_request(), auth)
            assert first.decision == "DENY"
            assert first.reason == "CAPABILITY_ERROR"
        finally:
            gate_module.CAPABILITIES["customer.read"] = original

        second = enforce(base_request(), auth)
        assert second.decision == "DENY"
        assert second.reason == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_replay_over_http_denied(self):
        token = sign_credential("svc-research", secret=os.environ["AGENTFENCE_AUTH_SECRET"])
        headers = {"Authorization": f"Bearer {token}"}
        state = json.loads(
            lambda_handler(
                {"httpMethod": "GET", "path": "/api/state", "body": None, "headers": headers},
                None,
            )["body"]
        )
        event = {
            "httpMethod": "POST",
            "path": "/api/execute",
            "body": json.dumps(
                {"request": state["scenario"], "authorization": state["authorization"]}
            ),
            "headers": {},
        }
        first = json.loads(lambda_handler(event, None)["body"])
        assert first["decision"] == "ALLOW"

        second = json.loads(lambda_handler(event, None)["body"])
        assert second["decision"] == "DENY"
        assert second["reason"] == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_documented_limitation_consistently_minted_authorization(self):
        """
        Honest statement of what the gate can and cannot see.

        An attacker who mints BOTH the authorization and the request consistently is
        indistinguishable to this gate: integrity() is a checksum, not a signature. That
        is why integrity cannot be the replay defence. What this branch adds is the
        *bound* on the damage: such an authorization is still single-use, and minting one
        now requires an authenticated caller at issuance (tests/test_auth_boundary.py).

        This test asserts the real, current behaviour rather than a claim.
        """
        auth = base_auth()
        tampered = auth.to_dict()
        tampered["resource"] = "customer/999"
        forged = Authorization.from_dict(tampered)
        forged.integrity_value = integrity(forged.integrity_payload())

        req = base_request(resource="customer/999")
        first = enforce(req, forged)
        assert first.decision == "ALLOW"  # the gate genuinely cannot tell

        second = enforce(req, forged)
        assert second.decision == "DENY"
        assert second.reason == "AUTHORIZATION_ALREADY_CONSUMED"  # ...but only once


# ==========================================================================
# Store atomicity, stated honestly
# ==========================================================================


class TestStoreAtomicity:
    def test_in_memory_store_is_thread_safe(self):
        """Exactly one concurrent consumer may win."""
        store = InMemoryConsumeStore()
        record = ConsumeRecord(
            authorization_id="AUTH-RACE", consumed_at_ms=1, expires_at_ms=10**13
        )
        wins: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait()
            got = store.consume(record)
            with lock:
                wins.append(got)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert wins.count(True) == 1, f"expected exactly one winner, got {wins.count(True)}"
        assert wins.count(False) == 15

    def test_in_memory_store_documents_its_limitation(self):
        """
        The atomicity claim must be honest in the code, not just in a review comment.

        The in-memory store can only guarantee single-use within one process. If that
        caveat is ever softened or deleted from the docstring, this fails — which is the
        point: an overstated atomicity claim is how a reviewer gets misled.
        """
        doc = InMemoryConsumeStore.__doc__ or ""
        lowered = doc.lower()
        assert "one process" in lowered
        assert "two processes" in lowered
        assert "not sufficient" in lowered

    def test_concurrent_gate_calls_only_one_allows(self):
        auth = base_auth()
        results: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            res = enforce(base_request(), auth)
            with lock:
                results.append(res.reason or res.decision)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count("ALLOW") == 1, results
        assert results.count("AUTHORIZATION_ALREADY_CONSUMED") == 7, results


# ==========================================================================
# Fail closed when the store cannot answer
# ==========================================================================


class _ConditionalCheckFailed(Exception):
    """Mimics boto3.dynamodb.exceptions.ConditionalCheckFailedException by name."""


_ConditionalCheckFailed.__name__ = "ConditionalCheckFailedException"


class FakeTable:
    def __init__(self, behaviour: str = "ok"):
        self.behaviour = behaviour
        self.items: dict = {}

    def put_item(self, Item, ConditionExpression=None):
        if self.behaviour == "conditional":
            # The item already exists -> the conditional write loses.
            raise _ConditionalCheckFailed()
        if self.behaviour == "boom":
            raise RuntimeError("network partition")
        self.items[Item["pk"]] = Item
        return {}


class TestFailClosedStores:
    def test_unavailable_store_denies(self):
        from agentfence.store import UnavailableConsumeStore

        store = UnavailableConsumeStore("test: no table")
        res = enforce(base_request(), base_auth(), consume_store=store)
        assert res.decision == "DENY"
        assert res.reason == "CONSUME_STORE_UNAVAILABLE"
        assert res.receipt_consume_status.startswith("UNAVAILABLE")

    def test_store_raising_is_a_denial_not_an_allow(self):
        class ExplodingStore:
            name = "exploding"

            def consume(self, record):
                raise RuntimeError("kaboom")

        res = enforce(base_request(), base_auth(), consume_store=ExplodingStore())
        assert res.decision == "DENY"
        assert res.reason == "CONSUME_STORE_UNAVAILABLE"
        assert res.result is None

    def test_production_mode_without_store_denies(self, monkeypatch):
        """
        A production deployment with no consumption store must DENY, not quietly fall
        back to the weaker process-local store.
        """
        monkeypatch.delenv("AGENTFENCE_CONSUME_TABLE", raising=False)
        store = resolve_consume_store("LIVE")
        assert store.name == "unavailable"

        res = enforce(base_request(), base_auth(), mode="LIVE", consume_store=store)
        assert res.decision == "DENY"
        assert res.reason == "CONSUME_STORE_UNAVAILABLE"

    def test_production_mode_without_receipt_chain_denies(self, monkeypatch):
        monkeypatch.delenv("AGENTFENCE_RECEIPT_TABLE", raising=False)
        chain = resolve_receipt_chain("LIVE")
        assert chain.name == "unavailable"

        res = enforce(base_request(), base_auth(), receipt_chain=chain)
        assert res.decision == "DENY"
        assert res.reason == "RECEIPT_PERSIST_FAILED"

    def test_demo_mode_defaults_to_memory(self, monkeypatch):
        monkeypatch.delenv("AGENTFENCE_CONSUME_TABLE", raising=False)
        assert resolve_consume_store("DEMO").name == "memory"

    def test_dynamodb_conditional_failure_means_already_consumed(self):
        store = DynamoDBConsumeStore("t", table=FakeTable("conditional"))
        record = ConsumeRecord(authorization_id="AUTH-X", consumed_at_ms=1, expires_at_ms=10**13)
        assert store.consume(record) is False

        res = enforce(base_request(), base_auth(), consume_store=store)
        assert res.decision == "DENY"
        assert res.reason == "AUTHORIZATION_ALREADY_CONSUMED"

    def test_dynamodb_first_write_wins(self):
        table = FakeTable("ok")
        store = DynamoDBConsumeStore("t", table=table)
        record = ConsumeRecord(authorization_id="AUTH-Y", consumed_at_ms=1, expires_at_ms=10**13)
        assert store.consume(record) is True
        assert "AUTHZ#AUTH-Y" in table.items

    def test_dynamodb_fault_is_unavailable(self):
        store = DynamoDBConsumeStore("t", table=FakeTable("boom"))
        record = ConsumeRecord(authorization_id="AUTH-Z", consumed_at_ms=1, expires_at_ms=10**13)
        with pytest.raises(StoreUnavailable) as exc:
            store.consume(record)
        assert exc.value.code == "CONSUME_STORE_UNAVAILABLE"

        res = enforce(base_request(), base_auth(), consume_store=store)
        assert res.decision == "DENY"
        assert res.reason == "CONSUME_STORE_UNAVAILABLE"


# ==========================================================================
# Clock skew
# ==========================================================================


class TestClockSkew:
    def _auth(self, issued_at=0, expires_at=1000):
        a = base_auth()
        a.issued_at = issued_at
        a.expires_at = expires_at
        a.integrity_value = integrity(a.integrity_payload())
        return a

    def test_zero_skew_preserves_original_boundary(self):
        auth = self._auth()
        assert check_validity(auth, 1000) is None  # t == expires_at is still valid
        d = check_validity(auth, 1001)
        assert d is not None and d.reason == "AUTHORIZATION_EXPIRED"

    def test_skew_narrows_the_window_only(self):
        auth = self._auth()
        # 995 is inside the window with no skew, outside it with 10ms of skew.
        assert check_validity(auth, 995) is None
        d = check_validity(auth, 995, skew_ms=10)
        assert d is not None and d.reason == "AUTHORIZATION_EXPIRED"

    def test_negative_skew_is_clamped_and_never_widens(self):
        auth = self._auth()
        d = check_validity(auth, 1001, skew_ms=-50_000)
        assert d is not None and d.reason == "AUTHORIZATION_EXPIRED"

    def test_env_configured_skew_applies_at_the_gate(self, monkeypatch):
        """
        Skew is configurable per deployment and is applied at the gate. Configured
        generously it makes an authorization expire EARLIER, never later.
        """
        monkeypatch.setenv("AGENTFENCE_CLOCK_SKEW_MS", "600000")
        auth = base_auth(ttl_ms=300_000)  # expires in 5 minutes
        res = enforce(base_request(), auth)
        assert res.decision == "DENY"
        assert res.reason == "AUTHORIZATION_EXPIRED"

    def test_malformed_skew_env_is_ignored(self, monkeypatch):
        monkeypatch.setenv("AGENTFENCE_CLOCK_SKEW_MS", "not-a-number")
        assert enforce(base_request(), base_auth()).decision == "ALLOW"
