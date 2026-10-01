"""
AgentFence — bypass / adversarial test suite.

This file is the evidence that the security invariant holds. Every test asserts an
OBSERVED outcome; nothing here is aspirational. If a test fails, the product fails.

Groups:
  A. Valid execution
  B. Context substitution (the five required attack demos + variants)
  C. Fail-closed matrix (every DENY path in the gate)
  D. Authorization integrity (tamper detection)
  E. Approval binding
  F. Receipt / evidence completeness
  G. Determinism + no-fallback invariants

Run:  python -m pytest tests/ -q

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.core import Authorization, issue, integrity, Constraints, DENY_REASONS
from agentfence.gate import enforce, DEMO_RECORDS
from agentfence.policy import create_approval, Approval, POLICY_VERSION

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def base_request() -> dict:
    """The exact scenario from the product specification."""
    return {
        "principal": "svc-research",
        "agent": "research-agent",
        "capability": "customer.read",
        "action": "read",
        "resource": "customer/123",
        "origin": "CRM-A",
        "task": "TASK-184",
    }


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


@pytest.fixture
def auth():
    return base_auth()


# ==========================================================================
# GROUP A — valid execution
# ==========================================================================


class TestValidExecution:
    def test_valid_authorization_executes(self, auth):
        res = enforce(base_request(), auth)
        assert res.decision == "ALLOW", f"expected ALLOW, got {res.decision}/{res.reason}"
        assert res.receipt.execution_status == "SUCCESS"

    def test_valid_returns_expected_record(self, auth):
        res = enforce(base_request(), auth)
        assert res.result == DEMO_RECORDS["customer/123"]
        assert res.result["name"] == "Northwind Traders"

    def test_valid_produces_receipt(self, auth):
        res = enforce(base_request(), auth)
        r = res.receipt
        assert r is not None
        assert r.receipt_id.startswith("RCPT-")
        assert r.authorization_id == auth.authorization_id
        assert r.integrity_hash.startswith("af1:sha256:")


# ==========================================================================
# GROUP B — context substitution (REQUIRED DEMO CASES 2-5)
# ==========================================================================


class TestContextSubstitution:
    """The product thesis: an authorization is NOT transferable."""

    def test_case1_valid_allow(self, auth):
        """Required Test 1 — valid execution."""
        res = enforce(base_request(), auth)
        assert res.decision == "ALLOW"
        assert res.receipt.execution_status == "SUCCESS"

    def test_case2_resource_substitution_denied(self, auth):
        """Required Test 2 — same authorization, different resource."""
        req = base_request()
        req["resource"] = "customer/999"  # record exists; authorization does not cover it
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "RESOURCE_MISMATCH"
        assert res.receipt.execution_status == "NOT_EXECUTED"
        assert res.expected["resource"] == "customer/123"
        assert res.received["resource"] == "customer/999"

    def test_case3_capability_substitution_denied(self, auth):
        """Required Test 3 — customer.read authorization cannot delete."""
        req = base_request()
        req["capability"] = "customer.delete"
        req["action"] = "delete"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        # Either the capability mismatch or the policy DENY is a correct refusal;
        # the binding check must be what fires first, before policy scope.
        assert res.reason == "CAPABILITY_MISMATCH"
        assert res.stage == "5-bindings"

    def test_case4_origin_substitution_denied(self, auth):
        """Required Test 4 — the signature context-substitution demo."""
        req = base_request()
        req["origin"] = "CRM-B"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "ORIGIN_MISMATCH"
        assert res.expected["origin"] == "CRM-A"
        assert res.received["origin"] == "CRM-B"
        assert res.detail == "Authorization context mismatch. Authorization is not transferable."

    def test_case5_task_replay_denied(self, auth):
        """Required Test 5 — replay against a different task."""
        req = base_request()
        req["task"] = "TASK-185"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "TASK_CONTEXT_MISMATCH"

    def test_case6_expiration_denied(self):
        """Optional Test 6 — expired authorization."""
        expired = base_auth(ttl_ms=1)
        import time
        time.sleep(0.05)
        res = enforce(base_request(), expired)
        assert res.decision == "DENY"
        assert res.reason == "AUTHORIZATION_EXPIRED"

    def test_agent_substitution_denied(self, auth):
        req = base_request()
        req["agent"] = "support-agent"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "AGENT_MISMATCH"

    def test_principal_substitution_denied(self, auth):
        req = base_request()
        req["principal"] = "svc-support"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "PRINCIPAL_MISMATCH"

    def test_all_bound_fields_are_enforced(self, auth):
        """No bound field may be silently ignored."""
        for field, other, reason in [
            ("principal", "svc-support", "PRINCIPAL_MISMATCH"),
            ("agent", "support-agent", "AGENT_MISMATCH"),
            ("capability", "customer.write", "CAPABILITY_MISMATCH"),
            ("action", "write", "ACTION_MISMATCH"),
            ("resource", "customer/999", "RESOURCE_MISMATCH"),
            ("origin", "CRM-B", "ORIGIN_MISMATCH"),
            ("task", "TASK-999", "TASK_CONTEXT_MISMATCH"),
        ]:
            req = base_request()
            req[field] = other
            res = enforce(req, auth)
            assert res.decision == "DENY", f"{field} substitution was not denied!"
            assert res.reason == reason, f"{field}: expected {reason}, got {res.reason}"


# ==========================================================================
# GROUP C — fail-closed matrix
# ==========================================================================


class TestFailClosed:
    def test_missing_authorization(self):
        res = enforce(base_request(), None)
        assert res.decision == "DENY"
        assert res.reason == "MISSING_AUTHORIZATION"

    @pytest.mark.parametrize(
        "field", ["principal", "agent", "capability", "action", "resource", "origin", "task"]
    )
    def test_missing_request_field(self, field, auth):
        req = base_request()
        del req[field]
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "MALFORMED_REQUEST"

    @pytest.mark.parametrize(
        "field", ["principal", "agent", "capability", "action", "resource", "origin", "task"]
    )
    def test_empty_request_field(self, field, auth):
        req = base_request()
        req[field] = ""
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "MALFORMED_REQUEST"

    def test_unknown_capability_no_default_allow(self, auth):
        req = base_request()
        req["capability"] = "customer.nuke_everything"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        # Binding fires before policy lookup for a substituted capability.
        assert res.reason in ("CAPABILITY_MISMATCH", "NO_SUCH_POLICY")

    def test_unknown_agent(self):
        a = base_auth(agent="ghost-agent")
        req = base_request()
        req["agent"] = "ghost-agent"
        res = enforce(req, a)
        assert res.decision == "DENY"
        assert res.reason == "UNKNOWN_AGENT"

    def test_unknown_origin(self):
        a = base_auth(origin="ROGUE-GATEWAY")
        req = base_request()
        req["origin"] = "ROGUE-GATEWAY"
        res = enforce(req, a)
        assert res.decision == "DENY"
        assert res.reason == "UNKNOWN_ORIGIN"

    def test_policy_deny_is_absolute(self):
        """customer.delete is denied by policy regardless of a valid authorization."""
        a = base_auth(capability="customer.delete", action="delete")
        req = base_request()
        req["capability"] = "customer.delete"
        req["action"] = "delete"
        res = enforce(req, a)
        assert res.decision == "DENY"
        assert res.reason == "POLICY_DENY"
        assert res.receipt.execution_status == "NOT_EXECUTED"

    def test_no_such_policy_fails_closed(self, auth):
        """An unknown capability/action pair must never default to ALLOW."""
        a = base_auth(capability="customer.teleport", action="teleport")
        req = base_request()
        req["capability"] = "customer.teleport"
        req["action"] = "teleport"
        res = enforce(req, a)
        assert res.decision == "DENY"
        assert res.reason == "NO_SUCH_POLICY"

    def test_denial_never_falls_back_to_broader_auth(self, auth):
        """A denied request must not be retried against a different resource/authorization."""
        req = base_request()
        req["resource"] = "customer/999"
        first = enforce(req, auth)
        assert first.decision == "DENY"
        # No implicit substitution occurred; the receipt still shows the denied context.
        assert first.receipt.resource == "customer/999"
        assert first.receipt.decision == "DENY"

    def test_unknown_resource_outside_prefix(self, auth):
        req = base_request()
        req["resource"] = "admin/secrets"
        res = enforce(req, auth)
        assert res.decision == "DENY"
        # Either binding mismatch (auth covers customer/123) — must deny, never allow.
        assert res.reason in ("RESOURCE_MISMATCH", "UNKNOWN_RESOURCE")

    def test_malformed_request_type(self, auth):
        res = enforce("not-an-object", auth)
        assert res.decision == "DENY"
        assert res.reason == "MALFORMED_REQUEST"

    def test_unreadable_authorization(self):
        res = enforce(base_request(), {"authorization_id": "AUTH-BROKEN"})
        assert res.decision == "DENY"
        assert res.reason == "MALFORMED_REQUEST"


# ==========================================================================
# GROUP D — authorization integrity / tamper detection
# ==========================================================================


class TestIntegrity:
    @pytest.mark.parametrize(
        "field",
        ["principal", "agent", "capability", "action", "resource", "origin", "task", "expires_at", "policy_version"],
    )
    def test_tampered_field_detected(self, auth, field):
        """
        Flipping ANY field in the authorization object must be caught.

        expires_at is typed as int, so a string tamper is rejected at parse time
        (MALFORMED_REQUEST); every other field survives parsing and must be caught by
        the integrity check. Both paths are fail-closed denials, which is what matters.
        """
        tampered = auth.to_dict()
        tampered[field] = "ATTACKER-CONTROLLED"
        res = enforce(base_request(), tampered)
        assert res.decision == "DENY"
        assert res.reason in ("INTEGRITY_MISMATCH", "MALFORMED_REQUEST")
        assert res.receipt.execution_status == "NOT_EXECUTED"

    def test_tampered_numeric_field_detected_by_integrity(self, auth):
        """A type-preserving tamper on expires_at MUST be caught by the integrity check."""
        tampered = auth.to_dict()
        tampered["expires_at"] = auth.expires_at + 10_000_000  # valid int, wrong value
        res = enforce(base_request(), tampered)
        assert res.decision == "DENY"
        assert res.reason == "INTEGRITY_MISMATCH"
        assert res.stage == "2-integrity"

    def test_stripped_integrity_value_detected(self, auth):
        d = auth.to_dict()
        d["integrity_value"] = ""
        res = enforce(base_request(), d)
        assert res.decision == "DENY"
        assert res.reason == "INTEGRITY_MISMATCH"

    def test_recomputed_hash_without_secret_is_still_caught(self, auth):
        """
        An attacker who recomputes the integrity value after tampering still cannot
        produce a *valid* authorization for a different context, because the bindings
        then disagree with the request. Both layers must hold.
        """
        d = auth.to_dict()
        d["resource"] = "customer/999"
        forged = Authorization.from_dict(d)
        forged.integrity_value = integrity(forged.integrity_payload())
        req = base_request()
        res = enforce(req, forged)
        assert res.decision == "DENY"
        assert res.reason == "RESOURCE_MISMATCH"

    def test_integrity_is_order_independent(self, auth):
        """Canonicalization must not depend on dict insertion order."""
        d = auth.to_dict()
        shuffled = {k: d[k] for k in sorted(d.keys(), reverse=True)}
        assert shuffled["integrity_value"] == integrity(
            Authorization.from_dict(shuffled).integrity_payload()
        )


# ==========================================================================
# GROUP E — approval binding
# ==========================================================================


class TestApproval:
    def write_auth(self, **over):
        kw = dict(
            principal="svc-research",
            agent="research-agent",
            capability="customer.write",
            action="write",
            resource="customer/123",
            origin="CRM-A",
            task="TASK-184",
            policy_version=POLICY_VERSION,
        )
        kw.update(over)
        return issue(**kw)

    def write_request(self, **over):
        r = base_request()
        r["capability"] = "customer.write"
        r["action"] = "write"
        r.update(over)
        return r

    def test_approval_required_without_approval(self):
        res = enforce(self.write_request(), self.write_auth())
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_MISSING"
        assert res.receipt.approval_required is True

    def test_valid_approval_allows(self):
        a = self.write_auth()
        ap = create_approval(a, approver="human.jay")
        res = enforce(self.write_request(), a, approval=ap)
        assert res.decision == "ALLOW"
        assert res.receipt.approval_id == ap.approval_id

    def test_fake_approval_rejected(self):
        a = self.write_auth()
        forged = Approval(
            approval_id="APPR-FORGED",
            authorization_id=a.authorization_id,
            action=a.action, resource=a.resource, origin=a.origin, task=a.task,
            approver="attacker", approved_at=1, expires_at=99999999999999,
        )
        # forged.integrity_value intentionally left empty
        res = enforce(self.write_request(), a, approval=forged)
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_MISMATCH"

    def test_approval_for_other_authorization_rejected(self):
        a = self.write_auth()
        other = self.write_auth(resource="customer/999")
        ap = create_approval(other, approver="human.jay")
        res = enforce(self.write_request(), a, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_MISMATCH"

    @pytest.mark.parametrize("field", ["resource", "origin", "task"])
    def test_approval_does_not_survive_context_change(self, field,):
        """Changing the request context invalidates an existing approval."""
        a = self.write_auth()
        ap = create_approval(a, approver="human.jay")
        req = self.write_request()
        # NB: action is already "write" on the write request, so substituting it is a
        # no-op. Exclude it here and rely on test_all_bound_fields_are_enforced, which
        # exercises action substitution against a read authorization.
        req[field] = {"resource": "customer/999", "origin": "CRM-B", "task": "TASK-185"}[field]
        res = enforce(req, a, approval=ap)
        assert res.decision == "DENY"
        # Must fail either the binding or the approval check, never reach execution.
        assert res.reason in ("APPROVAL_MISMATCH", "ACTION_MISMATCH", "RESOURCE_MISMATCH",
                              "ORIGIN_MISMATCH", "TASK_CONTEXT_MISMATCH")
        assert res.receipt.execution_status == "NOT_EXECUTED"

    def test_expired_approval_rejected(self):
        import time
        a = self.write_auth()
        ap = create_approval(a, approver="human.jay", ttl_ms=1)
        time.sleep(0.05)
        res = enforce(self.write_request(), a, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_EXPIRED"


# ==========================================================================
# GROUP F — receipts / evidence
# ==========================================================================


class TestReceipt:
    REQUIRED = [
        "receipt_id", "authorization_id", "agent", "capability", "action", "resource",
        "origin", "task", "policy_version", "approval_id", "decision",
        "execution_status", "timestamp", "integrity_hash", "mode",
    ]

    def test_receipt_has_all_required_fields(self, auth):
        res = enforce(base_request(), auth)
        d = res.receipt.to_dict()
        for f in self.REQUIRED:
            assert f in d, f"receipt missing field: {f}"

    def test_receipt_is_json_serializable(self, auth):
        res = enforce(base_request(), auth)
        s = json.dumps(res.receipt.to_dict())
        assert json.loads(s)["decision"] == "ALLOW"

    def test_denial_receipt_records_reason(self, auth):
        req = base_request()
        req["origin"] = "CRM-B"
        res = enforce(req, auth)
        assert res.receipt.deny_reason == "ORIGIN_MISMATCH"
        assert res.receipt.decision == "DENY"

    def test_receipt_integrity_detects_tampering(self, auth):
        res = enforce(base_request(), auth)
        d = res.receipt.to_dict()
        assert d["integrity_hash"].startswith("af1:sha256:")
        d["execution_status"] = "TAMPERED"
        from agentfence.core import full_digest
        d.pop("integrity_hash")
        assert "af1:sha256:" + full_digest(d)[:32] != res.receipt.integrity_hash


# ==========================================================================
# GROUP G — invariants the product claims
# ==========================================================================


class TestInvariants:
    def test_gate_is_deterministic(self, auth):
        req = base_request()
        a = enforce(req, auth)
        b = enforce(req, auth)
        assert a.decision == b.decision == "ALLOW"
        assert a.result == b.result

    def test_authorization_cannot_be_issued_with_wildcards(self):
        for bad in [{"origin": ""}, {"task": ""}, {"agent": "*"}, {"resource": ""}]:
            kw = dict(
                principal="svc-research", agent="research-agent",
                capability="customer.read", action="read",
                resource="customer/123", origin="CRM-A", task="TASK-184",
                policy_version=POLICY_VERSION,
            )
            kw.update(bad)
            with pytest.raises(ValueError):
                issue(**kw)

    def test_delete_capability_unreachable_by_policy(self, auth):
        """Even a correctly-scoped delete authorization must be denied by policy."""
        a = base_auth(capability="customer.delete", action="delete")
        req = base_request()
        req["capability"] = "customer.delete"
        req["action"] = "delete"
        res = enforce(req, a)
        assert res.decision == "DENY"
        assert res.stage == "7-policy-effect"

    def test_every_deny_path_has_stable_reason(self, auth):
        req = base_request()
        req["origin"] = "CRM-B"
        res = enforce(req, auth)
        assert res.reason in DENY_REASONS

    def test_gate_has_no_bypass_flag(self):
        """
        Structural assertion: enforce() has no parameter that can skip verification.
        If someone adds one later, this test fails loudly.
        """
        import inspect
        from agentfence.gate import enforce as enf
        params = set(inspect.signature(enf).parameters)
        forbidden = {"skip_verify", "bypass", "debug", "allow_all", "trust", "force"}
        assert not (params & forbidden), f"gate exposes bypass surface: {params & forbidden}"
