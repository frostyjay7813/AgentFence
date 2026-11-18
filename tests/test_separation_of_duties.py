"""
Fix 2 — the requester cannot approve its own request.

The gap: ``check_approval`` verified that an approval bound to the right authorization,
but nothing compared the approver to the requester. ``create_approval(auth,
approver=<the requester>)`` produced a perfectly well-sealed approval, and the gate
accepted it. Separation of duties was documented, not enforced.

The fix, and what each test here proves:

  * a self-approval is a DENY at the approval stage with a precise reason code
    (``test_self_approval_denied``)
  * spelling variants of one principal do not dodge it
    (``test_self_approval_by_alias_denied``)
  * self-asserting ``principal`` in the request does not dodge it — stage 5 rejects the
    request, and the duty check independently compares the authorization's principal
    (``test_request_principal_cannot_dodge_the_check``)
  * a genuinely distinct approver still succeeds
    (``test_distinct_approver_allowed``)
  * the API refuses to mint a self-approval in the first place
    (``test_api_refuses_self_approval``)

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

from agentfence.api import lambda_handler
from agentfence.auth import sign_credential
from agentfence.core import canonical_principal, issue, same_principal
from agentfence.gate import enforce
from agentfence.policy import POLICY_VERSION, check_separation_of_duties, create_approval


def write_request(**over):
    req = {
        "principal": "svc-research",
        "agent": "research-agent",
        "capability": "customer.write",
        "action": "write",
        "resource": "customer/123",
        "origin": "CRM-A",
        "task": "TASK-184",
    }
    req.update(over)
    return req


def write_auth(principal: str = "svc-research", **over):
    kw = dict(
        principal=principal,
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


# ==========================================================================
# Canonical identity
# ==========================================================================


class TestCanonicalIdentity:
    @pytest.mark.parametrize(
        "a,b",
        [
            ("svc-research", "SVC-RESEARCH"),
            ("svc-research", "svc_research"),
            ("svc-research", " svc.research "),
            ("svc-research", "svc-research@corp"),
            ("human.jay", "Human_Jay@example.com"),
        ],
    )
    def test_aliases_are_one_identity(self, a, b):
        assert same_principal(a, b) is True

    @pytest.mark.parametrize("a,b", [("svc-research", "svc-support"), ("svc", "svcresearch")])
    def test_distinct_principals_stay_distinct(self, a, b):
        assert same_principal(a, b) is False

    def test_missing_identity_never_matches(self):
        """An empty identity must not be treated as equal to another empty identity."""
        assert same_principal("", "") is False
        assert same_principal(None, None) is False
        assert same_principal("  ", "") is False

    def test_canonical_form_is_stable(self):
        assert canonical_principal(" SVC-Research@corp ") == "svcresearch"


# ==========================================================================
# The gate refuses self-approval
# ==========================================================================


class TestSelfApprovalDenied:
    def test_self_approval_denied(self):
        """
        The exact attack: the requester seals an approval for its own authorization.

        The approval is genuinely well-formed and correctly bound — this is not a
        malformed-input test. It fails only because the approver is the requester.
        """
        auth = write_auth()
        ap = create_approval(auth, approver="svc-research")
        assert ap.integrity_value.startswith("af1:sha256:")  # correctly sealed

        res = enforce(write_request(), auth, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "REQUESTER_CANNOT_APPROVE"
        assert res.stage == "8-approval"
        assert res.receipt.execution_status == "NOT_EXECUTED"

    @pytest.mark.parametrize(
        "alias",
        ["SVC-RESEARCH", "svc_research", " svc.research ", "svc-research@corp", "Svc.Research@corp"],
    )
    def test_self_approval_by_alias_denied(self, alias):
        """Changing a dash to an underscore does not create a second person."""
        auth = write_auth()
        ap = create_approval(auth, approver=alias)
        res = enforce(write_request(), auth, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "REQUESTER_CANNOT_APPROVE"

    def test_blank_approver_denied(self):
        """A blank approver cannot be shown to be distinct from the requester."""
        auth = write_auth()
        ap = create_approval(auth, approver="   ")
        res = enforce(write_request(), auth, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_MISMATCH"

    def test_request_principal_cannot_dodge_the_check(self):
        """
        Writing a different ``principal`` into the request does not help.

        Stage 5 rejects the request first, because the request principal no longer
        matches the authorization. The duty check also compares against the
        AUTHORIZATION's principal, so relaxing stage 5 would not open this door.
        """
        auth = write_auth(principal="svc-research")
        ap = create_approval(auth, approver="svc-support")
        req = write_request(principal="svc-support")  # self-asserted, to dodge
        res = enforce(req, auth, approval=ap)
        assert res.decision == "DENY"
        assert res.reason == "PRINCIPAL_MISMATCH"
        assert res.stage == "5-bindings"

    def test_duty_check_reads_the_authorization_principal_directly(self):
        """Direct unit check: even with a shifted request principal, the rule holds."""
        auth = write_auth(principal="svc-research")
        # Approver equals the request principal but not the authorization principal.
        d = check_separation_of_duties(
            "svc-support", auth, write_request(principal="svc-support")
        )
        assert d is not None
        assert d.reason == "REQUESTER_CANNOT_APPROVE"


# ==========================================================================
# A legitimate distinct approver still works
# ==========================================================================


class TestDistinctApproverAllowed:
    def test_distinct_approver_allowed(self):
        auth = write_auth()
        ap = create_approval(auth, approver="human.jay")
        res = enforce(write_request(), auth, approval=ap)
        assert res.decision == "ALLOW", f"expected ALLOW, got {res.reason}"
        assert res.receipt.approval_id == ap.approval_id
        assert res.receipt.execution_status == "SUCCESS"

    def test_another_service_principal_can_approve(self):
        """SoD is about distinctness, not about a particular approver allow-list."""
        auth = write_auth(principal="svc-support")
        ap = create_approval(auth, approver="svc-analytics")
        res = enforce(write_request(principal="svc-support"), auth, approval=ap)
        assert res.decision == "ALLOW"

    def test_sod_denial_does_not_consume_the_authorization(self):
        """
        A refused self-approval must not burn the authorization.

        Consumption happens only after every check passes (fix 3), so the same
        authorization can still be used once by a legitimate approver. This proves the
        two fixes compose instead of fighting each other.
        """
        auth = write_auth()
        bad = create_approval(auth, approver="svc-research")
        denied = enforce(write_request(), auth, approval=bad)
        assert denied.decision == "DENY"
        assert denied.reason == "REQUESTER_CANNOT_APPROVE"

        good = create_approval(auth, approver="human.jay")
        allowed = enforce(write_request(), auth, approval=good)
        assert allowed.decision == "ALLOW", f"authorization was burned: {allowed.reason}"


# ==========================================================================
# The API refuses to mint a self-approval
# ==========================================================================


def api_post(path, body, principal):
    token = sign_credential(principal, secret=os.environ["AGENTFENCE_AUTH_SECRET"])
    return lambda_handler(
        {
            "httpMethod": "POST",
            "path": path,
            "body": json.dumps(body),
            "headers": {"Authorization": f"Bearer {token}"},
        },
        None,
    )


def api_payload(resp):
    return json.loads(resp["body"])


class TestApiRefusesSelfApproval:
    def _authorization(self):
        body = {
            "agent": "research-agent",
            "capability": "customer.write",
            "action": "write",
            "resource": "customer/123",
            "origin": "CRM-A",
            "task": "TASK-184",
        }
        r = api_post("/api/authorize", body, "svc-research")
        assert r["statusCode"] == 200, r["body"]
        return api_payload(r)["authorization"]

    def test_api_refuses_self_approval(self):
        auth = self._authorization()
        r = api_post("/api/approve", {"authorization": auth}, "svc-research")
        assert r["statusCode"] == 403
        p = api_payload(r)
        assert p["error"] == "REQUESTER_CANNOT_APPROVE"
        assert "approval" not in p

    def test_api_refuses_self_approval_by_alias(self):
        auth = self._authorization()
        r = api_post("/api/approve", {"authorization": auth, "approver": "SVC_Research"}, "svc-research")
        assert r["statusCode"] == 403
        assert api_payload(r)["error"] == "REQUESTER_CANNOT_APPROVE"
        assert "approval" not in api_payload(r)

    def test_api_refuses_approver_not_matching_credential(self):
        """Cannot self-assert someone else's approver identity either."""
        auth = self._authorization()
        r = api_post("/api/approve", {"authorization": auth, "approver": "svc-support"}, "svc-research")
        assert r["statusCode"] == 403
        assert api_payload(r)["error"] in {
            "APPROVER_NOT_AUTHENTICATED",
            "REQUESTER_CANNOT_APPROVE",
        }
        assert "approval" not in api_payload(r)

    def test_api_issues_approval_for_distinct_approver(self):
        auth = self._authorization()
        r = api_post("/api/approve", {"authorization": auth, "approver": "human.jay"}, "human.jay")
        assert r["statusCode"] == 200
        p = api_payload(r)
        assert p["approval"]["approver"] == "human.jay"
        assert p["approval"]["authorization_id"] == auth["authorization_id"]

    def test_api_derived_approver_ignores_absent_body_field(self):
        """Approver is taken from the credential even when the body omits it."""
        auth = self._authorization()
        r = api_post("/api/approve", {"authorization": auth}, "human.jay")
        assert r["statusCode"] == 200
        assert api_payload(r)["approval"]["approver"] == "human.jay"

    def test_hand_forged_self_approval_still_denied_at_the_gate(self):
        """
        Bypassing /api/approve entirely does not help: the gate's approval stage
        applies the same rule to a hand-built approval object.
        """
        from agentfence.core import Authorization

        auth_dict = self._authorization()
        auth_obj = Authorization.from_dict(auth_dict)
        forged = create_approval(auth_obj, approver="svc-research")
        res = enforce(write_request(), auth_dict, approval=forged)
        assert res.decision == "DENY"
        assert res.reason == "REQUESTER_CANNOT_APPROVE"
