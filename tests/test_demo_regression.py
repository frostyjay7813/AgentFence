"""Regression tests for demo paths that previously reported the WRONG reason.

Both cases here were real bugs found while verifying the live deployment artifact:

1. The "expire" demo backdated a live authorization, which broke its integrity value,
   so expiry was reported as INTEGRITY_MISMATCH and AUTHORIZATION_EXPIRED was
   unreachable. The demo must issue a correctly-sealed, already-expired authorization.

2. The approval flow needs a fresh authorization for the capability being approved;
   reusing the read authorization reports CAPABILITY_MISMATCH and hides the approval
   lesson entirely.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


import json

from agentfence.api import lambda_handler


def read_request():
    """The demo's authorized context: research-agent reading customer/123."""
    return {"principal": "svc-research", "agent": "research-agent",
            "capability": "customer.read", "action": "read",
            "resource": "customer/123", "origin": "CRM-A", "task": "TASK-184"}


def write_request():
    """Same context, but the capability that policy marks REQUIRE_APPROVAL."""
    return dict(read_request(), capability="customer.write", action="write")


def call(path, body=None):
    event = {"httpMethod": "POST" if body is not None else "GET", "path": path,
             "body": json.dumps(body) if body is not None else None}
    return json.loads(lambda_handler(event, None)["body"])


class TestExpiryIsReachable:
    def test_expire_endpoint_returns_sealed_authorization(self):
        resp = call("/api/expire", {})
        auth = resp["authorization"]
        assert auth["integrity_value"].startswith("af1:sha256:")

    def test_expired_authorization_reports_expiry_not_tampering(self):
        auth = call("/api/expire", {})["authorization"]
        res = call("/api/execute", {"request": read_request(), "authorization": auth})
        assert res["decision"] == "DENY"
        assert res["reason"] == "AUTHORIZATION_EXPIRED", (
            "an expired-but-correctly-sealed authorization must fail on validity, "
            "not on integrity; otherwise the expiry stage is unreachable"
        )
        assert res["stage"] == "4-validity"

    def test_valid_execution_still_allowed(self):
        state = call("/api/state")
        res = call("/api/execute", {"request": state["scenario"], "authorization": state["authorization"]})
        assert res["decision"] == "ALLOW"
        assert res["receipt"]["execution_status"] == "SUCCESS"


class TestApprovalFlowIsReachable:
    def test_write_requires_approval(self):
        auth = call("/api/authorize", write_request())["authorization"]
        res = call("/api/execute", {"request": write_request(), "authorization": auth})
        assert res["decision"] == "DENY"
        assert res["reason"] == "APPROVAL_MISSING"

    def test_approval_allows_and_is_recorded(self):
        auth = call("/api/authorize", write_request())["authorization"]
        approval = call("/api/approve", {"authorization": auth, "approver": "human.jay"})["approval"]
        res = call("/api/execute", {"request": write_request(), "authorization": auth, "approval": approval})
        assert res["decision"] == "ALLOW"
        assert res["receipt"]["approval_id"] == approval["approval_id"]

    def test_approval_does_not_transfer_to_another_task(self):
        auth = call("/api/authorize", write_request())["authorization"]
        approval = call("/api/approve", {"authorization": auth, "approver": "human.jay"})["approval"]
        moved = dict(write_request(), task="TASK-185")
        res = call("/api/execute", {"request": moved, "authorization": auth, "approval": approval})
        assert res["decision"] == "DENY"
        assert res["reason"] == "TASK_CONTEXT_MISMATCH"


class TestSingleOriginDemo:
    def test_index_is_served_as_html(self):
        res = lambda_handler({"httpMethod": "GET", "path": "/", "body": None}, None)
        assert res["statusCode"] == 200
        assert res["headers"]["Content-Type"].startswith("text/html")
        assert "Authorization that follows the action" in res["body"]

    def test_index_html_is_served_at_both_paths(self):
        for path in ("/", "/index.html"):
            res = lambda_handler({"httpMethod": "GET", "path": path, "body": None}, None)
            assert res["statusCode"] == 200
