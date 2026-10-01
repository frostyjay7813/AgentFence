"""
AgentFence — API layer tests.

These exercise the exact handler AWS Lambda will run, including the round-trip a
judge performs in a browser: issue -> approve -> execute -> receipt.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.api import lambda_handler, build_demo_authorization, DEMO_SCENARIO


def call(method: str, path: str, body=None):
    return lambda_handler({"httpMethod": method, "path": path, "body": json.dumps(body) if body else None}, None)


def payload(resp):
    return json.loads(resp["body"])


class TestHealth:
    def test_health_ok(self):
        r = call("GET", "/health")
        assert r["statusCode"] == 200
        p = payload(r)
        assert p["status"] == "ok"
        assert p["service"] == "agentfence"
        assert p["gate"] == "fail-closed"
        assert p["capability"]["policy_rules"] >= 4

    def test_health_leaks_no_secrets(self):
        p = payload(call("GET", "/health"))
        s = json.dumps(p).lower()
        for bad in ("aws_secret", "password", "private_key", "secret_key"):
            assert bad not in s

    def test_unknown_route_404(self):
        r = call("GET", "/nope")
        assert r["statusCode"] == 404
        assert payload(r)["error"] == "NOT_FOUND"

    def test_stage_prefixed_route_normalized(self):
        assert call("GET", "/prod/health")["statusCode"] == 200


class TestDemoState:
    def test_state_returns_scenario_and_authorization(self):
        p = payload(call("GET", "/api/state"))
        assert p["scenario"]["task"] == "TASK-184"
        assert p["authorization"]["resource"] == "customer/123"
        assert p["authorization"]["integrity_value"].startswith("af1:sha256:")

    def test_demo_state_is_deterministic(self):
        a = payload(call("GET", "/api/state"))["authorization"]
        b = payload(call("GET", "/api/state"))["authorization"]
        assert a["authorization_id"] == b["authorization_id"] == "AUTH-8F31C4D92A"


class TestExecuteFlow:
    def test_valid_execution_over_http(self):
        st = payload(call("GET", "/api/state"))
        r = call("POST", "/api/execute", {"request": DEMO_SCENARIO, "authorization": st["authorization"]})
        assert r["statusCode"] == 200
        p = payload(r)
        assert p["decision"] == "ALLOW"
        assert p["receipt"]["execution_status"] == "SUCCESS"
        assert p["result"]["name"] == "Northwind Traders"
        assert p["mode"] == "DEMO"

    @pytest.mark.parametrize(
        "field,value,reason",
        [
            ("resource", "customer/999", "RESOURCE_MISMATCH"),
            ("capability", "customer.delete", "CAPABILITY_MISMATCH"),
            ("action", "delete", "ACTION_MISMATCH"),
            ("origin", "CRM-B", "ORIGIN_MISMATCH"),
            ("task", "TASK-185", "TASK_CONTEXT_MISMATCH"),
        ],
    )
    def test_substitution_denied_over_http(self, field, value, reason):
        st = payload(call("GET", "/api/state"))
        req = dict(DEMO_SCENARIO)
        req[field] = value
        if field == "capability":
            req["action"] = "delete"
        p = payload(call("POST", "/api/execute", {"request": req, "authorization": st["authorization"]}))
        assert p["decision"] == "DENY"
        assert p["reason"] == reason
        assert p["receipt"]["execution_status"] == "NOT_EXECUTED"

    def test_missing_authorization_denied(self):
        p = payload(call("POST", "/api/execute", {"request": DEMO_SCENARIO}))
        assert p["decision"] == "DENY"
        assert p["reason"] == "MISSING_AUTHORIZATION"

    def test_tampered_authorization_denied(self):
        st = payload(call("GET", "/api/state"))
        auth = dict(st["authorization"])
        auth["resource"] = "customer/999"
        p = payload(call("POST", "/api/execute", {"request": DEMO_SCENARIO, "authorization": auth}))
        assert p["decision"] == "DENY"
        assert p["reason"] == "INTEGRITY_MISMATCH"

    def test_expired_authorization_denied(self):
        st = payload(call("GET", "/api/state"))
        auth = dict(st["authorization"])
        auth["expires_at"] = auth["issued_at"] - 1
        p = payload(call("POST", "/api/execute", {"request": DEMO_SCENARIO, "authorization": auth}))
        assert p["decision"] == "DENY"
        assert p["reason"] in ("INTEGRITY_MISMATCH", "AUTHORIZATION_EXPIRED")

    def test_malformed_body_handled(self):
        r = lambda_handler({"httpMethod": "POST", "path": "/api/execute", "body": "{not json"}, None)
        assert r["statusCode"] == 400
        assert payload(r)["error"] == "MALFORMED_JSON"

    def test_request_not_object_400(self):
        r = call("POST", "/api/execute", {"request": "nope"})
        assert r["statusCode"] == 400


class TestApprovalFlow:
    def test_write_requires_then_accepts_approval(self):
        auth = payload(call("POST", "/api/authorize", {
            **{k: DEMO_SCENARIO[k] for k in
               ("principal", "agent", "origin", "task")},
            "capability": "customer.write", "action": "write", "resource": "customer/123",
        }))["authorization"]

        req = {**DEMO_SCENARIO, "capability": "customer.write", "action": "write"}
        p1 = payload(call("POST", "/api/execute", {"request": req, "authorization": auth}))
        assert p1["decision"] == "DENY"
        assert p1["reason"] == "APPROVAL_MISSING"
        assert p1["receipt"]["approval_required"] is True

        ap = payload(call("POST", "/api/approve", {"authorization": auth, "approver": "human.jay"}))["approval"]
        p2 = payload(call("POST", "/api/execute", {"request": req, "authorization": auth, "approval": ap}))
        assert p2["decision"] == "ALLOW"
        assert p2["receipt"]["approval_id"] == ap["approval_id"]

    def test_approval_does_not_transfer_to_other_task(self):
        auth = payload(call("POST", "/api/authorize", {
            **{k: DEMO_SCENARIO[k] for k in ("principal", "agent", "origin")},
            "capability": "customer.write", "action": "write",
            "resource": "customer/123", "task": "TASK-184",
        }))["authorization"]
        ap = payload(call("POST", "/api/approve", {"authorization": auth, "approver": "human.jay"}))["approval"]
        req = {**DEMO_SCENARIO, "capability": "customer.write", "action": "write", "task": "TASK-185"}
        p = payload(call("POST", "/api/execute", {"request": req, "authorization": auth, "approval": ap}))
        assert p["decision"] == "DENY"


class TestReceipts:
    def test_every_response_carries_receipt(self):
        st = payload(call("GET", "/api/state"))
        req = dict(DEMO_SCENARIO)
        req["origin"] = "CRM-B"
        p = payload(call("POST", "/api/execute", {"request": req, "authorization": st["authorization"]}))
        rc = p["receipt"]
        assert rc["decision"] == "DENY"
        assert rc["deny_reason"] == "ORIGIN_MISMATCH"
        assert rc["integrity_hash"].startswith("af1:sha256:")
        assert rc["mode"] == "DEMO"

    def test_receipt_answers_who_what_where_why(self):
        st = payload(call("GET", "/api/state"))
        rc = payload(call("POST", "/api/execute",
                          {"request": DEMO_SCENARIO, "authorization": st["authorization"]}))["receipt"]
        assert rc["agent"] == "research-agent"
        assert rc["capability"] == "customer.read"
        assert rc["resource"] == "customer/123"
        assert rc["origin"] == "CRM-A"
        assert rc["task"] == "TASK-184"
        assert rc["policy_version"]
        assert rc["authorization_id"] == "AUTH-8F31C4D92A"

    def test_demo_mode_labeled_never_blurred(self):
        st = payload(call("GET", "/api/state"))
        p = payload(call("POST", "/api/execute", {"request": DEMO_SCENARIO, "authorization": st["authorization"]}))
        assert p["mode"] == "DEMO"
        assert p["receipt"]["mode"] == "DEMO"
