"""
AgentFence — AWS Lambda handler (the deployed service).

Routes (all JSON over HTTPS via API Gateway):
    GET  /health                 liveness + capability status
    GET  /api/state              deterministic demo state (no credentials needed)
    POST /api/authorize           issue an authorization bound to a context
    POST /api/approve             bind a human approval to a specific authorization
    POST /api/execute             THE GATE — the only path to a capability
    GET  /api/audit               recent receipts from DynamoDB (if configured)

Deployment notes:
  * Zero third-party runtime dependencies — stdlib + boto3 (provided by Lambda).
  * Audit persistence is OPTIONAL. If AGENTFENCE_AUDIT_TABLE is set and reachable,
    receipts are written to DynamoDB. If not, the service still runs and receipts are
    returned inline. This is deliberate: the demo must never fail because of storage.
  * No AWS credentials are ever returned to the browser. The execution identity used
    for live AWS calls is the Lambda execution role, scoped by its IAM policy.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

# Lambda's runtime includes the repo root in sys.path only if packaged flat; make it explicit.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentfence.core import (  # noqa: E402
    Authorization, Constraints, DENY_REASONS, canonical, full_digest, integrity, issue, now_ms, short_id,
)
from agentfence.gate import DEMO_RECORDS, enforce  # noqa: E402
from agentfence.policy import (  # noqa: E402
    Approval, KNOWN_AGENTS, KNOWN_ORIGINS, KNOWN_PRINCIPALS, POLICY_BY_KEY, POLICY_TABLE,
    POLICY_VERSION, create_approval,
)

VERSION = "1.0.0"
BUILD = "agentfence-lambda"

# The canonical demo scenario from the specification. Deterministic on every call.
DEMO_SCENARIO = {
    "principal": "svc-research",
    "agent": "research-agent",
    "capability": "customer.read",
    "action": "read",
    "resource": "customer/123",
    "origin": "CRM-A",
    "task": "TASK-184",
}

MODE = os.environ.get("AGENTFENCE_MODE", "DEMO").upper()

_ddb = None
_ddb_failed = False


def get_table():
    """Lazily resolve the DynamoDB audit table; None if not configured."""
    global _ddb, _ddb_failed
    name = os.environ.get("AGENTFENCE_AUDIT_TABLE")
    if not name or _ddb_failed:
        return None
    if _ddb is None:
        try:
            import boto3

            _ddb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION"))
        except Exception:
            _ddb_failed = True
            return None
    return _ddb


def write_audit(receipt: dict[str, Any]) -> str:
    """Persist a receipt. Never let storage failure affect the authorization decision."""
    table = get_table()
    if table is None:
        return "INLINE_ONLY"
    try:
        import time as _t

        item = dict(receipt)
        item["pk"] = f"RECEIPT#{receipt.get('receipt_id', 'unknown')}"
        item["ts"] = int(_t.time())
        # ttl: 90 days of retention, a defensible default for an evidence store.
        item["expires_at_epoch"] = int(_t.time()) + 90 * 86400
        table.put_item(Item=item)
        return "DYNAMODB"
    except Exception as exc:  # pragma: no cover
        return f"FAILED:{type(exc).__name__}"


def list_audit(limit: int = 25) -> list[dict[str, Any]]:
    table = get_table()
    if table is None:
        return []
    try:
        from boto3.dynamodb.conditions import Attr

        resp = table.scan(Limit=max(1, min(limit, 100)))
        return sorted(resp.get("Items", []), key=lambda i: i.get("ts", 0), reverse=True)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def build_demo_authorization() -> Authorization:
    """The canonical demo authorization. Deterministic across calls (fixed ids)."""
    auth = issue(
        principal=DEMO_SCENARIO["principal"],
        agent=DEMO_SCENARIO["agent"],
        capability=DEMO_SCENARIO["capability"],
        action=DEMO_SCENARIO["action"],
        resource=DEMO_SCENARIO["resource"],
        origin=DEMO_SCENARIO["origin"],
        task=DEMO_SCENARIO["task"],
        policy_version=POLICY_VERSION,
        ttl_ms=3_600_000,  # 1 hour; the EXPIRE attack button backdates it explicitly
    )
    # Stable id so the demo narrative and screenshots stay reproducible.
    auth.authorization_id = "AUTH-8F31C4D92A"
    auth.integrity_value = integrity(auth.integrity_payload())
    return auth


def handle_health(_body, _headers):
    table_name = os.environ.get("AGENTFENCE_AUDIT_TABLE")
    audit_ok = "CONFIGURED" if table_name else "INLINE_ONLY"
    return 200, {
        "status": "ok",
        "service": "agentfence",
        "version": VERSION,
        "build": BUILD,
        "mode": MODE,
        "region": os.environ.get("AWS_REGION", "unknown"),
        "policy_version": POLICY_VERSION,
        "capability": {
            "policy_rules": len(POLICY_TABLE),
            "known_agents": len(KNOWN_AGENTS),
            "known_origins": len(KNOWN_ORIGINS),
            "known_principals": len(KNOWN_PRINCIPALS),
            "demo_records": len(DEMO_RECORDS),
        },
        "audit_store": audit_ok,
        "gate": "fail-closed",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def handle_state(_body, _headers):
    auth = build_demo_authorization()
    return 200, {
        "mode": MODE,
        "policy_version": POLICY_VERSION,
        "scenario": DEMO_SCENARIO,
        "authorization": auth.to_dict(),
        "policies": [r.to_dict() for r in POLICY_TABLE],
        "known": {
            "agents": list(KNOWN_AGENTS),
            "origins": list(KNOWN_ORIGINS),
            "principals": list(KNOWN_PRINCIPALS),
        },
        "records": DEMO_RECORDS,
        "deny_reasons": DENY_REASONS,
    }


def handle_authorize(body, _headers):
    err = _require(body, ("principal", "agent", "capability", "action", "resource", "origin", "task"))
    if err:
        return 400, err
    try:
        auth = issue(
            principal=body["principal"], agent=body["agent"], capability=body["capability"],
            action=body["action"], resource=body["resource"], origin=body["origin"],
            task=body["task"], policy_version=POLICY_VERSION,
            ttl_ms=int(body.get("ttl_ms", 900_000)),
            constraints=body.get("constraints") or {},
        )
    except ValueError as exc:
        return 400, {"error": "ISSUANCE_REFUSED", "detail": str(exc)}
    return 200, {"authorization": auth.to_dict()}


def handle_approve(body, _headers):
    err = _require(body, ("authorization", "approver"))
    if err:
        return 400, err
    try:
        auth = body["authorization"]
        auth = auth if isinstance(auth, Authorization) else Authorization.from_dict(auth)
    except Exception as exc:
        return 400, {"error": "BAD_AUTHORIZATION", "detail": str(exc)}
    ap = create_approval(auth, approver=str(body["approver"]), ttl_ms=int(body.get("ttl_ms", 300_000)))
    return 200, {"approval": ap.to_dict()}


def handle_execute(body, _headers):
    """
    THE GATE. Accepts a request + authorization (+ optional approval) and returns the
    decision, the causal mismatch detail, and an evidence receipt.
    """
    if not isinstance(body, dict):
        return 400, {"error": "MALFORMED_REQUEST", "detail": "Body must be a JSON object."}
    request = body.get("request")
    if not isinstance(request, dict):
        return 400, {"error": "MALFORMED_REQUEST", "detail": "'request' must be an object."}

    authorization = body.get("authorization")
    approval = body.get("approval")
    if isinstance(approval, dict):
        try:
            approval = Approval(**{k: v for k, v in approval.items() if k in Approval.__annotations__})
        except Exception:
            approval = None

    # The gate decides. The API layer never interprets the result.
    result = enforce(request, authorization, approval=approval, mode=body.get("mode", MODE))
    persist = write_audit(result.receipt.to_dict())
    payload = result.to_dict()
    payload["audit_persistence"] = persist
    payload["mode"] = MODE
    return 200, payload


def handle_audit(_body, _headers):
    items = list_audit(limit=25)
    return 200, {"items": items, "count": len(items), "store": os.environ.get("AGENTFENCE_AUDIT_TABLE") or "INLINE_ONLY"}


def _require(body, keys):
    if not isinstance(body, dict):
        return {"error": "MALFORMED_REQUEST", "detail": "Body must be a JSON object."}
    missing = [k for k in keys if not body.get(k)]
    if missing:
        return {"error": "MISSING_FIELDS", "detail": f"Missing: {missing}"}
    return None


ROUTES = {
    "GET /health": handle_health,
    "GET /api/state": handle_state,
    "POST /api/authorize": handle_authorize,
    "POST /api/approve": handle_approve,
    "POST /api/execute": handle_execute,
    "GET /api/audit": handle_audit,
}


def lambda_handler(event, context):
    method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("path") or event.get("rawPath") or "/"
    # Normalize: strip stage prefix (e.g. /prod/api/execute)
    path = path if path.startswith("/") else "/" + path
    parts = [p for p in path.split("/") if p and p not in ("prod", "default", "v1")]
    normalized = "/" + "/".join(parts) if parts else "/"

    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except Exception:
            return _json(400, {"error": "MALFORMED_JSON", "detail": "Request body is not valid JSON."})

    headers = {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    key = f"{method} {normalized}"
    fn = ROUTES.get(key)
    if fn is None:
        known = ", ".join(sorted(ROUTES))
        return _json(404, {"error": "NOT_FOUND", "detail": f"No route {key}", "routes": known})
    try:
        status, payload = fn(body, headers)
    except Exception as exc:  # never leak a stack trace to the client
        return _json(500, {"error": "INTERNAL", "detail": f"{type(exc).__name__}: {exc}"})
    return _json(status, payload)


def _json(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        "body": json.dumps(payload, default=str),
    }
