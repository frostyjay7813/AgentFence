"""
AgentFence — execution gate + evidence receipts.

This is the module that makes the product claim true or false. The gate is the ONLY
path to a capability, and it runs a fixed, ordered pipeline. There is no "bypass"
flag, no debug mode, and no early return that skips a check.

ORDER MATTERS and is asserted by the test suite:

  0. request schema          -> MALFORMED_REQUEST
  1. authorization present   -> MISSING_AUTHORIZATION
  2. authorization integrity -> INTEGRITY_MISMATCH          (tamper detection FIRST)
  3. registries              -> UNKNOWN_AGENT/ORIGIN/RESOURCE
  4. validity window         -> AUTHORIZATION_EXPIRED
  5. policy lookup           -> NO_SUCH_POLICY              (no default-allow)
  6. policy effect           -> POLICY_DENY / REQUIRE_APPROVAL
  7. binding match           -> *_MISMATCH                  (the core invariant)
  8. approval (if required)  -> APPROVAL_*
  9. policy scope            -> UNKNOWN_RESOURCE / ORIGIN
 10. execute                 -> capability invoked

Integrity is verified BEFORE binding comparison on purpose: if the authorization was
tampered with, every downstream comparison is meaningless.

Denials never fall back to a broader authorization, never self-elevate, and a denial
is never converted into an approval because execution failed.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable

from .core import (
    Authorization,
    Decision,
    DENY_REASONS,
    now_ms,
    short_id,
    verify_integrity,
    check_bindings,
    check_validity,
    full_digest,
    canonical,
    DENY_REASONS as _R,
)
from .policy import (
    Approval,
    check_approval,
    check_policy,
    evaluate_policy,
    KNOWN_AGENTS,
    KNOWN_ORIGINS,
    KNOWN_PRINCIPALS,
    POLICY_VERSION,
)

REQUIRED_REQUEST_FIELDS = (
    "principal",
    "agent",
    "capability",
    "action",
    "resource",
    "origin",
    "task",
)

# Synthetic dataset for DEMO mode. Deterministic, no live customer data.
DEMO_RECORDS: dict[str, dict[str, Any]] = {
    "customer/123": {
        "id": "customer/123",
        "name": "Northwind Traders",
        "segment": "enterprise",
        "mrr": 18400,
        "status": "active",
    },
    "customer/999": {
        "id": "customer/999",
        "name": "Initech Systems",
        "segment": "smb",
        "mrr": 2100,
        "status": "active",
    },
}


class CapabilityError(Exception):
    """Raised by a capability when the underlying action genuinely fails."""


def capability_read(request: dict[str, Any]) -> dict[str, Any]:
    """
    The 'AWS capability' stand-in for DEMO mode: a deterministic record read.

    In LIVE mode the same signature is satisfied by a real AWS call (see infra/).
    The contract the gate depends on is identical: dict in, dict out, raise on failure.
    """
    rid = request.get("resource", "")
    if rid not in DEMO_RECORDS:
        raise CapabilityError(f"no such record: {rid}")
    return dict(DEMO_RECORDS[rid])


def capability_write(request: dict[str, Any]) -> dict[str, Any]:
    rid = request.get("resource", "")
    if rid not in DEMO_RECORDS:
        raise CapabilityError(f"no such record: {rid}")
    return {"id": rid, "status": "updated", "note": "synthetic write in DEMO mode"}


def capability_delete(request: dict[str, Any]) -> dict[str, Any]:
    # Reachable only if policy is bypassed — which the test suite asserts is impossible.
    raise CapabilityError("delete capability is disabled by policy and unreachable")


CAPABILITIES: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "customer.read": capability_read,
    "customer.write": capability_write,
    "customer.delete": capability_delete,
}


@dataclass
class Receipt:
    """Evidence that answers WHO / WHAT / WHERE / WHY / UNDER WHICH AUTHORIZATION / POLICY."""

    receipt_id: str
    authorization_id: str
    agent: str
    principal: str
    capability: str
    action: str
    resource: str
    origin: str
    task: str
    policy_version: str
    policy_effect: str
    approval_id: str | None
    approval_required: bool
    decision: str
    deny_reason: str | None
    execution_status: str
    mode: str
    timestamp: str
    elapsed_ms: float
    result_summary: str
    authorization_integrity: str
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def compute_integrity(self) -> str:
        d = self.to_dict()
        d.pop("integrity_hash", None)
        self.integrity_hash = "af1:sha256:" + full_digest(d)[:32]
        return self.integrity_hash


@dataclass
class GateResult:
    decision: str
    reason: str = ""
    detail: str = ""
    expected: dict[str, Any] = field(default_factory=dict)
    received: dict[str, Any] = field(default_factory=dict)
    receipt: Receipt | None = None
    result: Any = None
    stage: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        d = {
            "decision": self.decision,
            "reason": self.reason,
            "detail": self.detail,
            "expected": self.expected,
            "received": self.received,
            "stage": self.stage,
        }
        if self.receipt:
            d["receipt"] = self.receipt.to_dict()
        if self.result is not None:
            d["result"] = self.result
        return d


def _iso(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + f".{ms % 1000:03d}Z"


def enforce(
    request: dict[str, Any],
    authorization: Authorization | dict[str, Any] | None,
    *,
    approval: Approval | None = None,
    mode: str = "DEMO",
) -> GateResult:
    """
    The execution gate. The single entry point to any capability.

    Returns a GateResult whose `decision` is ALLOW only when every one of the ten
    stages passed. Any failure produces DENY with a stable machine-readable reason.
    """
    t0 = time.perf_counter()
    ms = now_ms()

    def finish(
        decision: str,
        stage: str,
        reason: str = "",
        detail: str = "",
        expected: dict[str, Any] | None = None,
        received: dict[str, Any] | None = None,
        policy_effect: str = "",
        approval_required: bool = False,
        result: Any = None,
        exec_status: str = "NOT_EXECUTED",
        summary: str = "",
    ) -> GateResult:
        gr = GateResult(
            decision=decision,
            reason=reason,
            detail=detail,
            expected=expected or {},
            received=received or {},
            stage=stage,
            result=result,
        )
        auth_obj = authorization if isinstance(authorization, Authorization) else None
        aid = (
            auth_obj.authorization_id
            if auth_obj
            else (authorization or {}).get("authorization_id", "")
            if isinstance(authorization, dict)
            else ""
        )
        gr.receipt = Receipt(
            receipt_id=short_id("RCPT"),
            authorization_id=aid,
            agent=str(request.get("agent", "")) if isinstance(request, dict) else "",
            principal=str(request.get("principal", "")) if isinstance(request, dict) else "",
            capability=str(request.get("capability", "")) if isinstance(request, dict) else "",
            action=str(request.get("action", "")) if isinstance(request, dict) else "",
            resource=str(request.get("resource", "")) if isinstance(request, dict) else "",
            origin=str(request.get("origin", "")) if isinstance(request, dict) else "",
            task=str(request.get("task", "")) if isinstance(request, dict) else "",
            policy_version=str(request.get("_policy_version", POLICY_VERSION)) if isinstance(request, dict) else POLICY_VERSION,
            policy_effect=policy_effect,
            approval_id=approval.approval_id if approval else None,
            approval_required=approval_required,
            decision=decision,
            deny_reason=reason or None,
            execution_status=exec_status,
            mode=mode,
            timestamp=_iso(ms),
            elapsed_ms=round((time.perf_counter() - t0) * 1000, 3),
            result_summary=summary or reason or detail,
            authorization_integrity=(auth_obj.integrity_value if auth_obj else ""),
        )
        gr.receipt.compute_integrity()
        return gr

    # ---- 0. request schema -------------------------------------------------
    if not isinstance(request, dict):
        return finish("DENY", "0-schema", "MALFORMED_REQUEST", "Request must be an object.")
    missing = [f for f in REQUIRED_REQUEST_FIELDS if f not in request]
    if missing:
        return finish(
            "DENY", "0-schema", "MALFORMED_REQUEST", f"Missing required fields: {missing}"
        )
    if any(not isinstance(request[f], str) or not request[f].strip() for f in REQUIRED_REQUEST_FIELDS):
        bad = [f for f in REQUIRED_REQUEST_FIELDS if not str(request[f]).strip()]
        return finish(
            "DENY", "0-schema", "MALFORMED_REQUEST", f"Empty required fields: {bad}"
        )

    # ---- 1. authorization present -----------------------------------------
    if authorization is None:
        return finish(
            "DENY", "1-authorization", "MISSING_AUTHORIZATION",
            DENY_REASONS["MISSING_AUTHORIZATION"],
        )
    try:
        auth = authorization if isinstance(authorization, Authorization) else Authorization.from_dict(authorization)
    except Exception as exc:
        return finish("DENY", "1-authorization", "MALFORMED_REQUEST", f"Unreadable authorization: {exc}")

    # ---- 2. authorization integrity (tamper check BEFORE comparisons) ------
    d = verify_integrity(auth)
    if d:
        return finish("DENY", "2-integrity", d.reason, d.detail)

    # ---- 3. registries ------------------------------------------------------
    if request["agent"] not in KNOWN_AGENTS:
        return finish("DENY", "3-registries", "UNKNOWN_AGENT", f"Unknown agent '{request['agent']}'.")
    if request["principal"] not in KNOWN_PRINCIPALS:
        return finish("DENY", "3-registries", "MISSING_AUTHORIZATION", f"Unknown principal '{request['principal']}'.")
    if request["origin"] not in KNOWN_ORIGINS:
        return finish("DENY", "3-registries", "UNKNOWN_ORIGIN", f"Unknown origin '{request['origin']}'.")

    # ---- 4. validity window -------------------------------------------------
    d = check_validity(auth, ms)
    if d:
        return finish("DENY", "4-validity", d.reason, d.detail)

    # ---- 5. BINDING MATCH — the core invariant -----------------------------
    # Deliberately BEFORE any policy evaluation. "Is this request the one that was
    # authorized?" is self-contained and does not depend on policy posture. Checking
    # policy first would both leak the policy posture of capabilities the agent was
    # never granted and misattribute a capability swap as NO_SUCH_POLICY/POLICY_DENY
    # rather than the true security reason.
    d = check_bindings(auth, request)
    if d:
        return finish(
            "DENY", "5-bindings", d.reason, d.detail,
            expected=d.expected, received=d.received,
        )

    # ---- 6. policy lookup (no default-allow) --------------------------------
    # Only reached when the request genuinely matches the authorization.
    rule, perr = evaluate_policy(request["capability"], request["action"])
    if perr:
        return finish("DENY", "6-policy-lookup", perr.reason, perr.detail)
    assert rule is not None

    # ---- 7. policy effect ---------------------------------------------------
    # Reached only for correctly-authorized requests, so POLICY_DENY here means
    # "authorized, but policy forbids it" — the honest, non-leaking meaning.
    if rule.effect == "DENY":
        return finish(
            "DENY", "7-policy-effect", "POLICY_DENY", rule.rationale, policy_effect=rule.effect
        )
    approval_required = rule.effect == "REQUIRE_APPROVAL"

    # ---- 8. approval (if required) -----------------------------------------
    if approval_required:
        d = check_approval(approval, auth, request)
        if d:
            return finish(
                "DENY", "8-approval", d.reason, d.detail,
                expected=d.expected, received=d.received,
                policy_effect=rule.effect, approval_required=True,
            )

    # ---- 9. policy scope ----------------------------------------------------
    d = check_policy(rule, request)
    if d:
        return finish(
            "DENY", "9-policy-scope", d.reason, d.detail,
            expected=d.expected, received=d.received,
            policy_effect=rule.effect, approval_required=approval_required,
        )

    # ---- 10. execute --------------------------------------------------------
    fn = CAPABILITIES.get(request["capability"])
    if fn is None:
        # No capability implementation -> fail closed.
        return finish(
            "DENY", "10-execute", "UNKNOWN_CAPABILITY",
            f"No implementation for capability '{request['capability']}'.",
            policy_effect=rule.effect, approval_required=approval_required,
        )
    try:
        result = fn(request)
    except CapabilityError as exc:
        # A capability failure is a failure, never an implicit approval.
        return finish(
            "DENY", "10-execute", "CAPABILITY_ERROR", str(exc),
            policy_effect=rule.effect, approval_required=approval_required,
            exec_status="FAILED", summary=f"capability raised: {exc}",
        )

    summary = (
        f"{request['action']} {request['resource']} via {request['origin']} "
        f"under {request['task']}"
    )
    return finish(
        "ALLOW", "10-execute", "", "",
        policy_effect=rule.effect, approval_required=approval_required,
        result=result, exec_status="SUCCESS", summary=summary,
    )
