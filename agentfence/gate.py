"""
AgentFence — execution gate + evidence receipts.

This is the module that makes the product claim true or false. The gate is the ONLY
path to a capability, and it runs a fixed, ordered pipeline. There is no "bypass"
flag, no debug mode, and no early return that skips a check.

ORDER MATTERS and is asserted by the test suite (tests/test_gate_posture.py checks that
every stage label below still exists):

  -- preflight: receipt sealing key -- RECEIPT_KEY_UNAVAILABLE   (no unkeyed receipt)
  0. request schema          -> MALFORMED_REQUEST
  1. authorization present   -> MISSING_AUTHORIZATION
  2. authorization integrity -> INTEGRITY_MISMATCH          (tamper detection FIRST)
  3. registries              -> UNKNOWN_AGENT / UNKNOWN_ORIGIN
  4. validity window         -> AUTHORIZATION_EXPIRED        (skew may only shorten it)
  5. binding match           -> *_MISMATCH                  (the core invariant)
  6. policy lookup           -> NO_SUCH_POLICY              (no default-allow)
  7. policy effect           -> POLICY_DENY / REQUIRE_APPROVAL
  8. approval (if required)  -> APPROVAL_* / REQUESTER_CANNOT_APPROVE
  9. policy scope            -> UNKNOWN_RESOURCE / ORIGIN
 10. capability implementation -> UNKNOWN_CAPABILITY
 11. single use             -> AUTHORIZATION_ALREADY_CONSUMED / CONSUME_STORE_UNAVAILABLE
 12. execute                -> receipt sealed AND persisted BEFORE the effect

Bindings (5) are checked before policy (6) on purpose: "is this the request that was
authorized?" is self-contained and must not depend on policy posture, otherwise a
capability swap would be misreported as a policy denial and would leak the policy
posture of capabilities the agent was never granted.

Integrity is verified BEFORE binding comparison on purpose: if the authorization was
tampered with, every downstream comparison is meaningless.

Stages 10-12 were added by the authorization-boundary hardening and can only deny; no
earlier stage was removed or relaxed. There is exactly one ALLOW construction, and it is
the final statement.

Denials never fall back to a broader authorization, never self-elevate, and a denial
is never converted into an approval because execution failed.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import os
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
from .sealing import (
    receipt_hmac,
    receipt_integrity_hash,
    resolve_receipt_key,
)
from .store import (
    ConsumeRecord,
    StoreUnavailable,
    resolve_consume_store,
    resolve_receipt_chain,
)

ENV_CLOCK_SKEW_MS = "AGENTFENCE_CLOCK_SKEW_MS"

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
    # Chain linkage and keyed seal. Every field below is FINAL before the seal is
    # computed, so the bytes that were persisted are exactly the bytes that verify.
    seq: int = 0
    prev_hash: str = ""
    hmac_value: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def compute_integrity(self) -> str:
        """
        Legacy self-hash (``af1:sha256:``), byte-compatible with the published format.

        Not a security boundary on its own: see agentfence/sealing.py. The keyed seal is
        ``hmac_value``, computed afterwards over this value plus the chain linkage.
        """
        self.integrity_hash = receipt_integrity_hash(self.to_dict())
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
    # The receipt that was sealed and persisted BEFORE the effect was attempted. For an
    # ALLOW this is the load-bearing evidence: it existed before anything happened.
    pre_effect_receipt: Receipt | None = None
    # Where the receipt(s) ended up. Kept off the Receipt itself so the sealed bytes are
    # identical to the persisted bytes.
    receipt_chain_status: str = ""
    receipt_consume_status: str = ""

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
            "receipt_chain_status": self.receipt_chain_status,
            "receipt_consume_status": self.receipt_consume_status,
        }
        if self.pre_effect_receipt:
            d["pre_effect_receipt"] = self.pre_effect_receipt.to_dict()
        if self.receipt:
            d["receipt"] = self.receipt.to_dict()
        if self.result is not None:
            d["result"] = self.result
        return d


def _iso(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + f".{ms % 1000:03d}Z"


def _clock_skew_ms(explicit: int | None) -> int:
    """
    Resolve the clock-skew tolerance in milliseconds.

    Skew is a deployment fact (issuer clock vs gate clock), not a policy knob, and it is
    applied by ``check_validity`` in the only direction that is safe: it shortens the
    validity window, never lengthens it. A missing or malformed value means zero skew —
    the conservative choice — so a typo can never widen anything.
    """
    if explicit is not None:
        try:
            return max(0, int(explicit))
        except (TypeError, ValueError):
            return 0
    raw = os.environ.get(ENV_CLOCK_SKEW_MS)
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def enforce(
    request: dict[str, Any],
    authorization: Authorization | dict[str, Any] | None,
    *,
    approval: Approval | None = None,
    mode: str = "DEMO",
    consume_store: Any = None,
    receipt_chain: Any = None,
    receipt_key: str | bytes | None = None,
    clock_skew_ms: int | None = None,
) -> GateResult:
    """
    The execution gate. The single entry point to any capability.

    Returns a GateResult whose `decision` is ALLOW only when every stage passed. Any
    failure produces DENY with a stable machine-readable reason.

    The keyword-only parameters are dependency injection, not a bypass surface:
    ``consume_store``/``receipt_chain`` select where single-use state and receipts live,
    ``receipt_key`` supplies the sealing key, and ``clock_skew_ms`` sets the skew
    tolerance. None of them can skip a stage, and there is no combination of them that
    turns a DENY into an ALLOW.
    """
    t0 = time.perf_counter()
    ms = now_ms()
    skew_ms = _clock_skew_ms(clock_skew_ms)

    # ---- preflight: the receipt sealing key ---------------------------------
    # Refuse to run at all without a key. An unkeyed receipt cannot be distinguished
    # from one an attacker wrote, so emitting one would be worse than no evidence.
    key = resolve_receipt_key(receipt_key)
    if key is None:
        return GateResult(
            decision="DENY",
            reason="RECEIPT_KEY_UNAVAILABLE",
            detail=DENY_REASONS["RECEIPT_KEY_UNAVAILABLE"],
            stage="0-preflight",
            receipt_chain_status="NOT_ATTEMPTED",
        )

    store = consume_store if consume_store is not None else resolve_consume_store(mode)
    chain = receipt_chain if receipt_chain is not None else resolve_receipt_chain(mode)

    def build_receipt(
        *,
        decision: str,
        reason: str,
        detail: str,
        policy_effect: str,
        approval_required: bool,
        exec_status: str,
        summary: str,
    ) -> Receipt:
        auth_obj = authorization if isinstance(authorization, Authorization) else None
        aid = (
            auth_obj.authorization_id
            if auth_obj
            else (authorization or {}).get("authorization_id", "")
            if isinstance(authorization, dict)
            else ""
        )
        return Receipt(
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

    def seal_and_persist(rc: Receipt, *, persist: bool = True) -> tuple[Receipt, Any]:
        """
        Assign chain linkage, compute the self-hash and the keyed seal, then persist.

        Order matters and is the point of fix 4: linkage and both hashes are final
        before the record leaves this function, so the persisted bytes are exactly the
        bytes a verifier recomputes. Returns ``(receipt, error)`` where ``error`` is a
        StoreUnavailable when persistence failed.
        """
        if persist:
            try:
                seq, prev = chain.allocate()
            except StoreUnavailable as exc:
                # Linkage could not be reserved, so this receipt has no chain position.
                # It is still sealed (an unsealed receipt is worse), and the caller is
                # told so it can refuse to proceed to the effect.
                rc.compute_integrity()
                rc.hmac_value = receipt_hmac(rc.to_dict(), key)
                return rc, exc
            rc.seq, rc.prev_hash = seq, prev
        rc.compute_integrity()
        rc.hmac_value = receipt_hmac(rc.to_dict(), key)
        if not persist:
            return rc, None
        try:
            chain.persist(rc.to_dict())
        except StoreUnavailable as exc:
            return rc, exc
        return rc, None

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
        persist: bool = True,
        consume_status: str = "",
    ) -> GateResult:
        rc = build_receipt(
            decision=decision,
            reason=reason,
            detail=detail,
            policy_effect=policy_effect,
            approval_required=approval_required,
            exec_status=exec_status,
            summary=summary,
        )
        rc, err = seal_and_persist(rc, persist=persist)
        gr = GateResult(
            decision=decision,
            reason=reason,
            detail=detail,
            expected=expected or {},
            received=received or {},
            stage=stage,
            result=result,
        )
        gr.receipt = rc
        gr.receipt_consume_status = consume_status
        if not persist:
            gr.receipt_chain_status = "NOT_PERSISTED"
        elif err is None:
            gr.receipt_chain_status = "PERSISTED"
        else:
            gr.receipt_chain_status = f"FAILED:{getattr(err, 'code', 'UNKNOWN')}"
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
    d = check_validity(auth, ms, skew_ms)
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

    # ---- 10. capability implementation (fail closed, before spending) -------
    # Checked BEFORE consumption so a request that can never execute does not burn its
    # authorization.
    fn = CAPABILITIES.get(request["capability"])
    if fn is None:
        # No capability implementation -> fail closed.
        return finish(
            "DENY", "10-capability", "UNKNOWN_CAPABILITY",
            f"No implementation for capability '{request['capability']}'.",
            policy_effect=rule.effect, approval_required=approval_required,
        )

    # ---- 11. single-use consumption ----------------------------------------
    # Placed after every verification stage, so a rejected request never burns its
    # authorization; and before the effect, so a captured authorization cannot be
    # replayed. Consumption is the gate's one write to shared state, and it fails
    # closed: an unreachable or unconfigured store is a DENY, never an allow and never
    # a quiet downgrade to a weaker store.
    if not auth.authorization_id:
        return finish(
            "DENY", "11-consume", "AUTHORIZATION_ID_MISSING",
            DENY_REASONS["AUTHORIZATION_ID_MISSING"],
            policy_effect=rule.effect, approval_required=approval_required,
        )
    consume_record = ConsumeRecord(
        authorization_id=auth.authorization_id,
        consumed_at_ms=ms,
        # Retention only. Correctness does not depend on the purger; the validity stage
        # has already refused anything past its window.
        expires_at_ms=auth.expires_at + skew_ms,
        binding_digest=full_digest(auth.integrity_payload()),
    )
    try:
        first_use = store.consume(consume_record)
    except StoreUnavailable as exc:
        return finish(
            "DENY", "11-consume", "CONSUME_STORE_UNAVAILABLE",
            f"{DENY_REASONS['CONSUME_STORE_UNAVAILABLE']} ({exc.code})",
            policy_effect=rule.effect, approval_required=approval_required,
            consume_status=f"UNAVAILABLE:{exc.code}",
        )
    except Exception as exc:  # any store fault is a denial, never an allow
        return finish(
            "DENY", "11-consume", "CONSUME_STORE_UNAVAILABLE",
            f"{DENY_REASONS['CONSUME_STORE_UNAVAILABLE']} ({type(exc).__name__})",
            policy_effect=rule.effect, approval_required=approval_required,
            consume_status=f"UNAVAILABLE:{type(exc).__name__}",
        )
    if not first_use:
        return finish(
            "DENY", "11-consume", "AUTHORIZATION_ALREADY_CONSUMED",
            DENY_REASONS["AUTHORIZATION_ALREADY_CONSUMED"],
            expected={"authorization_id": auth.authorization_id, "permitted_uses": 1},
            received={"authorization_id": auth.authorization_id, "permitted_uses": ">1"},
            policy_effect=rule.effect, approval_required=approval_required,
            consume_status="ALREADY_CONSUMED",
        )

    # ---- 12. execute, with the evidence sealed and persisted FIRST ----------
    # The commitment receipt is produced, sealed with the server key, and persisted
    # BEFORE the capability runs. If that fails, the effect does not happen: a crash can
    # therefore never leave an effect with no receipt behind it.
    summary = (
        f"{request['action']} {request['resource']} via {request['origin']} "
        f"under {request['task']}"
    )
    pre_effect = build_receipt(
        decision="ALLOW",
        reason="",
        detail="",
        policy_effect=rule.effect,
        approval_required=approval_required,
        exec_status="AUTHORIZED_PRE_EFFECT",
        summary="receipt sealed and persisted before the effect",
    )
    pre_effect, persist_err = seal_and_persist(pre_effect, persist=True)
    if persist_err is not None:
        gr = finish(
            "DENY", "12-execute", "RECEIPT_PERSIST_FAILED",
            f"{DENY_REASONS['RECEIPT_PERSIST_FAILED']} "
            f"({getattr(persist_err, 'code', 'UNKNOWN')})",
            policy_effect=rule.effect, approval_required=approval_required,
            persist=False, consume_status="CONSUMED",
        )
        gr.pre_effect_receipt = pre_effect
        return gr

    # Only now is the effect attempted.
    try:
        result = fn(request)
    except CapabilityError as exc:
        # A capability failure is a failure, never an implicit approval.
        gr = finish(
            "DENY", "12-execute", "CAPABILITY_ERROR", str(exc),
            policy_effect=rule.effect, approval_required=approval_required,
            exec_status="FAILED", summary=f"capability raised: {exc}",
            consume_status="CONSUMED",
        )
        gr.pre_effect_receipt = pre_effect
        return gr

    outcome = finish(
        "ALLOW", "12-execute", "", "",
        policy_effect=rule.effect, approval_required=approval_required,
        result=result, exec_status="SUCCESS", summary=summary,
        consume_status="CONSUMED",
    )
    outcome.pre_effect_receipt = pre_effect
    return outcome
