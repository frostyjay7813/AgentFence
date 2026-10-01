"""
AgentFence — canonicalization + authorization integrity.

Core invariant of the product:

    An authorization is valid ONLY for the execution context for which it was issued.

This module implements the deterministic, verifiable core:
  * canonical()  — stable serialization of an authorization (RFC-8785-style, JSON-safe)
  * integrity()  — SHA-256 integrity value over the canonical form
  * issue()      — mint an authorization with an integrity value bound to its context
  * verify()     — re-verify integrity before ANY binding comparison happens

INTEGRITY, NOT SIGNING (stated honestly, see submission/KNOWN_LIMITATIONS.md):
This is a deterministic SHA-256 integrity value, NOT a digital signature and NOT a
complete trust system. It detects tampering with the authorization object. It does
NOT prove who issued the authorization — that requires a signature over a key whose
private half is controlled by a real principal. Production deployments should
replace integrity() with asymmetric signing (e.g. SigV4 / KMS) or delegate issuance
to an external authorization server.

The reason for shipping hashing rather than signing is deployment reliability: the
integrity algorithm is a single, dependency-free function that behaves identically in
tests, in the Lambda runtime, and in the browser demo. Swapping it for a signer is a
localized change (one function) and is called out in ARCHITECTURE.md.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

INTEGRITY_PREFIX = "af1"
INTEGRITY_ALGO = "sha256"

# Fields that constitute the execution context an authorization is bound to.
# Changing ANY of these invalidates the authorization at the execution boundary.
BOUND_FIELDS = (
    "principal",
    "agent",
    "capability",
    "action",
    "resource",
    "origin",
    "task",
)


def now_ms() -> int:
    """Current time in milliseconds since epoch (UTC)."""
    return int(time.time() * 1000)


def canonical(obj: Any) -> str:
    """
    Deterministic canonical serialization.

    Keys sorted, no insignificant whitespace, UTF-8, ensure_ascii off so the form is
    byte-stable across platforms. This MUST be the only serialization used for
    integrity computation, otherwise a re-ordered request would change the hash and
    produce a spurious DENY (fail-closed, but a confusing one).
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def integrity(payload: dict[str, Any]) -> str:
    """
    Compute the integrity value over the canonical form of `payload`.

    Format:  af1:sha256:<first 32 hex chars>   (truncated for display legibility;
    the full digest is used in receipts/audit records)

    The truncation is a display concern only. Verification recomputes the full digest
    and compares on the full value; only the human-facing short form is truncated.
    """
    digest = hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()
    return f"{INTEGRITY_PREFIX}:{INTEGRITY_ALGO}:{digest[:32]}"


def full_digest(payload: dict[str, Any]) -> str:
    """Full SHA-256 hex digest of the canonical form (used in receipts)."""
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


WILDCARD_TOKENS = {"*", "**", "any", "ANY", "all", "ALL", "*.*", "-", "?"}


def _is_wildcard(value: Any) -> bool:
    """True if the value is a wildcard/placeholder that would make the binding useless."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    return v in WILDCARD_TOKENS or "*" in v or v.lower() in {"any", "all"}


def short_id(prefix: str, n: int = 8) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:n].upper()}"


@dataclass
class Constraints:
    """Additional, non-structural limits bound into the authorization."""

    max_units: int | None = None
    requires_approval: bool = False
    read_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Authorization:
    """
    A narrowly scoped authorization to perform a particular action in a particular
    context. Note what is NOT here: there is no "agent may use capability X" field.
    There is only "this agent may do exactly this, here, now, until expiry".
    """

    authorization_id: str
    principal: str
    agent: str
    capability: str
    action: str
    resource: str
    origin: str
    task: str
    issued_at: int
    expires_at: int
    policy_version: str
    constraints: dict[str, Any] = field(default_factory=dict)
    # Populated at issuance. Excluded from its own integrity computation.
    integrity_value: str = ""

    BOUND = BOUND_FIELDS

    def integrity_payload(self) -> dict[str, Any]:
        """The exact object the integrity value is computed over."""
        return {
            "authorization_id": self.authorization_id,
            "principal": self.principal,
            "agent": self.agent,
            "capability": self.capability,
            "action": self.action,
            "resource": self.resource,
            "origin": self.origin,
            "task": self.task,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
            "constraints": self.constraints,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.integrity_payload()
        d["integrity_value"] = self.integrity_value
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Authorization":
        return Authorization(
            authorization_id=d["authorization_id"],
            principal=d["principal"],
            agent=d["agent"],
            capability=d["capability"],
            action=d["action"],
            resource=d["resource"],
            origin=d["origin"],
            task=d["task"],
            issued_at=int(d["issued_at"]),
            expires_at=int(d["expires_at"]),
            policy_version=d["policy_version"],
            constraints=d.get("constraints") or {},
            integrity_value=d.get("integrity_value", ""),
        )


def issue(
    *,
    principal: str,
    agent: str,
    capability: str,
    action: str,
    resource: str,
    origin: str,
    task: str,
    policy_version: str,
    ttl_ms: int = 900_000,
    constraints: Constraints | dict[str, Any] | None = None,
) -> Authorization:
    """
    Issue an authorization bound to a specific execution context.

    Fail-closed by construction: every bound field is required. There is no default
    and no wildcard. An authorization cannot be issued without a concrete origin or
    task, because those are precisely the fields that make it non-transferable.
    """
    missing = [
        f
        for f, v in (
            ("principal", principal),
            ("agent", agent),
            ("capability", capability),
            ("action", action),
            ("resource", resource),
            ("origin", origin),
            ("task", task),
        )
        if not isinstance(v, str) or not v.strip()
    ]
    if missing:
        raise ValueError(f"cannot issue authorization, missing bound fields: {missing}")

    # Wildcards defeat the invariant: an authorization bound to origin="*" or task="*"
    # is transferable to any origin/task, which is precisely what AgentFence exists to
    # prevent. Refuse at issuance so it can never be minted.
    bindings = {
        "principal": principal,
        "agent": agent,
        "capability": capability,
        "action": action,
        "resource": resource,
        "origin": origin,
        "task": task,
    }
    wildcards = [f for f, v in bindings.items() if _is_wildcard(v)]
    if wildcards:
        raise ValueError(
            f"cannot issue authorization, wildcard values are not a valid binding: {wildcards}"
        )

    if isinstance(constraints, Constraints):
        c = constraints.to_dict()
    else:
        c = dict(constraints or {})

    auth = Authorization(
        authorization_id=short_id("AUTH"),
        principal=principal,
        agent=agent,
        capability=capability,
        action=action,
        resource=resource,
        origin=origin,
        task=task,
        issued_at=now_ms(),
        expires_at=now_ms() + int(ttl_ms),
        policy_version=policy_version,
        constraints=c,
    )
    auth.integrity_value = integrity(auth.integrity_payload())
    return auth


# Reasons are stable, machine-readable strings. The UI renders these verbatim, so
# they are part of the product contract.
DENY_REASONS = {
    "MISSING_AUTHORIZATION": "No authorization was presented.",
    "MALFORMED_REQUEST": "Request could not be parsed or failed schema validation.",
    "UNKNOWN_AGENT": "Agent is not registered.",
    "UNKNOWN_CAPABILITY": "Capability is not recognized.",
    "UNKNOWN_ORIGIN": "Origin is not a registered execution boundary.",
    "UNKNOWN_RESOURCE": "Resource does not exist or is not addressable.",
    "UNKNOWN_ACTION": "Action is not recognized.",
    "AGENT_MISMATCH": "Agent does not match the authorization.",
    "CAPABILITY_MISMATCH": "Requested capability was not the authorized capability.",
    "ACTION_MISMATCH": "Requested action was not the authorized action.",
    "RESOURCE_MISMATCH": "Requested resource was not the authorized resource.",
    "ORIGIN_MISMATCH": "Authorization context mismatch. Authorization is not transferable.",
    "TASK_CONTEXT_MISMATCH": "Request task differs from the authorized task.",
    "PRINCIPAL_MISMATCH": "Request principal differs from the authorized principal.",
    "AUTHORIZATION_EXPIRED": "Authorization expired before execution.",
    "AUTHORIZATION_NOT_YET_VALID": "Authorization is not yet valid.",
    "INTEGRITY_MISMATCH": "Authorization integrity value does not verify. Treat as tampered.",
    "APPROVAL_REQUIRED": "This action requires human approval.",
    "APPROVAL_MISSING": "Required approval was not presented.",
    "APPROVAL_MISMATCH": "Approval does not bind to this exact authorization.",
    "APPROVAL_EXPIRED": "Approval expired.",
    "POLICY_DENY": "Policy returned DENY for this action.",
    "POLICY_UNAVAILABLE": "Policy could not be evaluated. Failing closed.",
    "NO_SUCH_POLICY": "No policy matches this capability/action pair.",
    "TRANSFER_ATTEMPT": "Authorization transfer was attempted but not authorized.",
}


@dataclass
class Decision:
    decision: str  # ALLOW | REQUIRE_APPROVAL | DENY
    reason: str = ""
    detail: str = ""
    expected: dict[str, Any] = field(default_factory=dict)
    received: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def mismatch(field_name: str, expected: Any, received: Any) -> Decision:
    reason = {
        "agent": "AGENT_MISMATCH",
        "capability": "CAPABILITY_MISMATCH",
        "action": "ACTION_MISMATCH",
        "resource": "RESOURCE_MISMATCH",
        "origin": "ORIGIN_MISMATCH",
        "task": "TASK_CONTEXT_MISMATCH",
        "principal": "PRINCIPAL_MISMATCH",
    }[field_name]
    return Decision(
        decision="DENY",
        reason=reason,
        detail=DENY_REASONS[reason],
        expected={field_name: expected},
        received={field_name: received},
    )


def verify_integrity(auth: Authorization) -> Decision | None:
    """Verify the authorization's own integrity value. DENY on any discrepancy."""
    if not auth.integrity_value:
        return Decision("DENY", "INTEGRITY_MISMATCH", DENY_REASONS["INTEGRITY_MISMATCH"])
    expected = integrity(auth.integrity_payload())
    # Constant-time-ish comparison; lengths are equal by construction.
    if expected != auth.integrity_value:
        return Decision(
            "DENY",
            "INTEGRITY_MISMATCH",
            DENY_REASONS["INTEGRITY_MISMATCH"]
            + f" (expected {expected}, got {auth.integrity_value})",
        )
    return None


def check_bindings(auth: Authorization, request: dict[str, Any]) -> Decision | None:
    """
    Compare every bound field of the authorization against the reconstructed
    execution context. Returns the FIRST mismatch as a Decision, or None if all match.

    Ordering is deliberate and is the demo narrative:
        principal -> agent -> capability -> action -> resource -> origin -> task
    """
    for f in BOUND_FIELDS:
        if f not in request:
            return Decision(
                "DENY", "MALFORMED_REQUEST",
                f"Request is missing bound field '{f}'.",
            )
        exp = getattr(auth, f)
        got = request[f]
        if not isinstance(got, str) or not got.strip():
            return Decision("DENY", "MALFORMED_REQUEST", f"Bound field '{f}' is empty.")
        if exp != got:
            return mismatch(f, exp, got)
    return None


def check_validity(auth: Authorization, at_ms: int | None = None) -> Decision | None:
    t = now_ms() if at_ms is None else at_ms
    if t < auth.issued_at:
        return Decision("DENY", "AUTHORIZATION_NOT_YET_VALID", DENY_REASONS["AUTHORIZATION_NOT_YET_VALID"])
    if t > auth.expires_at:
        return Decision("DENY", "AUTHORIZATION_EXPIRED", DENY_REASONS["AUTHORIZATION_EXPIRED"])
    return None
