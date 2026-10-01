"""
AgentFence — deterministic policy engine + human approval.

Design rule that governs this file:

    The LLM may PROPOSE an action. The LLM is never the authorization authority.

Everything in this module is total, deterministic, and data-only. No model call, no
network, no clock-dependent behaviour other than expiry checks. Given the same
(policy, capability, action, resource) it returns the same decision, which is what
makes the demo reproducible and the tests meaningful.

Fail-closed posture is enforced structurally:
  * capability/action not present in the policy table  -> DENY (no default-allow)
  * policy lookup itself raises                        -> DENY (POLICY_UNAVAILABLE)
  * an unmatched policy never falls through to ALLOW
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .core import (
    Decision,
    DENY_REASONS,
    canonical,
    integrity,
    full_digest,
    now_ms,
    short_id,
)

POLICY_VERSION = "customer-read-v4"


@dataclass
class PolicyRule:
    capability: str
    action: str
    effect: str  # ALLOW | REQUIRE_APPROVAL | DENY
    rationale: str
    resource_prefix: str = ""
    origins: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# The policy surface is intentionally small and legible. It is a data table, not code,
# so a reviewer can read the entire authorization posture of the demo in one screen.
POLICY_TABLE: tuple[PolicyRule, ...] = (
    PolicyRule(
        capability="customer.read",
        action="read",
        effect="ALLOW",
        rationale="Reading a single customer record is a low-blast-radius, read-only operation.",
        resource_prefix="customer/",
        origins=("CRM-A",),
    ),
    PolicyRule(
        capability="customer.write",
        action="write",
        effect="REQUIRE_APPROVAL",
        rationale="Customer mutation is consequential; a human must approve the exact authorization.",
        resource_prefix="customer/",
        origins=("CRM-A",),
    ),
    PolicyRule(
        capability="customer.delete",
        action="delete",
        effect="DENY",
        rationale="Deletion is irreversible. Denied regardless of authorization state.",
        resource_prefix="customer/",
        origins=(),
    ),
    PolicyRule(
        capability="customer.export",
        action="export",
        effect="REQUIRE_APPROVAL",
        rationale="Bulk export is a data-exfiltration vector; approval required.",
        resource_prefix="customer/",
        origins=("CRM-A",),
    ),
)

POLICY_BY_KEY: dict[tuple[str, str], PolicyRule] = {
    (r.capability, r.action): r for r in POLICY_TABLE
}

# Registries. Unknown values are a hard DENY, never a permissive fallback.
KNOWN_AGENTS = ("research-agent", "support-agent", "analytics-agent")
KNOWN_ORIGINS = ("CRM-A", "CRM-B", "CRM-C")
KNOWN_PRINCIPALS = ("svc-research", "svc-support", "svc-analytics", "human.jay")


def evaluate_policy(capability: str, action: str) -> tuple[PolicyRule | None, Decision | None]:
    """
    Deterministic policy evaluation.

    Returns (rule, decision). Exactly one is non-None.
    Unknown capability or action -> DENY. A missing policy is never ALLOW.
    """
    try:
        rule = POLICY_BY_KEY.get((capability, action))
    except Exception as exc:  # pragma: no cover - defensive; policy table is static
        return None, Decision(
            "DENY", "POLICY_UNAVAILABLE", f"Policy evaluation failed: {exc}"
        )

    if rule is None:
        return None, Decision(
            "DENY",
            "NO_SUCH_POLICY",
            f"No policy for capability '{capability}' with action '{action}'.",
        )
    return rule, None


def check_policy(rule: PolicyRule, request: dict[str, Any]) -> Decision | None:
    """Apply a matched policy rule. Anything the rule does not affirm is a DENY."""
    # Resource must live under the declared prefix (or the rule must be prefix-free).
    if rule.resource_prefix:
        res = request.get("resource", "")
        if not res.startswith(rule.resource_prefix):
            return Decision(
                "DENY",
                "UNKNOWN_RESOURCE",
                f"Resource '{res}' is outside the declared scope '{rule.resource_prefix}'.",
                expected={"resource_prefix": rule.resource_prefix},
                received={"resource": res},
            )

    # If the rule enumerates permitted origins, the request origin must be one of them.
    # NOTE: this is a policy-scope check, not the binding check. Both exist; the binding
    # check is what makes a stolen authorization unusable.
    if rule.origins and request.get("origin") not in rule.origins:
        return Decision(
            "DENY",
            "UNKNOWN_ORIGIN",
            f"Policy '{rule.capability}' does not admit origin '{request.get('origin')}'.",
            expected={"origins": list(rule.origins)},
            received={"origin": request.get("origin")},
        )

    if rule.effect == "DENY":
        return Decision("DENY", "POLICY_DENY", rule.rationale)
    return None


# ---------------------------------------------------------------------------
# Human approval — bound to a SPECIFIC authorization, never to an agent.
# ---------------------------------------------------------------------------


@dataclass
class Approval:
    approval_id: str
    authorization_id: str
    # The approval is bound to these exact values. Change any one and it no longer applies.
    action: str
    resource: str
    origin: str
    task: str
    approver: str
    approved_at: int
    expires_at: int
    decision: str = "APPROVED"
    integrity_value: str = ""

    BOUND = ("authorization_id", "action", "resource", "origin", "task")

    def integrity_payload(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "authorization_id": self.authorization_id,
            "action": self.action,
            "resource": self.resource,
            "origin": self.origin,
            "task": self.task,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "decision": self.decision,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.integrity_payload()
        d["integrity_value"] = self.integrity_value
        return d


def create_approval(authorization, *, approver: str, ttl_ms: int = 300_000) -> Approval:
    """
    Approve THIS authorization — not "approve the agent".

    The approval copies the authorization's bound action/resource/origin/task. It is
    therefore invalid the moment any of those change, which is the entire point.
    """
    a = Approval(
        approval_id=short_id("APPR"),
        authorization_id=authorization.authorization_id,
        action=authorization.action,
        resource=authorization.resource,
        origin=authorization.origin,
        task=authorization.task,
        approver=approver,
        approved_at=now_ms(),
        expires_at=now_ms() + int(ttl_ms),
    )
    a.integrity_value = integrity(a.integrity_payload())
    return a


def check_approval(
    approval: Approval | None, auth, request: dict[str, Any]
) -> Decision | None:
    """Verify an approval binds to exactly this authorization AND this request context."""
    if approval is None:
        return Decision("DENY", "APPROVAL_MISSING", DENY_REASONS["APPROVAL_MISSING"])

    # Approval integrity first — a forged approval must never reach comparison logic.
    if not approval.integrity_value or integrity(approval.integrity_payload()) != approval.integrity_value:
        return Decision("DENY", "APPROVAL_MISMATCH", "Approval integrity value does not verify.")

    if now_ms() > approval.expires_at:
        return Decision("DENY", "APPROVAL_EXPIRED", DENY_REASONS["APPROVAL_EXPIRED"])

    if approval.decision != "APPROVED":
        return Decision("DENY", "APPROVAL_MISMATCH", f"Approval decision is {approval.decision}.")

    if approval.authorization_id != auth.authorization_id:
        return Decision(
            "DENY",
            "APPROVAL_MISMATCH",
            "Approval was issued for a different authorization.",
            expected={"authorization_id": auth.authorization_id},
            received={"authorization_id": approval.authorization_id},
        )

    # Field-by-field: the approval must match BOTH the authorization and the live request.
    for f in ("action", "resource", "origin", "task"):
        if getattr(approval, f) != getattr(auth, f):
            return Decision(
                "DENY",
                "APPROVAL_MISMATCH",
                f"Approval.{f} does not match the authorization.",
                expected={f: getattr(auth, f)},
                received={f: getattr(approval, f)},
            )
        if request.get(f) != getattr(auth, f):
            return Decision(
                "DENY",
                "APPROVAL_MISMATCH",
                f"Request.{f} does not match the approved value.",
                expected={f: getattr(auth, f)},
                received={f: request.get(f)},
            )
    return None
