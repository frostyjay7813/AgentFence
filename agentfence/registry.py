"""
AgentFence — agent registry.

Replaces the three static tuples that used to live in ``policy.py``::

    KNOWN_AGENTS     = ("research-agent", "support-agent", "analytics-agent")
    KNOWN_ORIGINS    = ("CRM-A", "CRM-B", "CRM-C")
    KNOWN_PRINCIPALS = ("svc-research", "svc-support", "svc-analytics", "human.jay")

with a real, inspectable registry. A tuple cannot express who owns an agent, what it
is allowed to touch, or whether it is still trusted; every one of those questions had
to be answered "it is in the tuple, therefore yes" — and nothing could be withdrawn
without editing source and redeploying.

WHAT THIS MODULE ADDS
  * principals  — the service and human identities that can own agents and author
                  registry changes
  * origins     — the declared execution boundaries (a fleet-level fact)
  * agents      — AgentRecord: agent id, owner, capabilities, allowed origins,
                  lifecycle state, created/rotated/revoked timestamps, version
  * a hash-linked journal — every mutation becomes a RegistryReceipt sealed with the
                  same af1:sha256 integrity construction the execution gate uses for
                  its evidence receipts, and chained to its predecessor by prev_hash

FAIL-CLOSED POSTURE (unchanged, and extended to the registry)
  * an empty registry admits nothing — there is no seeded-by-accident allow
  * an unregistered agent, principal or origin is a hard DENY
  * a suspended or revoked agent admits nothing
  * a capability list of ``()`` grants nothing. It is NOT a wildcard
  * an origin list of ``()`` admits nothing. It is NOT a wildcard
  * wildcards are REFUSED at registration time, not merely ignored at check time,
    so an implicit allow can never be persisted into the registry in the first place
  * an agent cannot be granted an origin that was never declared
  * an agent's owner must already be a registered principal
  * registry mutations require a registered actor; refusals raise RegistryError and
    never leave a partially applied registry

AUTHORITY SPLIT (deliberately preserved)
  The registry is the IDENTITY authority: who exists, what it may possess, whether it
  is still trusted. ``policy.py`` remains the sole EFFECT authority: given a granted
  capability, whether the action is ALLOW / REQUIRE_APPROVAL / DENY. Moving identity
  data into a registry does not move, weaken or duplicate policy authority. An agent
  being granted ``customer.delete`` here would still be denied by policy; conversely
  policy can never grant a capability the registry does not issue to that agent.

WHAT THIS MODULE DOES NOT DO
  Registry mutation is a library/administration operation, not an HTTP surface. There
  is deliberately no POST route for register/rotate/revoke: an unauthenticated registry
  mutation endpoint would be a privilege-escalation primitive. ``GET /api/registry``
  exposes read-only state so operators can inspect the fleet and verify the chain.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable

from .core import full_digest, is_wildcard, iso_ms, now_ms, short_id

# ---------------------------------------------------------------------------
# Lifecycle states
# ---------------------------------------------------------------------------

ACTIVE = "active"
SUSPENDED = "suspended"
REVOKED = "revoked"

LIFECYCLE_STATES = (ACTIVE, SUSPENDED, REVOKED)

# States from which an agent may still be brought back to ACTIVE.
RESTORABLE_STATES = (SUSPENDED,)

PRINCIPAL_KINDS = ("service", "human")

SEAL_PREFIX = "af1:sha256:"


class RegistryError(Exception):
    """A registry mutation was refused.

    Refusal is total: the registry is left exactly as it was. Callers must treat this
    as a denial, never as "try again with less validation".
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _seal(payload: dict[str, Any]) -> str:
    """Seal a payload with the same construction used for receipts and approvals."""
    return SEAL_PREFIX + full_digest(payload)[:32]


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{field} must be a non-empty string.")
    v = value.strip()
    if is_wildcard(v):
        raise RegistryError(
            f"{field} '{v}' is a wildcard. Wildcards are an implicit allow and are refused."
        )
    return v


def _clean_grants(values: Any, *, field: str, subject: str) -> tuple[str, ...]:
    """Normalise a grant list. Empty is legal and means "grants nothing"."""
    if isinstance(values, str):
        raise RegistryError(
            f"{field} for '{subject}' must be a sequence of strings, not a bare string."
        )
    if values is None:
        raise RegistryError(f"{field} for '{subject}' is required (use () for none).")
    try:
        items = list(values)
    except TypeError:
        raise RegistryError(f"{field} for '{subject}' must be a sequence of strings.") from None
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise RegistryError(f"{field} for '{subject}' contains an empty or non-string entry.")
        v = item.strip()
        if is_wildcard(v):
            raise RegistryError(
                f"{field} for '{subject}' contains wildcard '{v}'. "
                "A wildcard grant is an implicit allow and is refused at registration."
            )
        out.append(v)
    return tuple(sorted(set(out)))


# ---------------------------------------------------------------------------
# Agent record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentRecord:
    """An immutable agent identity record.

    Mutations produce a new record with a bumped ``version``; the old record is never
    edited in place, so a sealed snapshot of the registry can always be re-verified.
    """

    agent_id: str
    owner: str
    capabilities: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    lifecycle_state: str
    created_at: int
    rotated_at: int | None = None
    revoked_at: int | None = None
    version: int = 1
    record_integrity: str = ""

    def payload(self) -> dict[str, Any]:
        """The exact object ``record_integrity`` is computed over."""
        return {
            "agent_id": self.agent_id,
            "owner": self.owner,
            "capabilities": list(self.capabilities),
            "allowed_origins": list(self.allowed_origins),
            "lifecycle_state": self.lifecycle_state,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "revoked_at": self.revoked_at,
            "version": self.version,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["record_integrity"] = self.record_integrity
        return d

    @property
    def active(self) -> bool:
        return self.lifecycle_state == ACTIVE

    def grants(self, capability: str) -> bool:
        """True only if the agent is active AND that exact capability is granted."""
        return self.active and capability in self.capabilities

    def admits_origin(self, origin: str) -> bool:
        """True only if the agent is active AND that exact origin is permitted."""
        return self.active and origin in self.allowed_origins

    def verify(self) -> bool:
        return bool(self.record_integrity) and self.record_integrity == _seal(self.payload())


def _seal_record(record: AgentRecord) -> AgentRecord:
    return replace(record, record_integrity=_seal(record.payload()))


# ---------------------------------------------------------------------------
# Registry receipts — the mutation audit trail
# ---------------------------------------------------------------------------


@dataclass
class RegistryReceipt:
    """Evidence that a registry mutation happened, and of what it changed.

    Sealed with the same ``af1:sha256`` construction as an execution Receipt, and
    linked to the previous registry receipt by ``prev_hash``, so the mutation history
    is append-only and tamper-evident as a sequence rather than record by record.
    """

    receipt_id: str
    chain_index: int
    prev_hash: str
    operation: str
    subject: str
    actor: str
    before_digest: str
    after_digest: str
    after_state: dict[str, Any]
    registry_version: int
    timestamp: str
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def compute_integrity(self) -> str:
        d = self.to_dict()
        d.pop("integrity_hash", None)
        self.integrity_hash = _seal(d)
        return self.integrity_hash

    def verify(self) -> bool:
        d = self.to_dict()
        d.pop("integrity_hash", None)
        return bool(self.integrity_hash) and self.integrity_hash == _seal(d)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class AgentRegistry:
    """An in-process agent registry with a hash-linked mutation journal.

    An instance created with ``AgentRegistry()`` is EMPTY and therefore denies every
    agent. Demo seed data is applied explicitly by :func:`default_registry`, which
    makes the difference between "empty" and "seeded" visible rather than implicit.
    """

    def __init__(self) -> None:
        self._principals: dict[str, dict[str, Any]] = {}
        self._origins: dict[str, dict[str, Any]] = {}
        self._records: dict[str, AgentRecord] = {}
        self._journal: list[RegistryReceipt] = []
        self._version = 0

    # -- read surface -------------------------------------------------------

    @property
    def version(self) -> int:
        return self._version

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._records.get(agent_id)

    def agents(self) -> tuple[str, ...]:
        return tuple(sorted(self._records))

    def principals(self) -> tuple[str, ...]:
        return tuple(sorted(self._principals))

    def origins(self) -> tuple[str, ...]:
        """Declared execution boundaries. A fleet-level fact, not per-agent state."""
        return tuple(sorted(self._origins))

    def records(self) -> tuple[AgentRecord, ...]:
        return tuple(self._records[k] for k in sorted(self._records))

    def journal(self) -> tuple[RegistryReceipt, ...]:
        return tuple(self._journal)

    def state_digest(self) -> str:
        """Deterministic digest of registry STATE (not of the journal).

        A gate receipt can carry this to prove which registry configuration produced
        the decision, without the digest changing every time an unrelated receipt is
        appended.
        """
        return full_digest(
            {
                "agents": [r.payload() for r in self.records()],
                "principals": {k: self._principals[k] for k in sorted(self._principals)},
                "origins": {k: self._origins[k] for k in sorted(self._origins)},
            }
        )

    # -- integrity ----------------------------------------------------------

    def verify_chain(self) -> tuple[bool, str]:
        """Re-verify the whole mutation journal: index, links and each seal."""
        prev = ""
        for i, rcpt in enumerate(self._journal):
            if rcpt.chain_index != i:
                return False, f"receipt {i}: chain_index is {rcpt.chain_index}, expected {i}"
            if rcpt.prev_hash != prev:
                return False, f"receipt {i}: prev_hash does not match the previous receipt"
            if not rcpt.verify():
                return False, f"receipt {i}: integrity_hash does not verify"
            prev = rcpt.integrity_hash
        return True, "ok"

    def verify_records(self) -> tuple[bool, str]:
        for rec in self.records():
            if not rec.verify():
                return False, f"agent '{rec.agent_id}': record_integrity does not verify"
        return True, "ok"

    # -- internals ----------------------------------------------------------

    def _commit(
        self,
        *,
        operation: str,
        subject: str,
        actor: str,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
        at_ms: int,
    ) -> RegistryReceipt:
        self._version += 1
        rcpt = RegistryReceipt(
            receipt_id=short_id("RGST"),
            chain_index=len(self._journal),
            prev_hash=self._journal[-1].integrity_hash if self._journal else "",
            operation=operation,
            subject=subject,
            actor=actor,
            before_digest=full_digest(before_state),
            after_digest=full_digest(after_state),
            after_state=after_state,
            registry_version=self._version,
            timestamp=iso_ms(at_ms),
        )
        rcpt.compute_integrity()
        self._journal.append(rcpt)
        return rcpt

    def _require_actor(self, actor: str) -> str:
        a = _require_id(actor, "actor")
        if a not in self._principals:
            raise RegistryError(f"actor '{a}' is not a registered principal.")
        return a

    def _existing(self, agent_id: str) -> AgentRecord:
        aid = _require_id(agent_id, "agent_id")
        rec = self._records.get(aid)
        if rec is None:
            raise RegistryError(f"agent '{aid}' is not registered.")
        return rec

    # -- mutations ----------------------------------------------------------

    def register_principal(
        self,
        principal_id: str,
        *,
        kind: str = "service",
        actor: str,
        at_ms: int | None = None,
    ) -> RegistryReceipt:
        """Register a principal. Bootstrapping: while the registry is EMPTY, the first
        principal may only register itself, so an empty registry cannot be seized by
        an arbitrary caller."""
        pid = _require_id(principal_id, "principal_id")
        if kind not in PRINCIPAL_KINDS:
            raise RegistryError(f"kind must be one of {PRINCIPAL_KINDS}, got '{kind}'.")
        if pid in self._principals:
            raise RegistryError(f"principal '{pid}' is already registered.")
        if self._principals:
            self._require_actor(actor)
        elif _require_id(actor, "actor") != pid:
            raise RegistryError(
                "the first principal must bootstrap itself: actor must equal principal_id."
            )
        t = now_ms() if at_ms is None else int(at_ms)
        entry = {"principal_id": pid, "kind": kind, "created_at": t}
        self._principals[pid] = entry
        return self._commit(
            operation="REGISTER_PRINCIPAL",
            subject=pid,
            actor=actor,
            before_state={},
            after_state=dict(entry),
            at_ms=t,
        )

    def register_origin(self, origin_id: str, *, actor: str, at_ms: int | None = None) -> RegistryReceipt:
        """Declare an execution boundary. Agents may only be granted declared origins."""
        oid = _require_id(origin_id, "origin_id")
        actor = self._require_actor(actor)
        if oid in self._origins:
            raise RegistryError(f"origin '{oid}' is already declared.")
        t = now_ms() if at_ms is None else int(at_ms)
        entry = {"origin_id": oid, "created_at": t}
        self._origins[oid] = entry
        return self._commit(
            operation="REGISTER_ORIGIN",
            subject=oid,
            actor=actor,
            before_state={},
            after_state=dict(entry),
            at_ms=t,
        )

    def register_agent(
        self,
        agent_id: str,
        owner: str,
        capabilities: Iterable[str],
        allowed_origins: Iterable[str],
        *,
        actor: str,
        at_ms: int | None = None,
    ) -> RegistryReceipt:
        """Register an agent. Refuses duplicates, unknown owners, undeclared origins
        and any wildcard grant."""
        aid = _require_id(agent_id, "agent_id")
        owner = _require_id(owner, "owner")
        if aid in self._records:
            raise RegistryError(f"agent '{aid}' is already registered.")
        if owner not in self._principals:
            raise RegistryError(f"owner '{owner}' is not a registered principal.")
        actor = self._require_actor(actor)

        caps = _clean_grants(capabilities, field="capabilities", subject=aid)
        origins = _clean_grants(allowed_origins, field="allowed_origins", subject=aid)
        undeclared = [o for o in origins if o not in self._origins]
        if undeclared:
            raise RegistryError(
                f"agent '{aid}' requests undeclared origin(s) {undeclared}; "
                "declare the boundary with register_origin first."
            )

        t = now_ms() if at_ms is None else int(at_ms)
        rec = _seal_record(
            AgentRecord(
                agent_id=aid,
                owner=owner,
                capabilities=caps,
                allowed_origins=origins,
                lifecycle_state=ACTIVE,
                created_at=t,
                rotated_at=None,
                revoked_at=None,
                version=1,
            )
        )
        self._records[aid] = rec
        return self._commit(
            operation="REGISTER_AGENT",
            subject=aid,
            actor=actor,
            before_state={},
            after_state=rec.to_dict(),
            at_ms=t,
        )

    def rotate_agent(
        self,
        agent_id: str,
        *,
        actor: str,
        capabilities: Iterable[str] | None = None,
        allowed_origins: Iterable[str] | None = None,
        at_ms: int | None = None,
    ) -> RegistryReceipt:
        """Replace the credentials/grants of an existing agent.

        Rotation never silently widens: omitted fields keep their current value, and
        whatever is supplied is re-validated (wildcards still refused, origins must
        still be declared).
        """
        rec = self._existing(agent_id)
        actor = self._require_actor(actor)
        if rec.lifecycle_state == REVOKED:
            raise RegistryError(f"agent '{rec.agent_id}' is revoked; revocation is terminal.")
        if capabilities is None and allowed_origins is None:
            raise RegistryError("rotate requires capabilities and/or allowed_origins.")

        caps = rec.capabilities if capabilities is None else _clean_grants(
            capabilities, field="capabilities", subject=rec.agent_id
        )
        origins = rec.allowed_origins if allowed_origins is None else _clean_grants(
            allowed_origins, field="allowed_origins", subject=rec.agent_id
        )
        undeclared = [o for o in origins if o not in self._origins]
        if undeclared:
            raise RegistryError(
                f"agent '{rec.agent_id}' requests undeclared origin(s) {undeclared}."
            )

        t = now_ms() if at_ms is None else int(at_ms)
        new = _seal_record(
            replace(
                rec,
                capabilities=caps,
                allowed_origins=origins,
                rotated_at=t,
                version=rec.version + 1,
                record_integrity="",
            )
        )
        self._records[rec.agent_id] = new
        return self._commit(
            operation="ROTATE_AGENT",
            subject=rec.agent_id,
            actor=actor,
            before_state=rec.payload(),
            after_state=new.to_dict(),
            at_ms=t,
        )

    def suspend_agent(self, agent_id: str, *, actor: str, at_ms: int | None = None) -> RegistryReceipt:
        """Temporarily withdraw an agent. Reversible; grants are preserved."""
        rec = self._existing(agent_id)
        actor = self._require_actor(actor)
        if rec.lifecycle_state == REVOKED:
            raise RegistryError(f"agent '{rec.agent_id}' is revoked; revocation is terminal.")
        if rec.lifecycle_state == SUSPENDED:
            raise RegistryError(f"agent '{rec.agent_id}' is already suspended.")
        t = now_ms() if at_ms is None else int(at_ms)
        new = _seal_record(
            replace(rec, lifecycle_state=SUSPENDED, version=rec.version + 1, record_integrity="")
        )
        self._records[rec.agent_id] = new
        return self._commit(
            operation="SUSPEND_AGENT",
            subject=rec.agent_id,
            actor=actor,
            before_state=rec.payload(),
            after_state=new.to_dict(),
            at_ms=t,
        )

    def reinstate_agent(self, agent_id: str, *, actor: str, at_ms: int | None = None) -> RegistryReceipt:
        """Return a suspended agent to active service."""
        rec = self._existing(agent_id)
        actor = self._require_actor(actor)
        if rec.lifecycle_state not in RESTORABLE_STATES:
            raise RegistryError(
                f"agent '{rec.agent_id}' is {rec.lifecycle_state}; only {RESTORABLE_STATES} "
                "can be reinstated."
            )
        t = now_ms() if at_ms is None else int(at_ms)
        new = _seal_record(
            replace(rec, lifecycle_state=ACTIVE, version=rec.version + 1, record_integrity="")
        )
        self._records[rec.agent_id] = new
        return self._commit(
            operation="REINSTATE_AGENT",
            subject=rec.agent_id,
            actor=actor,
            before_state=rec.payload(),
            after_state=new.to_dict(),
            at_ms=t,
        )

    def revoke_agent(self, agent_id: str, *, actor: str, at_ms: int | None = None) -> RegistryReceipt:
        """Permanently withdraw an agent. Terminal: no transition out of REVOKED."""
        rec = self._existing(agent_id)
        actor = self._require_actor(actor)
        if rec.lifecycle_state == REVOKED:
            raise RegistryError(f"agent '{rec.agent_id}' is already revoked.")
        t = now_ms() if at_ms is None else int(at_ms)
        new = _seal_record(
            replace(rec, lifecycle_state=REVOKED, revoked_at=t, version=rec.version + 1, record_integrity="")
        )
        self._records[rec.agent_id] = new
        return self._commit(
            operation="REVOKE_AGENT",
            subject=rec.agent_id,
            actor=actor,
            before_state=rec.payload(),
            after_state=new.to_dict(),
            at_ms=t,
        )

    # -- snapshot / restore (test and operational hygiene) -------------------

    def snapshot(self) -> dict[str, Any]:
        return {
            "principals": {k: dict(v) for k, v in self._principals.items()},
            "origins": {k: dict(v) for k, v in self._origins.items()},
            "records": {k: v.to_dict() for k, v in self._records.items()},
            "journal": [r.to_dict() for r in self._journal],
            "version": self._version,
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        self._principals = {k: dict(v) for k, v in snapshot["principals"].items()}
        self._origins = {k: dict(v) for k, v in snapshot["origins"].items()}
        self._records = {
            k: AgentRecord(
                agent_id=v["agent_id"],
                owner=v["owner"],
                capabilities=tuple(v["capabilities"]),
                allowed_origins=tuple(v["allowed_origins"]),
                lifecycle_state=v["lifecycle_state"],
                created_at=v["created_at"],
                rotated_at=v["rotated_at"],
                revoked_at=v["revoked_at"],
                version=v["version"],
                record_integrity=v["record_integrity"],
            )
            for k, v in snapshot["records"].items()
        }
        self._journal = [
            RegistryReceipt(
                receipt_id=r["receipt_id"],
                chain_index=r["chain_index"],
                prev_hash=r["prev_hash"],
                operation=r["operation"],
                subject=r["subject"],
                actor=r["actor"],
                before_digest=r["before_digest"],
                after_digest=r["after_digest"],
                after_state=r["after_state"],
                registry_version=r["registry_version"],
                timestamp=r["timestamp"],
                integrity_hash=r["integrity_hash"],
            )
            for r in snapshot["journal"]
        ]
        self._version = snapshot["version"]


# ---------------------------------------------------------------------------
# Demo seed + process-wide default
# ---------------------------------------------------------------------------

# The demo fleet, expressed as data instead of three tuples. This is seed data for the
# shipped demo, NOT a default that silently applies to a fresh registry: AgentRegistry()
# stays empty, and only default_registry() is seeded.
DEMO_PRINCIPALS: tuple[tuple[str, str], ...] = (
    ("svc-research", "service"),
    ("svc-support", "service"),
    ("svc-analytics", "service"),
    ("human.jay", "human"),
)

DEMO_ORIGINS: tuple[str, ...] = ("CRM-A", "CRM-B", "CRM-C")

# agent_id, owner, capabilities, allowed_origins
DEMO_AGENTS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("research-agent", "svc-research", ("customer.read", "customer.write", "customer.export"), ("CRM-A",)),
    ("support-agent", "svc-support", ("customer.read",), ("CRM-A", "CRM-B")),
    ("analytics-agent", "svc-analytics", ("customer.read", "customer.export"), ("CRM-B", "CRM-C")),
)


def build_seeded_registry(at_ms: int | None = None) -> AgentRegistry:
    """Construct the demo registry through the public mutation API.

    Deliberately goes through register_* rather than poking internals, so the seed
    itself is journalled and the shipped registry can prove where its state came from.

    Pass ``at_ms`` to pin every seed timestamp, which makes ``state_digest()``
    reproducible across processes (without it, timestamps are wall-clock).
    """
    reg = AgentRegistry()
    first, first_kind = DEMO_PRINCIPALS[0]
    reg.register_principal(first, kind=first_kind, actor=first, at_ms=at_ms)
    for pid, kind in DEMO_PRINCIPALS[1:]:
        reg.register_principal(pid, kind=kind, actor=first, at_ms=at_ms)
    for origin in DEMO_ORIGINS:
        reg.register_origin(origin, actor=first, at_ms=at_ms)
    for aid, owner, caps, origins in DEMO_AGENTS:
        reg.register_agent(aid, owner, caps, origins, actor=first, at_ms=at_ms)
    return reg


_DEFAULT: AgentRegistry | None = None


def default_registry() -> AgentRegistry:
    """The process-wide registry the execution gate consults."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = build_seeded_registry()
    return _DEFAULT


def reset_default_registry() -> AgentRegistry:
    """Rebuild the default registry from seed. Intended for tests and demos only."""
    global _DEFAULT
    _DEFAULT = build_seeded_registry()
    return _DEFAULT
