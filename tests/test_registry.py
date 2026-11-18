"""Tests for the agent registry.

These tests exist to prove three separate things, which are worth keeping apart:

1. The registry is a strict replacement, not a relaxation. The demo seed reproduces the
   exact contents of the three static tuples it replaced, so no decision changes.

2. The registry fails closed. An empty registry admits nothing; a suspended or revoked
   agent admits nothing; an empty grant list is not a wildcard; a wildcard grant cannot
   be registered at all.

3. Every mutation is evidence. Each register/rotate/suspend/reinstate/revoke appends a
   sealed, hash-linked receipt, and tampering with that journal is detectable.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


import pytest

from agentfence import gate as gate_module
from agentfence.core import DENY_REASONS, issue
from agentfence.gate import enforce
from agentfence.policy import POLICY_VERSION
from agentfence.registry import (
    ACTIVE,
    REVOKED,
    SUSPENDED,
    AgentRecord,
    AgentRegistry,
    RegistryError,
    build_seeded_registry,
    default_registry,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def base_request(**over):
    req = {
        "principal": "svc-research",
        "agent": "research-agent",
        "capability": "customer.read",
        "action": "read",
        "resource": "customer/123",
        "origin": "CRM-A",
        "task": "TASK-184",
    }
    req.update(over)
    return req


def base_auth(**over):
    kw = dict(
        principal="svc-research",
        agent="research-agent",
        capability="customer.read",
        action="read",
        resource="customer/123",
        origin="CRM-A",
        task="TASK-184",
        policy_version=POLICY_VERSION,
    )
    kw.update(over)
    return issue(**kw)


def fresh_registry_with_principal():
    """A minimal, empty-except-bootstrap registry plus one extra principal + origin."""
    reg = AgentRegistry()
    reg.register_principal("svc-research", kind="service", actor="svc-research")
    reg.register_principal("human.jay", kind="human", actor="svc-research")
    reg.register_origin("CRM-A", actor="svc-research")
    reg.register_origin("CRM-B", actor="svc-research")
    return reg


@pytest.fixture
def registry():
    """Mutate the process-wide registry inside a test, then put it back exactly."""
    reg = default_registry()
    snapshot = reg.snapshot()
    try:
        yield reg
    finally:
        reg.restore(snapshot)


# ---------------------------------------------------------------------------
# 1. Strict replacement: the seed matches the tuples it replaced
# ---------------------------------------------------------------------------


class TestSeedPreservesLegacyContents:
    def test_agents_match_legacy_known_agents(self):
        reg = build_seeded_registry()
        assert set(reg.agents()) == {"research-agent", "support-agent", "analytics-agent"}

    def test_origins_match_legacy_known_origins(self):
        reg = build_seeded_registry()
        assert set(reg.origins()) == {"CRM-A", "CRM-B", "CRM-C"}

    def test_principals_match_legacy_known_principals(self):
        reg = build_seeded_registry()
        assert set(reg.principals()) == {
            "svc-research", "svc-support", "svc-analytics", "human.jay",
        }

    def test_seed_is_deterministic(self):
        """Two independently built registries agree on state, digest included.

        Timestamps are pinned here, because created_at is sealed into the record and
        therefore into state_digest by design.
        """
        a = build_seeded_registry(at_ms=1_700_000_000_000)
        b = build_seeded_registry(at_ms=1_700_000_000_000)
        assert a.state_digest() == b.state_digest()
        assert a.version == b.version
        assert a.agents() == b.agents()

    def test_state_digest_is_stable_for_an_unchanged_registry(self):
        reg = build_seeded_registry()
        first = reg.state_digest()
        assert reg.state_digest() == first
        reg.verify_chain()  # reading must not perturb state
        assert reg.state_digest() == first

    def test_default_registry_is_seeded(self):
        assert default_registry().get("research-agent") is not None


# ---------------------------------------------------------------------------
# 2. Fail-closed behaviour
# ---------------------------------------------------------------------------


class TestEmptyRegistryDeniesEverything:
    def test_fresh_registry_is_empty(self):
        reg = AgentRegistry()
        assert reg.agents() == ()
        assert reg.principals() == ()
        assert reg.origins() == ()
        assert reg.version == 0

    def test_gate_denies_every_agent_when_registry_is_empty(self, monkeypatch):
        """The strongest fail-closed assertion: no registry, no allow."""
        monkeypatch.setattr(gate_module, "default_registry", lambda: AgentRegistry())
        res = enforce(base_request(), base_auth())
        assert res.decision == "DENY"
        assert res.reason == "UNKNOWN_AGENT"
        assert res.stage == "3-registries"


class TestLifecycle:
    def test_unregistered_agent_denied(self, registry):
        registry.revoke_agent("research-agent", actor="human.jay")
        # even a correctly bound authorization cannot resurrect it
        res = enforce(base_request(), base_auth())
        assert res.decision == "DENY"
        assert res.reason == "AGENT_NOT_ACTIVE"

    def test_suspended_agent_denied(self, registry):
        registry.suspend_agent("research-agent", actor="human.jay")
        res = enforce(base_request(), base_auth())
        assert res.decision == "DENY"
        assert res.reason == "AGENT_NOT_ACTIVE"
        assert res.stage == "3-registries"
        assert res.received["lifecycle_state"] == SUSPENDED

    def test_suspension_is_reversible(self, registry):
        registry.suspend_agent("research-agent", actor="human.jay")
        assert enforce(base_request(), base_auth()).decision == "DENY"
        registry.reinstate_agent("research-agent", actor="human.jay")
        assert enforce(base_request(), base_auth()).decision == "ALLOW"

    def test_reinstated_agent_keeps_its_grants(self, registry):
        before = registry.get("research-agent")
        registry.suspend_agent("research-agent", actor="human.jay")
        registry.reinstate_agent("research-agent", actor="human.jay")
        after = registry.get("research-agent")
        assert after.capabilities == before.capabilities
        assert after.allowed_origins == before.allowed_origins
        assert after.lifecycle_state == ACTIVE

    def test_revocation_is_terminal(self, registry):
        registry.revoke_agent("research-agent", actor="human.jay")
        with pytest.raises(RegistryError):
            registry.reinstate_agent("research-agent", actor="human.jay")
        with pytest.raises(RegistryError):
            registry.rotate_agent("research-agent", actor="human.jay", capabilities=("customer.read",))
        with pytest.raises(RegistryError):
            registry.revoke_agent("research-agent", actor="human.jay")

    def test_revoked_agent_cannot_be_reactivated_by_rotation(self, registry):
        registry.revoke_agent("research-agent", actor="human.jay")
        assert enforce(base_request(), base_auth()).reason == "AGENT_NOT_ACTIVE"

    def test_suspend_twice_refused(self, registry):
        registry.suspend_agent("research-agent", actor="human.jay")
        with pytest.raises(RegistryError):
            registry.suspend_agent("research-agent", actor="human.jay")


class TestNoImplicitAllow:
    def test_empty_capability_list_grants_nothing(self, registry):
        registry.register_agent("locked-agent", "svc-research", (), ("CRM-A",), actor="human.jay")
        auth = base_auth(agent="locked-agent", principal="svc-research")
        res = enforce(base_request(agent="locked-agent"), auth)
        assert res.decision == "DENY"
        assert res.reason == "CAPABILITY_NOT_GRANTED"
        assert res.stage == "9-policy-scope"

    def test_empty_origin_list_admits_nothing(self, registry):
        registry.register_agent(
            "homeless-agent", "svc-research", ("customer.read",), (), actor="human.jay"
        )
        auth = base_auth(agent="homeless-agent", principal="svc-research")
        res = enforce(base_request(agent="homeless-agent"), auth)
        assert res.decision == "DENY"
        assert res.reason == "ORIGIN_NOT_GRANTED"

    @pytest.mark.parametrize("wildcard", ["*", "any", "ALL", "customer.*", "?"])
    def test_wildcard_capability_refused_at_registration(self, wildcard):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("w-agent", "svc-research", (wildcard,), ("CRM-A",), actor="human.jay")
        assert reg.get("w-agent") is None
        assert reg.agents() == ()

    @pytest.mark.parametrize("wildcard", ["*", "any", "CRM-*"])
    def test_wildcard_origin_refused_at_registration(self, wildcard):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("w-agent", "svc-research", ("customer.read",), (wildcard,), actor="human.jay")
        assert reg.get("w-agent") is None

    def test_wildcard_refused_on_rotation_too(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("r-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        with pytest.raises(RegistryError):
            reg.rotate_agent("r-agent", actor="human.jay", capabilities=("*",))
        # the failed rotation must not have partially applied
        assert reg.get("r-agent").capabilities == ("customer.read",)

    def test_bare_string_grant_refused(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("s-agent", "svc-research", "customer.read", ("CRM-A",), actor="human.jay")

    def test_empty_string_grant_refused(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("e-agent", "svc-research", ("",), ("CRM-A",), actor="human.jay")

    def test_registry_grant_cannot_create_a_policy_effect(self, registry):
        """A grant is necessary, never sufficient: policy still has the final word."""
        registry.register_agent(
            "teleporter", "svc-research", ("customer.teleport",), ("CRM-A",), actor="human.jay"
        )
        auth = base_auth(agent="teleporter", capability="customer.teleport", action="teleport")
        res = enforce(
            base_request(agent="teleporter", capability="customer.teleport", action="teleport"), auth
        )
        assert res.decision == "DENY"
        assert res.reason == "NO_SUCH_POLICY"

    def test_registry_grant_cannot_skip_required_approval(self, registry):
        """Granting customer.write does not turn REQUIRE_APPROVAL into ALLOW."""
        auth = base_auth(capability="customer.write", action="write")
        req = base_request(capability="customer.write", action="write")
        res = enforce(req, auth)
        assert res.decision == "DENY"
        assert res.reason == "APPROVAL_MISSING"


class TestRegistrationGuards:
    def test_owner_must_be_a_registered_principal(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("x-agent", "svc-unknown", ("customer.read",), ("CRM-A",), actor="human.jay")

    def test_actor_must_be_a_registered_principal(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("x-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="svc-ghost")

    def test_origin_must_be_declared_first(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_agent("x-agent", "svc-research", ("customer.read",), ("CRM-Z",), actor="human.jay")
        assert reg.get("x-agent") is None

    def test_duplicate_agent_refused(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("dup", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        with pytest.raises(RegistryError):
            reg.register_agent("dup", "svc-research", ("customer.write",), ("CRM-A",), actor="human.jay")

    def test_duplicate_principal_refused(self):
        reg = fresh_registry_with_principal()
        with pytest.raises(RegistryError):
            reg.register_principal("svc-research", actor="human.jay")

    def test_first_principal_must_bootstrap_itself(self):
        reg = AgentRegistry()
        with pytest.raises(RegistryError):
            reg.register_principal("svc-a", actor="someone-else")

    def test_empty_registry_cannot_be_seized_by_anonymous_actor(self):
        """No principals registered: only a self-bootstrap is possible."""
        reg = AgentRegistry()
        reg.register_principal("svc-a", actor="svc-a")
        assert reg.principals() == ("svc-a",)

    def test_registration_failure_leaves_registry_untouched(self):
        reg = fresh_registry_with_principal()
        before = reg.state_digest()
        with pytest.raises(RegistryError):
            reg.register_agent("bad", "svc-research", ("*",), ("CRM-A",), actor="human.jay")
        assert reg.state_digest() == before
        assert reg.agents() == ()


# ---------------------------------------------------------------------------
# 3. Mutation evidence: the receipt chain
# ---------------------------------------------------------------------------


class TestReceiptChain:
    def test_every_mutation_appends_a_receipt(self):
        reg = fresh_registry_with_principal()
        n = len(reg.journal())
        reg.register_agent("c-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        reg.rotate_agent("c-agent", actor="human.jay", capabilities=("customer.read", "customer.write"))
        reg.suspend_agent("c-agent", actor="human.jay")
        reg.reinstate_agent("c-agent", actor="human.jay")
        reg.revoke_agent("c-agent", actor="human.jay")
        assert len(reg.journal()) == n + 5
        assert [r.operation for r in reg.journal()[-5:]] == [
            "REGISTER_AGENT", "ROTATE_AGENT", "SUSPEND_AGENT", "REINSTATE_AGENT", "REVOKE_AGENT",
        ]

    def test_receipts_are_hash_linked(self):
        reg = fresh_registry_with_principal()
        journal = reg.journal()
        assert journal[0].prev_hash == ""
        for i, rcpt in enumerate(journal):
            assert rcpt.chain_index == i
            if i:
                assert rcpt.prev_hash == journal[i - 1].integrity_hash

    def test_chain_verifies(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("v-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        ok, detail = reg.verify_chain()
        assert ok is True, detail

    def test_tampering_with_a_journal_record_breaks_the_chain(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("t-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        assert reg.verify_chain()[0] is True
        reg.journal()[-1].after_state["capabilities"] = ["customer.write"]  # forge a wider grant
        ok, detail = reg.verify_chain()
        assert ok is False
        assert "integrity" in detail

    def test_removing_a_middle_record_breaks_the_chain(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("d-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        del reg._journal[1]  # noqa: SLF001 - deliberately simulating an edit to the log
        ok, _ = reg.verify_chain()
        assert ok is False

    def test_truncating_the_tail_is_NOT_detected_by_the_chain_alone(self):
        """Documented limitation, asserted so it cannot be forgotten.

        A hash chain proves internal consistency and ordering: it detects modification,
        reordering and deletion in the middle. It cannot detect that the most recent
        entries were simply dropped, because nothing external pins the head. Detecting
        truncation needs an out-of-band anchor (publish the head hash, or seal it into
        the DynamoDB audit record). This test asserts the limitation honestly rather
        than implying a stronger guarantee.
        """
        reg = fresh_registry_with_principal()
        reg.register_agent("t1", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        head_before = reg.journal()[-1].integrity_hash
        del reg._journal[-1]  # noqa: SLF001
        ok, _ = reg.verify_chain()
        assert ok is True, "the chain verifies a truncated prefix - this is the known gap"
        assert reg.journal()[-1].integrity_hash != head_before

    def test_receipts_carry_before_and_after_digests(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("b-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        rcpt = reg.journal()[-1]
        assert rcpt.before_digest != rcpt.after_digest
        assert len(rcpt.before_digest) == 64
        assert len(rcpt.after_digest) == 64

    def test_receipt_records_the_actor(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("a-agent", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        assert reg.journal()[-1].actor == "human.jay"

    def test_receipts_are_sealed_with_the_receipt_integrity_construction(self):
        reg = build_seeded_registry()
        for rcpt in reg.journal():
            assert rcpt.integrity_hash.startswith("af1:sha256:")
            assert rcpt.verify() is True


class TestRecordIntegrity:
    def test_records_are_sealed(self):
        reg = build_seeded_registry()
        ok, detail = reg.verify_records()
        assert ok is True, detail
        for rec in reg.records():
            assert rec.record_integrity.startswith("af1:sha256:")

    def test_forged_record_fails_verification(self):
        rec = AgentRecord(
            agent_id="forged",
            owner="svc-research",
            capabilities=("customer.read",),
            allowed_origins=("CRM-A",),
            lifecycle_state=ACTIVE,
            created_at=1,
            record_integrity="af1:sha256:deadbeef",
        )
        assert rec.verify() is False


# ---------------------------------------------------------------------------
# Rotation semantics
# ---------------------------------------------------------------------------


class TestRotation:
    def test_rotation_bumps_version_and_stamps_time(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("rot", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        before = reg.get("rot")
        assert before.rotated_at is None and before.version == 1
        reg.rotate_agent("rot", actor="human.jay", capabilities=("customer.read", "customer.export"))
        after = reg.get("rot")
        assert after.version == 2
        assert after.rotated_at is not None
        assert after.created_at == before.created_at
        assert after.capabilities == ("customer.export", "customer.read")

    def test_rotation_preserves_omitted_fields(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("rot2", "svc-research", ("customer.read",), ("CRM-A", "CRM-B"), actor="human.jay")
        reg.rotate_agent("rot2", actor="human.jay", capabilities=("customer.export",))
        rec = reg.get("rot2")
        assert rec.allowed_origins == ("CRM-A", "CRM-B")
        assert rec.capabilities == ("customer.export",)

    def test_rotation_requires_something_to_change(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("rot3", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        with pytest.raises(RegistryError):
            reg.rotate_agent("rot3", actor="human.jay")

    def test_rotation_can_narrow_grants(self, registry):
        """The point of a registry: withdrawal is a data change, not a deploy."""
        auth = base_auth()
        assert enforce(base_request(), auth).decision == "ALLOW"
        registry.rotate_agent(
            "research-agent", actor="human.jay", capabilities=("customer.write",)
        )
        res = enforce(base_request(), auth)
        assert res.decision == "DENY"
        assert res.reason == "CAPABILITY_NOT_GRANTED"

    def test_rotation_cannot_widen_to_undeclared_origin(self):
        reg = fresh_registry_with_principal()
        reg.register_agent("rot4", "svc-research", ("customer.read",), ("CRM-A",), actor="human.jay")
        with pytest.raises(RegistryError):
            reg.rotate_agent("rot4", actor="human.jay", allowed_origins=("CRM-Q",))


# ---------------------------------------------------------------------------
# Gate receipts are bound to the registry configuration that produced them
# ---------------------------------------------------------------------------


class TestGateReceiptBindsRegistry:
    def test_receipt_carries_registry_version_and_digest(self):
        reg = default_registry()
        res = enforce(base_request(), base_auth())
        assert res.receipt.registry_version == reg.version
        assert res.receipt.registry_digest == reg.state_digest()

    def test_digest_changes_after_a_mutation(self, registry):
        before = enforce(base_request(), base_auth()).receipt.registry_digest
        registry.suspend_agent("analytics-agent", actor="human.jay")
        after = enforce(base_request(), base_auth()).receipt.registry_digest
        assert before != after

    def test_registry_digest_does_not_perturb_determinism(self):
        a = enforce(base_request(), base_auth())
        b = enforce(base_request(), base_auth())
        assert a.receipt.registry_digest == b.receipt.registry_digest
        assert a.decision == b.decision == "ALLOW"


# ---------------------------------------------------------------------------
# HTTP surface: read-only
# ---------------------------------------------------------------------------


class TestNoMutationOverHttp:
    def test_there_is_no_registry_mutation_route(self):
        from agentfence.api import ROUTES

        registry_routes = {k: v for k, v in ROUTES.items() if "registry" in k}
        assert registry_routes, "expected a read-only registry route"
        for key in registry_routes:
            assert key.startswith("GET "), f"registry route must be read-only, found {key}"

    def test_registry_endpoint_reports_a_verified_chain(self):
        import json

        from agentfence.api import lambda_handler

        res = lambda_handler({"httpMethod": "GET", "path": "/api/registry", "body": None}, None)
        assert res["statusCode"] == 200
        body = json.loads(res["body"])
        assert body["mutable_over_http"] is False
        assert body["chain"]["ok"] is True
        assert body["records_verification"]["ok"] is True
        assert body["chain"]["length"] == len(default_registry().journal())

    def test_health_reports_registry_verification(self):
        import json

        from agentfence.api import lambda_handler

        res = lambda_handler({"httpMethod": "GET", "path": "/health", "body": None}, None)
        body = json.loads(res["body"])
        assert body["registry"]["chain_ok"] is True
        assert body["registry"]["records_ok"] is True
        assert body["capability"]["known_agents"] == len(default_registry().agents())


# ---------------------------------------------------------------------------
# Deny reasons stay a documented, closed set
# ---------------------------------------------------------------------------


class TestDenyReasonsAreDocumented:
    @pytest.mark.parametrize(
        "reason", ["AGENT_NOT_ACTIVE", "CAPABILITY_NOT_GRANTED", "ORIGIN_NOT_GRANTED"]
    )
    def test_new_reasons_are_in_the_public_reason_table(self, reason):
        assert reason in DENY_REASONS


# ---------------------------------------------------------------------------
# The gate must still expose no bypass surface after this change
# ---------------------------------------------------------------------------


class TestGateSurfaceUnchanged:
    def test_gate_still_has_no_bypass_parameter(self):
        import inspect

        params = set(inspect.signature(enforce).parameters)
        forbidden = {"skip_verify", "bypass", "debug", "allow_all", "trust", "force"}
        assert not (params & forbidden)
