"""
Fix 1 — authenticated authorization issuance.

The gap: ``POST /api/authorize`` was anonymous and accepted no credential, so any
caller reachable over HTTPS could mint an authorization naming any principal it liked.
The gate then did its job faithfully and enforced authority the attacker had just
invented. ``GET /api/state`` and ``GET /api/expire`` were the same hole behind different
URLs — both hand back a sealed, usable authorization object.

The fix, and what each test here proves:

  * issuance requires a signed credential verified against a server-side secret
    (``test_unauthenticated_*``)
  * the principal comes from the credential and is never caller-asserted
    (``test_credential_principal_wins``, ``test_claimed_principal_mismatch_refused``)
  * ``AuthorizationType: NONE`` is refused explicitly
    (``test_authorization_type_none_*``)
  * an unauthenticated request gets 401 with NO authorization object
    (``test_no_authorization_object_on_any_failure``)
  * a missing server secret fails closed rather than disabling the check
    (``test_missing_server_secret_fails_closed``)

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.api import DEMO_SCENARIO, lambda_handler
from agentfence.auth import (
    AuthError,
    MAX_CREDENTIAL_TTL_MS,
    authenticate_caller,
    resolve_auth_secret,
    sign_credential,
    verify_credential,
)

ISSUANCE_BODY = {
    "agent": "research-agent",
    "capability": "customer.read",
    "action": "read",
    "resource": "customer/123",
    "origin": "CRM-A",
    "task": "TASK-184",
}


def secret() -> str:
    return os.environ["AGENTFENCE_AUTH_SECRET"]


def bearer(principal: str = "svc-research", **kw) -> dict:
    return {"Authorization": f"Bearer {sign_credential(principal, secret=secret(), **kw)}"}


def post(path: str, body=None, headers=None):
    event = {
        "httpMethod": "POST",
        "path": path,
        "body": json.dumps(body) if body is not None else None,
        "headers": headers or {},
    }
    return lambda_handler(event, None)


def get(path: str, headers=None):
    return lambda_handler(
        {"httpMethod": "GET", "path": path, "body": None, "headers": headers or {}}, None
    )


def payload(resp) -> dict:
    return json.loads(resp["body"])


# ==========================================================================
# Unauthenticated issuance is refused
# ==========================================================================


class TestUnauthenticatedIssuance:
    def test_authorize_without_credential_is_401(self):
        r = post("/api/authorize", ISSUANCE_BODY)
        assert r["statusCode"] == 401
        p = payload(r)
        assert p["error"] == "MISSING_CREDENTIAL"
        assert "authorization" not in p

    def test_authorize_with_body_principal_but_no_credential_is_401(self):
        """The old attack: name a principal, get an authorization for it."""
        body = dict(ISSUANCE_BODY, principal="human.jay")
        r = post("/api/authorize", body)
        assert r["statusCode"] == 401
        assert "authorization" not in payload(r)

    def test_state_without_credential_is_401(self):
        """GET /api/state also mints an authorization, so it is also a boundary."""
        r = get("/api/state")
        assert r["statusCode"] == 401
        assert "authorization" not in payload(r)

    def test_expire_without_credential_is_401(self):
        r = get("/api/expire")
        assert r["statusCode"] == 401
        assert "authorization" not in payload(r)

    def test_approve_without_credential_is_401(self):
        r = post("/api/approve", {"authorization": {"authorization_id": "AUTH-X"}})
        assert r["statusCode"] == 401
        assert "approval" not in payload(r)

    def test_health_stays_public(self):
        """Liveness must not require a credential; it mints nothing."""
        assert get("/health")["statusCode"] == 200


# ==========================================================================
# AuthorizationType: NONE is rejected explicitly
# ==========================================================================


class TestAuthorizationTypeNone:
    def test_header_authorization_type_none_rejected(self):
        r = post("/api/authorize", ISSUANCE_BODY, {"X-Authorization-Type": "NONE"})
        assert r["statusCode"] == 401
        p = payload(r)
        assert p["error"] == "AUTHORIZATION_TYPE_NONE_REJECTED"
        assert "authorization" not in p

    def test_scheme_none_rejected(self):
        r = post("/api/authorize", ISSUANCE_BODY, {"Authorization": "NONE"})
        assert r["statusCode"] == 401
        assert payload(r)["error"] == "AUTHORIZATION_TYPE_NONE_REJECTED"

    def test_body_authorization_type_none_rejected(self):
        body = dict(ISSUANCE_BODY, AuthorizationType="NONE")
        r = post("/api/authorize", body, bearer())
        assert r["statusCode"] == 401
        assert payload(r)["error"] == "AUTHORIZATION_TYPE_NONE_REJECTED"
        assert "authorization" not in payload(r)

    @pytest.mark.parametrize("value", ["NONE", "none", " Null ", "ANONYMOUS"])
    def test_none_family_value_rejected(self, value):
        with pytest.raises(AuthError) as exc:
            authenticate_caller({"X-Authorization-Type": value})
        assert exc.value.code == "AUTHORIZATION_TYPE_NONE_REJECTED"

    def test_unsupported_scheme_rejected(self):
        with pytest.raises(AuthError) as exc:
            authenticate_caller({"Authorization": "Basic dXNlcjpwYXNz"})
        assert exc.value.code == "UNSUPPORTED_AUTHORIZATION_TYPE"


# ==========================================================================
# The principal comes from the credential, never from the caller
# ==========================================================================


class TestPrincipalDerivation:
    def test_issued_authorization_uses_credential_principal(self):
        r = post("/api/authorize", ISSUANCE_BODY, bearer("svc-support"))
        assert r["statusCode"] == 200
        p = payload(r)
        assert p["authorization"]["principal"] == "svc-support"
        assert p["issued_to"] == "svc-support"

    def test_body_principal_is_ignored_when_absent_and_not_trusted(self):
        r = post("/api/authorize", ISSUANCE_BODY, bearer("svc-analytics"))
        assert payload(r)["authorization"]["principal"] == "svc-analytics"

    def test_claimed_principal_mismatch_refused(self):
        """Body claims one principal, credential proves another -> explicit refusal."""
        body = dict(ISSUANCE_BODY, principal="human.jay")
        r = post("/api/authorize", body, bearer("svc-research"))
        assert r["statusCode"] == 403
        p = payload(r)
        assert p["error"] == "PRINCIPAL_NOT_AUTHENTICATED"
        assert "authorization" not in p

    @pytest.mark.parametrize(
        "alias", ["SVC-RESEARCH", "svc_research", " svc.research ", "svc-research@corp"]
    )
    def test_aliased_principal_matches_credential(self, alias):
        """An alias of your own identity is still your identity, not a mismatch."""
        body = dict(ISSUANCE_BODY, principal=alias)
        r = post("/api/authorize", body, bearer("svc-research"))
        assert r["statusCode"] == 200
        # ...and the authorization still carries the canonical credential principal.
        assert payload(r)["authorization"]["principal"] == "svc-research"

    def test_plus_tag_alias_cannot_borrow_another_principal(self):
        """``svc+tag@corp`` canonicalizes to ``svc``, so it is NOT svc-research."""
        body = dict(ISSUANCE_BODY, principal="svc+tag@corp")
        r = post("/api/authorize", body, bearer("svc-research"))
        assert r["statusCode"] == 403
        assert payload(r)["error"] == "PRINCIPAL_NOT_AUTHENTICATED"

    def test_state_requires_the_demo_principal(self):
        r = get("/api/state", bearer("svc-support"))
        assert r["statusCode"] == 403
        assert "authorization" not in payload(r)

    def test_state_succeeds_for_demo_principal(self):
        r = get("/api/state", bearer("svc-research"))
        assert r["statusCode"] == 200
        assert payload(r)["authorization"]["principal"] == DEMO_SCENARIO["principal"]


# ==========================================================================
# Credential verification, negative cases
# ==========================================================================


class TestCredentialVerification:
    def test_wrong_secret_rejected(self):
        # Generated here, not committed: a literal secret in the repo — even a throwaway
        # one — is exactly what the credential scanner is meant to catch.
        token = sign_credential("svc-research", secret=secrets.token_hex(32))
        r = post("/api/authorize", ISSUANCE_BODY, {"Authorization": f"Bearer {token}"})
        assert r["statusCode"] == 401
        assert payload(r)["error"] == "INVALID_CREDENTIAL_SIGNATURE"

    def test_tampered_payload_rejected(self):
        token = sign_credential("svc-research", secret=secret())
        prefix, body, sig = token.split(".")
        # Re-encode the payload claiming a different principal, keep the old signature.
        forged_body = __import__("base64").urlsafe_b64encode(
            json.dumps({"aud": "agentfence", "exp": 9999999999999, "iat": 0,
                        "p": "human.jay", "v": 1}, sort_keys=True,
                       separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        r = post("/api/authorize", ISSUANCE_BODY,
                 {"Authorization": f"Bearer {prefix}.{forged_body}.{sig}"})
        assert r["statusCode"] == 401
        assert payload(r)["error"] == "INVALID_CREDENTIAL_SIGNATURE"

    def test_expired_credential_rejected(self):
        token = sign_credential("svc-research", secret=secret(), ttl_ms=1,
                                issued_at_ms=int(time.time() * 1000) - 10_000)
        with pytest.raises(AuthError) as exc:
            verify_credential(token, secret=secret())
        assert exc.value.code == "CREDENTIAL_EXPIRED"

    def test_not_yet_valid_credential_rejected(self):
        token = sign_credential("svc-research", secret=secret(),
                                issued_at_ms=int(time.time() * 1000) + 60_000)
        with pytest.raises(AuthError) as exc:
            verify_credential(token, secret=secret())
        assert exc.value.code == "CREDENTIAL_NOT_YET_VALID"

    @pytest.mark.parametrize("token", ["", "garbage", "afcred1.onlytwo", "a.b.c", "afcred1.."])
    def test_malformed_credentials_rejected(self, token):
        with pytest.raises(AuthError) as exc:
            verify_credential(token, secret=secret())
        assert exc.value.code in {"MALFORMED_CREDENTIAL", "MISSING_CREDENTIAL",
                                  "INVALID_CREDENTIAL_SIGNATURE"}

    def test_wrong_audience_rejected(self):
        token = sign_credential("svc-research", secret=secret(), audience="someone-else")
        with pytest.raises(AuthError) as exc:
            verify_credential(token, secret=secret())
        assert exc.value.code == "CREDENTIAL_WRONG_AUDIENCE"

    def test_missing_server_secret_fails_closed(self, monkeypatch):
        """
        No secret configured means nobody can be authenticated — never "auth disabled".

        The token below is well-formed, so it reaches the secret lookup rather than being
        rejected earlier for bad syntax.
        """
        well_formed = sign_credential("svc-research", secret=secret())
        monkeypatch.delenv("AGENTFENCE_AUTH_SECRET", raising=False)
        assert resolve_auth_secret() is None
        r = post("/api/authorize", ISSUANCE_BODY, {"Authorization": f"Bearer {well_formed}"})
        assert r["statusCode"] == 503
        p = payload(r)
        assert p["error"] == "CREDENTIAL_VERIFICATION_UNAVAILABLE"
        assert "authorization" not in p

    def test_blank_secret_is_treated_as_absent(self):
        assert resolve_auth_secret("   ") is None

    def test_sign_refuses_empty_principal(self):
        with pytest.raises(ValueError):
            sign_credential("  ", secret=secret())

    def test_sign_refuses_empty_secret(self):
        with pytest.raises(ValueError):
            sign_credential("svc-research", secret="")

    def test_credential_ttl_is_capped(self):
        token = sign_credential("svc-research", secret=secret(), ttl_ms=10 * MAX_CREDENTIAL_TTL_MS)
        p = verify_credential(token, secret=secret())
        assert p["exp"] - p["iat"] <= MAX_CREDENTIAL_TTL_MS

    def test_skew_never_extends_a_credential(self):
        """
        Skew shortens the acceptance window; it must never lengthen it.
        """
        now = int(time.time() * 1000)
        token = sign_credential("svc-research", secret=secret(), ttl_ms=10_000, issued_at_ms=now - 20_000)
        # The credential expired ~10s ago. A large skew must not resurrect it.
        with pytest.raises(AuthError):
            verify_credential(token, secret=secret(), now_ms=now, skew_ms=60_000)


# ==========================================================================
# Failure responses are never success-shaped
# ==========================================================================


class TestNoAuthorizationObjectOnAnyFailure:
    @pytest.mark.parametrize(
        "headers,body",
        [
            ({}, ISSUANCE_BODY),
            ({"Authorization": "NONE"}, ISSUANCE_BODY),
            ({"Authorization": "Bearer bad"}, ISSUANCE_BODY),
            ({"X-Authorization-Type": "NONE"}, ISSUANCE_BODY),
            ({"Authorization": "Bearer bad"}, dict(ISSUANCE_BODY, AuthorizationType="NONE")),
        ],
    )
    def test_no_authorization_key(self, headers, body):
        r = post("/api/authorize", body, headers)
        p = payload(r)
        assert r["statusCode"] >= 400
        assert "authorization" not in p
        # Nothing that even looks like a minted authority.
        serialized = json.dumps(p)
        assert "integrity_value" not in serialized
        assert "authorization_id" not in serialized

    def test_missing_bound_field_still_400_after_auth(self):
        body = {k: v for k, v in ISSUANCE_BODY.items() if k != "task"}
        r = post("/api/authorize", body, bearer())
        assert r["statusCode"] == 400
        assert "authorization" not in payload(r)

    def test_issuance_rules_still_apply_to_authenticated_callers(self):
        """Authentication does not buy a wildcard binding."""
        body = dict(ISSUANCE_BODY, origin="*")
        r = post("/api/authorize", body, bearer())
        assert r["statusCode"] == 400
        assert payload(r)["error"] == "ISSUANCE_REFUSED"
