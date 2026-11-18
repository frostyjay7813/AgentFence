"""
AgentFence — caller authentication for authorization issuance.

Why this module exists
----------------------
Before this module, ``POST /api/authorize`` was anonymous: any caller reachable over
HTTPS could mint an authorization naming any principal, and the gate would then
faithfully enforce an authority the attacker had just invented. The gate was correct
and the boundary in front of it was absent. This module closes that boundary at the
application layer.

What it is — and is not
-----------------------
This is deliberately NOT an identity provider. It is the smallest thing that can
carry an authenticated caller identity into the issuance path:

  * a compact, URL-safe credential signed with HMAC-SHA256 using a server-side secret
  * the secret is read from the environment (``AGENTFENCE_AUTH_SECRET``) and never
    committed, never logged, and never returned
  * the principal is taken from the SIGNED PAYLOAD only

There is no client-supplied field anywhere in the decision: a caller cannot assert
``principal`` in the body and have it used, because the issuance path derives the
principal exclusively from the verified credential.

Fail-closed posture
-------------------
Every failure raises :class:`AuthError` carrying a stable ``code``. There is no code
path that returns a principal on error, and no permissive default. In particular the
API Gateway ``AuthorizationType: NONE`` posture that the deployment template still
declares is explicitly refused here: a request that declares no authorization type, or
declares ``NONE``, is rejected before any issuance logic runs.

Honest limitation: HMAC with a shared secret proves the caller holds a credential
minted by a holder of the same secret. It does not provide per-caller key isolation,
rotation without a restart, or revocation. Those require the asymmetric signing /
external authorization server called out in the README and in
``submission/KNOWN_LIMITATIONS.md``.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Mapping

CREDENTIAL_PREFIX = "afcred1"
CREDENTIAL_AUDIENCE = "agentfence"
ENV_AUTH_SECRET = "AGENTFENCE_AUTH_SECRET"

# A credential is a bearer token for a single issuance call; it has no reason to live
# long. Callers may request less, never more.
MAX_CREDENTIAL_TTL_MS = 3_600_000
DEFAULT_CREDENTIAL_TTL_MS = 300_000

# Header names we accept for the credential. The first is canonical; the second is
# tolerated because API Gateway normalises header casing inconsistently.
_AUTH_HEADER = "authorization"
_AUTH_TYPE_HEADER = "x-authorization-type"

# Values that mean "I am presenting no identity". These are rejected explicitly rather
# than being allowed to fall through to a "no header" branch, so the rejection reason
# is unambiguous in logs and tests.
_NONE_SCHEMES = {"", "NONE", "NULL", "ANONYMOUS", "OFF", "DISABLED"}


class AuthError(Exception):
    """
    Raised on any authentication failure.

    ``code`` is stable and machine-readable; ``status`` is the HTTP status the API
    layer must return. Defaults to 401: an authentication failure is never a 200 and
    never carries an authorization object.
    """

    def __init__(self, code: str, detail: str = "", status: int = 401) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code
        self.status = status


# ---------------------------------------------------------------------------
# Encoding helpers (stdlib only, URL-safe, no padding ambiguity)
# ---------------------------------------------------------------------------


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Secret resolution
# ---------------------------------------------------------------------------


def resolve_auth_secret(explicit: str | bytes | None = None) -> bytes | None:
    """
    Resolve the credential signing secret.

    Returns ``None`` when no usable secret is configured. Callers must treat ``None``
    as "cannot authenticate anyone" and deny — never as "authentication disabled".
    """
    value: Any = explicit if explicit is not None else os.environ.get(ENV_AUTH_SECRET)
    if value is None:
        return None
    if isinstance(value, bytes):
        return value if value.strip() else None
    if not isinstance(value, str):
        return None
    if not value.strip():
        return None
    return value.encode("utf-8")


# ---------------------------------------------------------------------------
# Credential mint / verify
# ---------------------------------------------------------------------------


def sign_credential(
    principal: str,
    *,
    secret: str | bytes,
    ttl_ms: int = DEFAULT_CREDENTIAL_TTL_MS,
    issued_at_ms: int | None = None,
    audience: str = CREDENTIAL_AUDIENCE,
) -> str:
    """
    Mint a signed credential for ``principal``.

    Used by tests and by the operator's issuing tool. The API surface itself never
    mints credentials from a request body — that would reintroduce the hole this
    module exists to close.
    """
    if not isinstance(principal, str) or not principal.strip():
        raise ValueError("cannot sign a credential for an empty principal")
    key = resolve_auth_secret(secret)
    if key is None:
        raise ValueError("cannot sign a credential without a non-empty secret")

    ttl = int(ttl_ms)
    if ttl <= 0:
        raise ValueError("credential ttl must be positive")
    ttl = min(ttl, MAX_CREDENTIAL_TTL_MS)

    iat = _now_ms() if issued_at_ms is None else int(issued_at_ms)
    payload = {
        "aud": audience,
        "exp": iat + ttl,
        "iat": iat,
        "p": principal,
        "v": 1,
    }
    body = _b64u_encode(_canonical(payload).encode("utf-8"))
    signing_input = f"{CREDENTIAL_PREFIX}.{body}".encode("utf-8")
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{CREDENTIAL_PREFIX}.{body}.{_b64u_encode(sig)}"


def verify_credential(
    token: str,
    *,
    secret: str | bytes,
    now_ms: int | None = None,
    skew_ms: int = 0,
    audience: str = CREDENTIAL_AUDIENCE,
) -> dict[str, Any]:
    """
    Verify a credential and return its signed payload, or raise :class:`AuthError`.

    Clock skew is applied in the only safe direction: the credential is treated as
    expired ``skew_ms`` EARLIER, and as not-yet-valid ``skew_ms`` LATER. Skew can
    therefore shorten a credential's acceptance window but never lengthen it.
    """
    if not isinstance(token, str) or not token.strip():
        raise AuthError("MISSING_CREDENTIAL", "No credential was presented.")

    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != CREDENTIAL_PREFIX:
        raise AuthError("MALFORMED_CREDENTIAL", "Credential is not in the expected format.")

    prefix, body, sig_b64 = parts
    key = resolve_auth_secret(secret)
    if key is None:
        # Fail closed: without a secret nothing can be verified.
        raise AuthError(
            "CREDENTIAL_VERIFICATION_UNAVAILABLE",
            "No credential verification secret is configured.",
            status=503,
        )

    try:
        presented_sig = _b64u_decode(sig_b64)
    except Exception:
        raise AuthError("MALFORMED_CREDENTIAL", "Credential signature is not valid base64.")

    expected_sig = hmac.new(
        key, f"{prefix}.{body}".encode("utf-8"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_sig, presented_sig):
        raise AuthError("INVALID_CREDENTIAL_SIGNATURE", "Credential signature does not verify.")

    try:
        payload = json.loads(_b64u_decode(body).decode("utf-8"))
    except Exception:
        raise AuthError("MALFORMED_CREDENTIAL", "Credential payload is not readable JSON.")
    if not isinstance(payload, dict):
        raise AuthError("MALFORMED_CREDENTIAL", "Credential payload must be an object.")

    if payload.get("aud") != audience:
        raise AuthError("CREDENTIAL_WRONG_AUDIENCE", "Credential was issued for a different audience.")

    principal = payload.get("p")
    if not isinstance(principal, str) or not principal.strip():
        raise AuthError("MALFORMED_CREDENTIAL", "Credential carries no principal.")

    try:
        iat = int(payload["iat"])
        exp = int(payload["exp"])
    except Exception:
        raise AuthError("MALFORMED_CREDENTIAL", "Credential carries no usable validity window.")

    t = _now_ms() if now_ms is None else int(now_ms)
    skew = max(0, int(skew_ms or 0))
    if t + skew < iat:
        raise AuthError("CREDENTIAL_NOT_YET_VALID", "Credential is not yet valid.")
    if t > exp - skew:
        raise AuthError("CREDENTIAL_EXPIRED", "Credential has expired.")

    return payload


# ---------------------------------------------------------------------------
# Request-level authentication
# ---------------------------------------------------------------------------


def _header(headers: Mapping[str, Any] | None, name: str) -> str | None:
    """Case-insensitive header lookup over a plain mapping."""
    if not headers:
        return None
    target = name.lower()
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == target and v is not None:
            return str(v)
    return None


def authenticate_caller(
    headers: Mapping[str, Any] | None,
    *,
    secret: str | bytes | None = None,
    now_ms: int | None = None,
    skew_ms: int = 0,
    audience: str = CREDENTIAL_AUDIENCE,
) -> str:
    """
    Resolve the authenticated principal for a request, or raise :class:`AuthError`.

    The principal comes from the verified credential and from nowhere else. A caller
    that supplies ``principal`` in the body has that value ignored by the issuance
    path; a caller that supplies a credential naming a principal gets exactly that
    principal.

    ``AuthorizationType: NONE`` — the posture the deployment template still declares at
    the gateway — is rejected here explicitly, so the application boundary does not
    depend on a gateway configuration that may be absent (as it is on ``serve.py``).
    """
    declared_type = _header(headers, _AUTH_TYPE_HEADER)
    if declared_type is not None and declared_type.strip().upper() in _NONE_SCHEMES:
        raise AuthError(
            "AUTHORIZATION_TYPE_NONE_REJECTED",
            "AuthorizationType NONE is not an acceptable authorization type for issuance.",
        )

    raw = _header(headers, _AUTH_HEADER)
    if raw is None or not raw.strip():
        raise AuthError("MISSING_CREDENTIAL", "No Authorization header was presented.")

    tokens = raw.strip().split()
    scheme = tokens[0] if tokens else ""
    if scheme.upper() in _NONE_SCHEMES:
        raise AuthError(
            "AUTHORIZATION_TYPE_NONE_REJECTED",
            "AuthorizationType NONE is not an acceptable authorization type for issuance.",
        )
    if scheme.lower() != "bearer":
        raise AuthError(
            "UNSUPPORTED_AUTHORIZATION_TYPE",
            f"Authorization scheme '{scheme}' is not accepted; use Bearer.",
        )
    if len(tokens) < 2:
        raise AuthError("MISSING_CREDENTIAL", "Bearer scheme presented with no credential.")

    payload = verify_credential(
        tokens[1], secret=secret, now_ms=now_ms, skew_ms=skew_ms, audience=audience
    )
    return str(payload["p"])


def parse_bearer(headers: Mapping[str, Any] | None) -> str | None:
    """Return the raw bearer token, or ``None``. Convenience for callers/tests."""
    raw = _header(headers, _AUTH_HEADER)
    if not raw:
        return None
    tokens = raw.strip().split()
    if len(tokens) >= 2 and tokens[0].lower() == "bearer":
        return tokens[1]
    return None
