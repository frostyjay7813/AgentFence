"""
AgentFence — pre-effect receipt sealing (HMAC) and chain verification.

The problem this module solves
------------------------------
Receipts used to be produced *after* the effect, and were sealed with a bare SHA-256
of their own contents. That is a checksum, not evidence: anyone who can write a
receipt can recompute it, and a crash between the effect and the receipt write leaves
an effect with no record at all.

What changed
------------
  * Receipts are built and sealed BEFORE the effect is attempted, so the record of the
    authorization decision exists before anything observable happens.
  * The seal is an HMAC-SHA256 under a server-side key read from
    ``AGENTFENCE_RECEIPT_HMAC_KEY``. Without that key the gate fails closed: it refuses
    to emit an unkeyed receipt, because an unkeyed receipt is indistinguishable from an
    attacker-authored one.
  * Each receipt carries ``seq`` and ``prev_hash``, so receipts form a chain and
    :func:`verify_chain` can detect a removed, reordered or edited receipt rather than
    validating each one in isolation.

Two hashes, two jobs
--------------------
``integrity_hash`` is the legacy self-hash (``af1:sha256:``) over the receipt body with
the seal fields removed. It is retained because the existing suite and evidence
artifacts depend on it, and it still catches accidental corruption.

``hmac_value`` (``af2:hmac-sha256:``) is the actual seal: it covers the full receipt
including ``integrity_hash``, ``seq`` and ``prev_hash``, keyed with a secret the
receipt author does not have. ``verify_chain`` checks both.

Key handling rules
------------------
  * The key is read from the environment only. It is never written, logged, echoed in
    an error, or included in a receipt.
  * The key must be at least 16 bytes; a shorter key is treated as unconfigured
    (RECEIPT_KEY_UNAVAILABLE) rather than accepted as weak-but-fine.
  * Hex keys (64 hex chars) are decoded to their 32 raw bytes; other values are used
    as raw UTF-8 bytes. Both are operator choices; neither is a default in the repo.
  * Tests generate an ephemeral key per run. No key material appears in the repo.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Iterable

from .core import full_digest

ENV_RECEIPT_KEY = "AGENTFENCE_RECEIPT_HMAC_KEY"

HMAC_PREFIX = "af2:hmac-sha256:"
INTEGRITY_PREFIX = "af1:sha256:"
MIN_KEY_BYTES = 16

# Fields that are part of the seal rather than the sealed body.
_SEAL_FIELDS = ("integrity_hash", "hmac_value")


def resolve_receipt_key(explicit: str | bytes | None = None) -> bytes | None:
    """
    Resolve the receipt HMAC key, or ``None`` if it is absent/too weak.

    Returns bytes so the key never has to be re-encoded differently in different
    call sites. ``None`` means "cannot seal" — the gate must DENY, never emit an
    unkeyed receipt.
    """
    raw: Any = explicit if explicit is not None else os.environ.get(ENV_RECEIPT_KEY)
    if raw is None:
        return None
    if isinstance(raw, bytes):
        key = raw
    elif isinstance(raw, str):
        if not raw.strip():
            return None
        text = raw.strip()
        # 64 hex chars is an unambiguous 32-byte key encoding.
        if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
            try:
                key = bytes.fromhex(text)
            except ValueError:
                key = text.encode("utf-8")
        else:
            key = text.encode("utf-8")
    else:
        return None
    if len(key) < MIN_KEY_BYTES:
        return None
    return key


def receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    """The part of a receipt covered by ``integrity_hash`` (seal fields removed)."""
    body = dict(receipt)
    for f in _SEAL_FIELDS:
        body.pop(f, None)
    return body


def receipt_integrity_hash(receipt: dict[str, Any]) -> str:
    """
    Legacy self-hash over the receipt body.

    Deliberately NOT the security boundary on its own — see the module docstring. It
    stays byte-compatible with the existing evidence format so previously published
    receipts remain verifiable, and it is one of the two checks ``verify_chain`` runs.
    """
    return INTEGRITY_PREFIX + full_digest(receipt_body(receipt))[:32]


def receipt_hmac(receipt: dict[str, Any], key: bytes) -> str:
    """HMAC-SHA256 over the full receipt (minus the seal itself), keyed server-side."""
    body = {k: v for k, v in receipt.items() if k != "hmac_value"}
    # Canonical form comes from core via full_digest's serializer, so the sealed bytes
    # are stable across platforms and key ordering.
    from .core import canonical

    digest = hmac.new(key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return HMAC_PREFIX + digest


def verify_receipt_seal(receipt: dict[str, Any], key: bytes) -> bool:
    """Constant-time check of a single receipt's HMAC."""
    presented = receipt.get("hmac_value") or ""
    if not isinstance(presented, str) or not presented.startswith(HMAC_PREFIX):
        return False
    expected = receipt_hmac(receipt, key)
    return hmac.compare_digest(expected, presented)


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def verify_chain(
    receipts: Iterable[dict[str, Any]],
    key: bytes | str | None = None,
    *,
    require_genesis: bool = False,
) -> tuple[bool, str, int | None]:
    """
    Verify a sequence of sealed receipts.

    Returns ``(ok, reason, index)`` where ``index`` is the position that failed (or
    ``None`` when ok).

    Checks, in order, per receipt:
      1. the self-hash ``integrity_hash`` recomputes (corruption / plain editing)
      2. the HMAC ``hmac_value`` verifies under the server key (forgery)
      3. ``seq`` is strictly increasing by exactly 1 (a gap means missing evidence)
      4. ``prev_hash`` equals the previous receipt's ``hmac_value`` (reordering,
         substitution, or removal)

    ``require_genesis`` additionally demands that the first receipt links to the empty
    genesis hash, which is what the chain store produces for its very first append.

    An empty input verifies as ok: there is nothing to contradict. Callers who need to
    prove that evidence *exists* must check that the list is non-empty themselves.
    """
    resolved = resolve_receipt_key(key) if key is not None else resolve_receipt_key()
    if resolved is None:
        return False, "RECEIPT_KEY_UNAVAILABLE", None

    items = list(receipts)
    prev_hmac = "" if require_genesis else None
    prev_seq: int | None = None

    for i, rc in enumerate(items):
        if not isinstance(rc, dict):
            return False, "MALFORMED_RECEIPT", i

        if rc.get("integrity_hash") != receipt_integrity_hash(rc):
            return False, "INTEGRITY_MISMATCH", i

        if not verify_receipt_seal(rc, resolved):
            return False, "HMAC_INVALID", i

        seq = rc.get("seq")
        if not isinstance(seq, int):
            return False, "MISSING_SEQ", i
        if prev_seq is not None and seq != prev_seq + 1:
            return False, "SEQ_NOT_MONOTONIC", i

        if prev_hmac is not None:
            if (rc.get("prev_hash") or "") != prev_hmac:
                return False, "PREV_HASH_MISMATCH", i

        prev_hmac = rc.get("hmac_value") or ""
        prev_seq = seq

    return True, "", None
