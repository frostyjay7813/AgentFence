"""
AgentFence — single-use authorization store and pre-effect receipt chain.

Two small store interfaces, each with an in-memory default and a DynamoDB
implementation behind conditional configuration:

  * :class:`ConsumeStore` — records that an authorization has been spent.
  * :class:`ReceiptChain` — appends sealed receipts and returns chain linkage so a
    receipt can be proven to belong to a sequence rather than standing alone.

Honest atomicity claims
-----------------------
The in-memory store guarantees at-most-once consumption **within a single process,
across threads**. It is guarded by a lock and the check-and-set happens under that
lock, so two threads cannot both win. It does NOT guarantee it across processes,
across Lambda container instances, across cold starts, or across a restart: each
process has its own dictionary, so N instances of the service permit up to N
consumptions of the same authorization. That limitation is real and is why the
DynamoDB implementation exists: ``put_item`` with ``attribute_not_exists`` is a single
conditional write that the storage layer executes atomically, which is what actually
holds under concurrency and across instances.

The gate therefore uses whichever store the deployment configures, and refuses to run
in a production mode without one. It never silently substitutes the weaker in-memory
guarantee for the stronger one it was told to use.

Fail-closed resolution
----------------------
:func:`resolve_consume_store` returns an :class:`UnavailableConsumeStore` when the
deployment is configured for production but no store is configured. Every operation on
that object raises :class:`StoreUnavailable`, and the gate converts that into a DENY.
An unconfigured store is a denial, never an implicit allow and never a quiet
downgrade to in-memory.

Zero third-party runtime dependencies: ``boto3`` is imported lazily inside the
DynamoDB paths, and only when a table has actually been configured. The Lambda runtime
provides it; nothing is required to import this module or to run the demo.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any, Protocol

ENV_CONSUME_TABLE = "AGENTFENCE_CONSUME_TABLE"
ENV_RECEIPT_TABLE = "AGENTFENCE_RECEIPT_TABLE"
ENV_MODE = "AGENTFENCE_MODE"

# Modes in which a missing store is a hard failure rather than a demo convenience.
PRODUCTION_MODES = {"LIVE", "PROD", "PRODUCTION", "AWS"}


class StoreUnavailable(Exception):
    """
    Raised when a store cannot perform its operation.

    The gate turns this into a DENY. It must never be swallowed and must never be
    interpreted as "nothing was consumed".
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class ConsumeRecord:
    """What a consume store persists. Kept small: it is a lock, not an audit log."""

    authorization_id: str
    consumed_at_ms: int
    expires_at_ms: int
    binding_digest: str = ""


class ConsumeStore(Protocol):
    """Minimal single-use interface the gate depends on."""

    name: str

    def consume(self, record: ConsumeRecord) -> bool:
        """
        Atomically mark ``record.authorization_id`` as spent.

        Returns True if THIS call performed the transition (first use, caller may
        proceed). Returns False if it was already spent (caller must deny).
        Raises :class:`StoreUnavailable` if the store cannot answer — never returns
        True optimistically.
        """
        ...


class InMemoryConsumeStore:
    """
    Process-local single-use store.

    Atomicity: a single ``threading.Lock`` guards the contains-check and the insert, so
    the check-and-set is atomic across threads in ONE process. Two processes sharing
    nothing will each allow one consumption. This is sufficient for the demo and for a
    single-process deployment, and it is NOT sufficient for a horizontally scaled one —
    configure ``AGENTFENCE_CONSUME_TABLE`` for that.

    Expired records are purged lazily so the dictionary cannot grow without bound.
    Purging is safe because an authorization past its retention horizon is already
    refused by the validity stage before consumption is ever attempted.
    """

    name = "memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, ConsumeRecord] = {}

    def consume(self, record: ConsumeRecord) -> bool:
        if not record.authorization_id:
            # Defensive: an anonymous record cannot be a lock.
            raise StoreUnavailable("CONSUME_RECORD_INVALID", "record has no authorization id")
        with self._lock:
            self._purge_locked(record.consumed_at_ms)
            if record.authorization_id in self._seen:
                return False
            self._seen[record.authorization_id] = record
            return True

    def _purge_locked(self, now_ms: int) -> None:
        dead = [k for k, v in self._seen.items() if now_ms > v.expires_at_ms]
        for k in dead:
            del self._seen[k]

    def __len__(self) -> int:  # observability for tests
        with self._lock:
            return len(self._seen)

    def reset(self) -> None:
        """Forget all consumptions. For tests and for process re-initialisation only."""
        with self._lock:
            self._seen.clear()


class DynamoDBConsumeStore:
    """
    DynamoDB single-use store using one conditional write.

    Atomicity: ``put_item`` with ``ConditionExpression="attribute_not_exists(pk)"`` is a
    single-item conditional write, which DynamoDB evaluates atomically. Concurrent
    consumers race on that condition and exactly one wins. This is the only
    implementation here whose guarantee survives multiple processes and instances.

    The table must have ``pk`` as its partition key. A TTL attribute lets DynamoDB
    expire spent records; the gate never depends on that for correctness.
    """

    name = "dynamodb"

    def __init__(self, table_name: str, table: Any = None) -> None:
        self._table_name = table_name
        self._table = table

    def _resolve_table(self) -> Any:
        if self._table is not None:
            return self._table
        try:  # pragma: no cover - exercised only with real AWS credentials
            import boto3

            self._table = boto3.resource(
                "dynamodb", region_name=os.environ.get("AWS_REGION")
            ).Table(self._table_name)
        except Exception as exc:  # pragma: no cover
            raise StoreUnavailable(
                "CONSUME_STORE_UNAVAILABLE", f"cannot reach consume table: {type(exc).__name__}"
            ) from exc
        return self._table

    def consume(self, record: ConsumeRecord) -> bool:
        if not record.authorization_id:
            raise StoreUnavailable("CONSUME_RECORD_INVALID", "record has no authorization id")
        table = self._resolve_table()
        item = {
            "pk": f"AUTHZ#{record.authorization_id}",
            "authorization_id": record.authorization_id,
            "consumed_at_ms": int(record.consumed_at_ms),
            "expires_at_ms": int(record.expires_at_ms),
            "binding_digest": record.binding_digest,
        }
        try:
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except Exception as exc:
            # Distinguish "already spent" (a legitimate deny) from "cannot answer"
            # (a store outage that must also deny, but for a different reason).
            code = type(exc).__name__
            if code == "ConditionalCheckFailedException":
                return False
            raise StoreUnavailable(
                "CONSUME_STORE_UNAVAILABLE", f"consume write failed: {code}"
            ) from exc


class UnavailableConsumeStore:
    """
    A store that always fails. Returned when a production deployment has no store
    configured, so the gate DENIES instead of degrading to allow.
    """

    name = "unavailable"

    def __init__(self, reason: str = "no consume store configured") -> None:
        self._reason = reason

    def consume(self, record: ConsumeRecord) -> bool:
        raise StoreUnavailable("CONSUME_STORE_UNAVAILABLE", self._reason)


# ---------------------------------------------------------------------------
# Receipt chain
# ---------------------------------------------------------------------------


class ReceiptChain(Protocol):
    """Append-only sequenced log the gate writes sealed receipts into."""

    name: str

    def allocate(self) -> tuple[int, str]:
        """
        Reserve the next chain position, returning ``(seq, prev_hash)``.

        Split from :meth:`persist` because the seal must cover ``seq`` and
        ``prev_hash``: the position has to be known before the receipt can be sealed.
        Raises :class:`StoreUnavailable` if no position can be reserved.
        """
        ...

    def persist(self, receipt: dict[str, Any]) -> None:
        """Store a sealed receipt at the position previously allocated for it."""
        ...


class InMemoryReceiptChain:
    """
    Process-local append-only chain.

    Durability: holds receipts in a list in this process only. Adequate to prove
    ordering and linkage within a run; it does not survive a crash. The pre-effect
    guarantee the gate relies on is therefore only as strong as the configured chain:
    with the in-memory chain, "persisted before the effect" means "recorded in this
    process before the effect". A durable chain (DynamoDB) is what makes it survive a
    crash, and is why the production resolution refuses to fall back to this.
    """

    name = "memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[dict[str, Any]] = []
        self._next_seq = 0
        self._last_hmac = ""

    def allocate(self) -> tuple[int, str]:
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            return seq, self._last_hmac

    def persist(self, receipt: dict[str, Any]) -> None:
        with self._lock:
            stored = dict(receipt)
            self._items.append(stored)
            self._last_hmac = stored.get("hmac_value", "") or ""

    def receipts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(i) for i in sorted(self._items, key=lambda d: d.get("seq", 0))]

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
            self._next_seq = 0
            self._last_hmac = ""


class UnavailableReceiptChain:
    """A chain that always fails, used to refuse production with no durable chain."""

    name = "unavailable"

    def __init__(self, reason: str = "no receipt chain configured") -> None:
        self._reason = reason

    def allocate(self) -> tuple[int, str]:
        raise StoreUnavailable("RECEIPT_PERSIST_FAILED", self._reason)

    def persist(self, receipt: dict[str, Any]) -> None:
        raise StoreUnavailable("RECEIPT_PERSIST_FAILED", self._reason)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def current_mode(mode: str | None = None) -> str:
    return (mode or os.environ.get(ENV_MODE, "DEMO")).upper()


def is_production_mode(mode: str | None = None) -> bool:
    return current_mode(mode) in PRODUCTION_MODES


def resolve_consume_store(mode: str | None = None, table: Any = None) -> ConsumeStore:
    """
    Choose the consume store for this deployment.

    Configured table -> DynamoDB (the strong guarantee).
    Otherwise production -> unavailable (DENY). Never silently in-memory.
    Otherwise (demo/local) -> the shared in-memory store.
    """
    name = os.environ.get(ENV_CONSUME_TABLE)
    if name:
        return DynamoDBConsumeStore(name, table=table)
    if is_production_mode(mode):
        return UnavailableConsumeStore(
            "AGENTFENCE_CONSUME_TABLE is not configured and mode is production"
        )
    return _DEFAULT_CONSUME_STORE


def resolve_receipt_chain(mode: str | None = None, table: Any = None) -> ReceiptChain:
    """Same resolution rule as :func:`resolve_consume_store`, for the receipt chain."""
    name = os.environ.get(ENV_RECEIPT_TABLE)
    if name:
        return DynamoDBReceiptChain(name, table=table)
    if is_production_mode(mode):
        return UnavailableReceiptChain(
            "AGENTFENCE_RECEIPT_TABLE is not configured and mode is production"
        )
    return _DEFAULT_RECEIPT_CHAIN


class DynamoDBReceiptChain:
    """
    DynamoDB-backed receipt chain.

    Each receipt is written as its own item. Ordering is by a monotonically increasing
    ``seq`` obtained from a counter item, and ``prev_hash`` links to the previous
    receipt's HMAC. Honest limitation: the counter increment and the link read are two
    operations, so two concurrent writers can interleave and produce a chain that
    ``verify_chain`` will report as broken — which is the correct, detectable outcome
    (a broken chain is evidence of a problem, not a silent success). Producing a
    perfectly linear chain across writers needs a single serialising writer.
    """

    name = "dynamodb"

    def __init__(self, table_name: str, table: Any = None) -> None:
        self._table_name = table_name
        self._table = table

    def _resolve_table(self) -> Any:
        if self._table is not None:
            return self._table
        try:  # pragma: no cover
            import boto3

            self._table = boto3.resource(
                "dynamodb", region_name=os.environ.get("AWS_REGION")
            ).Table(self._table_name)
        except Exception as exc:  # pragma: no cover
            raise StoreUnavailable(
                "RECEIPT_PERSIST_FAILED", f"cannot reach receipt table: {type(exc).__name__}"
            ) from exc
        return self._table

    def allocate(self) -> tuple[int, str]:
        table = self._resolve_table()
        try:
            counter = table.update_item(
                Key={"pk": "CHAIN#receipts"},
                UpdateExpression="ADD seq :one",
                ExpressionAttributeValues={":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            seq = int(counter["Attributes"]["seq"]) - 1
            prev = ""
            last = table.query(
                KeyConditionExpression="pk = :p",
                ExpressionAttributeValues={":p": "RCPT#LATEST"},
                ScanIndexForward=False,
                Limit=1,
            )
            items = last.get("Items") or []
            if items:
                prev = items[0].get("hmac_value", "") or ""
            return seq, prev
        except StoreUnavailable:
            raise
        except Exception as exc:
            raise StoreUnavailable(
                "RECEIPT_PERSIST_FAILED", f"chain allocation failed: {type(exc).__name__}"
            ) from exc

    def persist(self, receipt: dict[str, Any]) -> None:
        table = self._resolve_table()
        try:
            stored = dict(receipt)
            seq = int(stored.get("seq", 0))
            stored["pk"] = f"RCPT#{seq}"
            table.put_item(Item=stored)
            table.put_item(
                Item={
                    "pk": "RCPT#LATEST",
                    "hmac_value": stored.get("hmac_value", ""),
                    "seq": seq,
                }
            )
        except StoreUnavailable:
            raise
        except Exception as exc:
            raise StoreUnavailable(
                "RECEIPT_PERSIST_FAILED", f"receipt write failed: {type(exc).__name__}"
            ) from exc


# Shared process-local defaults. These are module-level so that consumption persists
# across calls to enforce() within a process — otherwise single-use would be a
# per-call fiction.
_DEFAULT_CONSUME_STORE = InMemoryConsumeStore()
_DEFAULT_RECEIPT_CHAIN = InMemoryReceiptChain()


def default_consume_store() -> InMemoryConsumeStore:
    return _DEFAULT_CONSUME_STORE


def default_receipt_chain() -> InMemoryReceiptChain:
    return _DEFAULT_RECEIPT_CHAIN


def reset_default_stores() -> None:
    """Clear the process-local defaults. Used by tests and by a full service restart."""
    _DEFAULT_CONSUME_STORE.reset()
    _DEFAULT_RECEIPT_CHAIN.reset()
