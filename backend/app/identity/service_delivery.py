"""Recoverable append-only SQL-to-Mongo delivery; not an import command or API.

The SQL adapter must commit source assertion and prepared delivery together,
enforce unique (raw_record_id, writer_policy), and append completion receipts.
Concrete SQL storage and intake authorization are intentionally separate gates.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Protocol
from uuid import UUID

from bson import BSON, Binary
from bson.codec_options import CodecOptions
from pymongo.errors import DuplicateKeyError

from app.identity.service_plan import REQUIRED, ROUTES, SERVICE_PLAN_POLICY
from app.identity.service_values import SERVICE_VALUE_POLICY
from app.storage.mongo_contract import PROPERTIES, encryption_context

WRITER_POLICY = "HR_SERVICE_EVIDENCE_V1"


@dataclass(frozen=True)
class PreparedDelivery:
    # Persist these exact BSON bytes before Mongo insertion: retries must reuse
    # the same event ID, timestamp, nonce and ciphertext, not regenerate them.
    document_bson: bytes = field(repr=False)
    document_sha256: str

    def document(self):
        if type(self.document_bson) is not bytes or len(self.document_bson) > 12 * 1024 * 1024:
            raise ValueError("Invalid delivery size/type.")
        if hashlib.sha256(self.document_bson).hexdigest() != self.document_sha256:
            raise ValueError("Prepared delivery digest differs.")
        return BSON(self.document_bson).decode(codec_options=CodecOptions(tz_aware=True))


class DeliveryLedger(Protocol):
    """Adapter contract; its real PostgreSQL implementation remains required."""

    def prepare_once(self, proposed: PreparedDelivery) -> PreparedDelivery:
        """Atomically commit assertion + outbox, or return the existing winner.

        SQL uniqueness must resolve concurrent attempts. Validate the source,
        officer and provenance before returning an existing prepared record.
        """
        ...

    def completion_digest(self, event_id: str) -> str | None:
        """Return an immutable completion receipt, if committed."""
        ...

    def complete_once(self, prepared: PreparedDelivery) -> str:
        """Commit one append-only receipt or return the existing receipt digest."""
        ...


def check_payload(payload):
    """Allow planned evidence only, never silently promote it to current truth."""
    if (payload.get("schema_version"), payload.get("policy_version"),
        payload.get("value_policy_version"), payload.get("logical_destination"),
        payload.get("record_classification"), payload.get("needs_review")) != (
        "1.0", SERVICE_PLAN_POLICY, SERVICE_VALUE_POLICY,
        "mongodb.service_status_events", "UNASSESSED", False):
        raise ValueError("Service payload is unsupported or requires review.")
    if any(payload.get(f) is not None for f in ("snapshot_date", "valid_from", "valid_to")):
        raise ValueError("Unknown temporal applicability must remain unknown.")
    if payload.get("review_issues") != []:
        raise ValueError("Unresolved consistency review cannot be delivered.")
    fields = payload.get("fields")
    if not isinstance(fields, list) or len(fields) != len(ROUTES):
        raise ValueError("Service field coverage differs.")
    names = [f.get("source_column") for f in fields]
    if len(set(names)) != len(ROUTES) or set(names) != set(ROUTES):
        raise ValueError("Service fields are duplicated or missing.")
    for item in fields:
        if item.get("target_field") != ROUTES[item["source_column"]] or item.get("status") not in {"PARSED", "MISSING"}:
            raise ValueError("Service field routing or review status differs.")
        if not isinstance(item.get("source_value"), str):
            raise ValueError("Original source text must be preserved.")
        if item["source_column"] in REQUIRED and (item["status"] != "PARSED" or not item["source_value"].strip()):
            raise ValueError("Required service evidence is missing.")
    # A JSON roundtrip rejects unsupported values/NaN and copies caller-owned data.
    return json.loads(json.dumps(payload, allow_nan=False))


def validate_document(document):
    """Reject malformed envelope metadata before any adapter is called."""
    if set(document) != set(PROPERTIES):
        raise ValueError("Mongo envelope fields differ.")
    for name in ("_id", "officer_uid", "source_assertion_uid"):
        value = document[name]
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("Canonical opaque UUID is required.")
    if not isinstance(document["raw_record_id"], str) or re.fullmatch("[0-9a-f]{64}", document["raw_record_id"]) is None:
        raise ValueError("Invalid source-row binding.")
    if (document["writer_policy"], document["classification"]) != (WRITER_POLICY, "UNASSESSED"):
        raise ValueError("Unexpected policy/classification.")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("Unexpected schema version.")
    date = document["recorded_at"]
    if not isinstance(date, datetime) or date.utcoffset() is None:
        raise ValueError("An aware recorded timestamp is required.")
    key = document["payload_key_version"]
    if not isinstance(key, str) or not 1 <= len(key) <= 128:
        raise ValueError("Invalid encryption key version.")
    if not isinstance(document["payload_ciphertext"], (bytes, Binary)) or len(document["payload_ciphertext"]) < 29:
        raise ValueError("Invalid encrypted payload.")


def make_delivery(crypto, backup, payload, *, event_id, assertion_id, recorded_at):
    """Create a candidate; this does not establish accepted identity/source linkage."""
    expected = check_payload(payload)
    if not isinstance(recorded_at, datetime) or recorded_at.utcoffset() is None:
        raise ValueError("An aware recorded timestamp is required.")
    # This is transaction recording time, never an inferred state-effective date.
    recorded = recorded_at.astimezone(timezone.utc)
    recorded = recorded.replace(microsecond=recorded.microsecond // 1000 * 1000)
    document = dict(_id=str(event_id), officer_uid=expected["officer_uid"],
                    source_assertion_uid=str(assertion_id), raw_record_id=expected["raw_record_id"],
                    writer_policy=WRITER_POLICY, schema_version=1, classification="UNASSESSED",
                    recorded_at=recorded, payload_key_version=crypto.active_encryption_version)
    cipher, version = crypto.encrypt_assertion(expected, context=encryption_context(document))
    if version != document["payload_key_version"]:
        raise ValueError("Encryption version changed during preparation.")
    document["payload_ciphertext"] = Binary(cipher)
    validate_document(document)
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    verify_delivery(prepared, crypto, backup, expected)
    return prepared


def verify_delivery(prepared, crypto, backup, expected_payload):
    expected = check_payload(expected_payload)
    document = prepared.document()
    validate_document(document)
    if (document["officer_uid"], document["raw_record_id"]) != (expected["officer_uid"], expected["raw_record_id"]):
        raise ValueError("Prepared source/officer binding differs.")
    binding = dict(key_version=document["payload_key_version"], context=encryption_context(document))
    # Both key copies must recover the exact source plan, not merely parse JSON.
    if crypto.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Prepared service evidence differs from source plan.")
    if backup.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Backup service recovery differs.")
    return document


def verify_mongo(collection, document):
    """Never repair a mismatch by updating/deleting existing evidence."""
    existing = collection.find_one({"raw_record_id": document["raw_record_id"],
                                    "writer_policy": document["writer_policy"]})
    if existing is not None and existing != document:
        raise ValueError("Mongo evidence differs from committed preparation; stop for review.")
    return existing is not None


def deliver(ledger, collection, proposed, *, crypto, backup, expected_payload):
    """Prepare SQL -> append Mongo -> verify readback -> append SQL receipt.

    A timeout at any point is an unknown outcome. Retry this protocol; do not
    roll back by deleting evidence from either database.
    """
    verify_delivery(proposed, crypto, backup, expected_payload)
    prepared = ledger.prepare_once(proposed)
    document = verify_delivery(prepared, crypto, backup, expected_payload)
    receipt = ledger.completion_digest(document["_id"])
    if receipt is not None and receipt != prepared.document_sha256:
        raise ValueError("SQL completion receipt differs.")
    exists = verify_mongo(collection, document)
    if receipt is not None and not exists:
        # Missing evidence after a completed import is an integrity incident,
        # not an ordinary unfinished delivery that should be silently repaired.
        raise ValueError("Completed Mongo evidence is missing; stop for integrity review.")
    if not exists:
        try:
            result = collection.insert_one(document)
            if not result.acknowledged:
                raise RuntimeError("Mongo delivery was not acknowledged.")
        except DuplicateKeyError:
            # Another worker may have inserted the identical prepared document.
            # Readback must prove that, including ciphertext/provenance equality.
            pass
        if not verify_mongo(collection, document):
            raise RuntimeError("Mongo evidence was not recovered after insertion.")
    if receipt is None and ledger.complete_once(prepared) != prepared.document_sha256:
        raise ValueError("SQL completion receipt differs.")
    # Verify receipt readback as well as the adapter's acknowledgment.
    if ledger.completion_digest(document["_id"]) != prepared.document_sha256:
        raise ValueError("SQL completion receipt was not recovered.")
    return "VERIFIED_EXISTING" if receipt is not None else "COMPLETED"


def reconcile(ledger, collection, prepared, *, crypto, backup, expected_payload):
    """Read-only reconciliation must not fill missing documents or receipts."""
    document = verify_delivery(prepared, crypto, backup, expected_payload)
    if not verify_mongo(collection, document):
        raise ValueError("Mongo evidence is missing.")
    if ledger.completion_digest(document["_id"]) != prepared.document_sha256:
        raise ValueError("SQL completion receipt is missing or differs.")
    return "VERIFIED_EXISTING"
