"""Recoverable append-only SQL-to-Mongo delivery; not an import command or API.

The SQL adapter must commit source assertion and prepared delivery together,
enforce unique (raw_record_id, writer_policy), and append completion receipts.
The paired SQL adapter is included; intake authorization and import remain separate gates.
"""
from datetime import datetime, timezone
import json
import hashlib
import re
from typing import Protocol
from uuid import UUID

from bson import BSON, Binary
from pymongo.errors import DuplicateKeyError

from app.identity.history_plan import ROUTES, HISTORY_PLAN_POLICY, plan_history
from app.identity.history_plan_crypto import encoded
from app.identity.service_values import SERVICE_VALUE_POLICY
from app.identity.service_delivery import PreparedDelivery
from app.storage.history_mongo_contract import COLLECTION_POLICIES, properties, encryption_context as historical_context

FILE_COLLECTIONS = {"transfer_history.csv": "transfer_events", "promotion_history.csv": "promotion_events"}


def collection_for(payload):
    try:
        return FILE_COLLECTIONS[payload["filename"]]
    except (KeyError, TypeError):
        raise ValueError("Unsupported historical source filename.") from None


def document_collection(document):
    matching = [name for name, policy in COLLECTION_POLICIES.items() if policy == document.get("writer_policy")]
    if len(matching) != 1:
        raise ValueError("Unsupported historical writer policy.")
    return matching[0]


def encryption_context(document):
    return historical_context(document_collection(document), document)


class DeliveryLedger(Protocol):
    """Adapter contract implemented by SqlHistoryLedger in the paired module."""

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
    """Only exact plans, including the reviewed negative-duration exception, qualify."""
    allowed = {"schema_version", "policy_version", "value_policy_version", "filename", "officer_uid", "raw_record_id",
        "record_classification", "authority_result", "authority_assessment", "valid_from", "valid_to", "needs_review",
        "reference_evidence", "review_issues", "observations", "uncertainties", "fields"}
    if not isinstance(payload, dict) or set(payload) != allowed:
        raise ValueError("Historical payload shape differs.")
    filename = payload.get("filename")
    if filename not in ROUTES or (payload.get("schema_version"), payload.get("policy_version"),
        payload.get("value_policy_version"), payload.get("record_classification"),
        payload.get("authority_assessment"), payload.get("authority_result")) != (
        "1.0", HISTORY_PLAN_POLICY, SERVICE_VALUE_POLICY, "UNASSESSED", "NOT_RUN", None):
        raise ValueError("Unsupported historical plan or authority/classification promotion.")
    if any(payload.get(f) is not None for f in ("valid_from", "valid_to")) or payload.get("review_issues") != []:
        raise ValueError("Unresolved historical applicability or consistency promotion.")
    fields = payload.get("fields")
    if not isinstance(fields, list) or len(fields) != len(ROUTES[filename]):
        raise ValueError("Historical field coverage differs.")
    names = [f.get("source_column") for f in fields]
    if len(set(names)) != len(fields) or set(names) != set(ROUTES[filename]):
        raise ValueError("Historical fields are duplicated or missing.")
    if any(not isinstance(f.get("source_value"), str) for f in fields):
        raise ValueError("Original source text is required.")
    row = {f["source_column"]: f["source_value"] for f in fields}
    references = payload.get("reference_evidence")
    if not isinstance(references, dict) or not isinstance(references.get("station_matches", {}), dict):
        raise ValueError("Historical evidence references are required.")
    # Recompute parsed claims. Referenced station rows are independently checked
    # by SQL; the import preflight must also verify full-snapshot name uniqueness.
    station_candidates = {}
    for prefix in ("from", "to"):
        code_name, label_name = prefix + "_station_code", prefix + "_station_name"
        reference = references.get("station_matches", {}).get(code_name)
        if reference is not None:
            if filename != "transfer_history.csv" or reference.get("station_code") != row[code_name].strip():
                raise ValueError("Historical station reference differs.")
            label = row[label_name].strip()
            candidate = (row[code_name].strip(),)
            if label in station_candidates and station_candidates[label] != candidate:
                raise ValueError("Conflicting station reference labels.")
            station_candidates[label] = candidate
    plan = plan_history(filename, row, officer_uid=UUID(payload["officer_uid"]), station_candidates=station_candidates)
    expected_fields = [dict(source_column=f.source_column, target_field=f.target_field, source_value=f.source_value,
        value=encoded(f.value), status=f.status, issues=list(f.issues)) for f in plan.fields]
    if fields != expected_fields or payload.get("needs_review") is not plan.needs_review or payload.get("observations") != list(plan.observations) or payload.get("uncertainties") != list(plan.uncertainties):
        raise ValueError("Historical plan differs from its preserved source values.")
    if plan.review_issues:
        raise ValueError("Historical consistency issues require review before delivery.")
    for f in plan.fields:
        if f.status == "REVIEW_REQUIRED":
            # Preserve the observed 30 anomalies, never replace them with absolute
            # values or use them as accepted durations in reconstruction.
            if filename != "transfer_history.csv" or f.source_column != "days_in_previous_posting" or re.fullmatch(r"-[0-9]{1,12}", f.source_value.strip()) is None or int(f.source_value.strip()) >= 0:
                raise ValueError("Historical field review is not the approved duration exception.")
    return json.loads(json.dumps(payload, allow_nan=False))


def validate_document(document):
    """Reject malformed envelope metadata before any adapter is called."""
    if set(document) != set(properties(document_collection(document))):
        raise ValueError("Mongo envelope fields differ.")
    for name in ("_id", "officer_uid", "source_assertion_uid"):
        value = document[name]
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("Canonical opaque UUID is required.")
    if not isinstance(document["raw_record_id"], str) or re.fullmatch("[0-9a-f]{64}", document["raw_record_id"]) is None:
        raise ValueError("Invalid source-row binding.")
    if document["classification"] != "UNASSESSED":
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
                    writer_policy=COLLECTION_POLICIES[collection_for(expected)], schema_version=1, classification="UNASSESSED",
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
    if document_collection(document) != collection_for(expected):
        raise ValueError("Prepared destination differs from historical plan.")
    if (document["officer_uid"], document["raw_record_id"]) != (expected["officer_uid"], expected["raw_record_id"]):
        raise ValueError("Prepared source/officer binding differs.")
    binding = dict(key_version=document["payload_key_version"], context=encryption_context(document))
    # Both key copies must recover the exact source plan, not merely parse JSON.
    if crypto.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Prepared historical evidence differs from source plan.")
    if backup.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Backup historical recovery differs.")
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
    if collection.name != collection_for(expected_payload):
        raise ValueError("Wrong historical Mongo destination.")
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
    if collection.name != collection_for(expected_payload):
        raise ValueError("Wrong historical Mongo destination.")
    document = verify_delivery(prepared, crypto, backup, expected_payload)
    if not verify_mongo(collection, document):
        raise ValueError("Mongo evidence is missing.")
    if ledger.completion_digest(document["_id"]) != prepared.document_sha256:
        raise ValueError("SQL completion receipt is missing or differs.")
    return "VERIFIED_EXISTING"
