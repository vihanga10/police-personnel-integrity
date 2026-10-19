"""Recoverable station reference delivery; no accepted mappings or import API.

Persist exact encrypted BSON in SQL before Mongo insertion. Retries recover the
committed preparation; they never regenerate or overwrite delivered evidence.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Protocol
from uuid import UUID
from bson import BSON, Binary
from pymongo.errors import DuplicateKeyError
from app.identity.reference_plan import validate_payload, ROUTES, raw_id
from app.identity.service_delivery import PreparedDelivery
from app.storage.reference_mongo_contract import COLLECTION_POLICIES, properties, encryption_context as reference_context

FILE_COLLECTIONS = {'station_master.csv':'station_reference_records',
    'sri_lanka_police_stations_sinhala.csv':'station_sinhala_reference_records'}
EVIDENCE_KEYS = {'batch_id','archive_sha256','confirmation_sha256','source_system_code',
    'import_file_id','source_file_sha256','source_row_number','master_import_file_id',
    'master_file_sha256','master_rows'}


def check_payload(payload):
    """Preserve the planner envelope; SQL independently rebuilds its candidates.

    The importer must pin the intended intake archive and source confirmation.
    This adapter also supports isolated synthetic source batches in recovery checks.
    """
    try:
        if not isinstance(payload,dict) or set(payload) != {'plan','evidence'}:
            raise ValueError('Reference delivery payload shape differs.')
        validate_payload(payload['plan'])
        evidence=payload['evidence']
        if not isinstance(evidence,dict) or set(evidence)!=EVIDENCE_KEYS:
            raise ValueError('Reference source evidence shape differs.')
        if not isinstance(evidence['batch_id'],str) or not evidence['batch_id'] or evidence['source_system_code']!='POLICE_HR_IS':
            raise ValueError('Reference supplying source differs.')
        for name in ('archive_sha256','confirmation_sha256','source_file_sha256','master_file_sha256'):
            raw_id(evidence[name])
        for name in ('import_file_id','master_import_file_id'):
            if str(UUID(evidence[name]))!=evidence[name]:raise ValueError('Canonical reference file UUID required.')
        for name in ('source_row_number','master_rows'):
            if type(evidence[name]) is not int or evidence[name]<=0:raise ValueError('Positive reference count required.')
        return json.loads(json.dumps(payload,allow_nan=False))
    except (KeyError,TypeError,AttributeError,OverflowError):
        raise ValueError('Reference delivery contract differs.') from None


def collection_for(payload):
    try:return FILE_COLLECTIONS[payload['plan']['filename']]
    except (KeyError,TypeError):raise ValueError('Unsupported station reference destination.') from None


def document_collection(document):
    matches=[name for name,policy in COLLECTION_POLICIES.items() if policy==document.get('writer_policy')]
    if len(matches)!=1:raise ValueError('Unsupported station reference writer policy.')
    return matches[0]


def encryption_context(document):
    return reference_context(document_collection(document),document)


class DeliveryLedger(Protocol):
    def prepare_once(self, proposed: PreparedDelivery) -> PreparedDelivery: ...
    def completion_digest(self, event_id: str) -> str | None: ...
    def complete_once(self, prepared: PreparedDelivery) -> str: ...


def validate_document(document):
    """Reject malformed envelope metadata before any adapter is called."""
    if set(document) != set(properties(document_collection(document))):
        raise ValueError("Mongo envelope fields differ.")
    for name in ("_id", "source_assertion_uid"):
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
    document = dict(_id=str(event_id), source_assertion_uid=str(assertion_id), raw_record_id=expected["plan"]["raw_record_id"],
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
        raise ValueError("Prepared destination differs from station reference plan.")
    if document["raw_record_id"] != expected["plan"]["raw_record_id"]:
        raise ValueError("Prepared reference source binding differs.")
    binding = dict(key_version=document["payload_key_version"], context=encryption_context(document))
    # Both key copies must recover the exact source plan, not merely parse JSON.
    if crypto.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Prepared station reference evidence differs from source plan.")
    if backup.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Backup station reference recovery differs.")
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
        raise ValueError("Wrong station reference Mongo destination.")
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
        raise ValueError("Wrong station reference Mongo destination.")
    document = verify_delivery(prepared, crypto, backup, expected_payload)
    if not verify_mongo(collection, document):
        raise ValueError("Mongo evidence is missing.")
    if ledger.completion_digest(document["_id"]) != prepared.document_sha256:
        raise ValueError("SQL completion receipt is missing or differs.")
    return "VERIFIED_EXISTING"
