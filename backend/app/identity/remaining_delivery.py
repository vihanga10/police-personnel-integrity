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

from app.identity.remaining_plan import ROUTES as ALL_ROUTES, REMAINING_PLAN_POLICY, plan_remaining
from app.identity.inspect_remaining_sources import HEADERS, ACTOR_FIELDS, SOURCES
from app.identity.remaining_plan_crypto import encoded
from app.identity.service_delivery import PreparedDelivery
from app.storage.remaining_mongo_contract import COLLECTION_POLICIES, properties, encryption_context as remaining_context

FILE_COLLECTIONS = {'officer_education.csv':'education_records', 'operations.csv':'operation_records',
    'court_details.csv':'court_records', 'public_complaints.csv':'complaint_records', '_demotions_enacted.csv':'demotion_events'}
ROUTES = {name: ALL_ROUTES[name] for name in FILE_COLLECTIONS}
CANDIDATE_STATES = {'EXACT_EVIDENCE_CANDIDATE','NO_CANDIDATE_FOUND','MULTIPLE_CANDIDATES',
    'NO_USABLE_NIC_EVIDENCE','UNUSABLE_NIC'}


def identity_fields(filename):
    fields = tuple(name for name in ACTOR_FIELDS[filename] if name != 'officer_nic_as_recorded')
    if 'officer_nic_no' in HEADERS[filename]: fields += ('officer_nic_no',)
    if filename == 'public_complaints.csv': fields += ('officer_nic_as_recorded',)
    return fields


def collection_for(payload):
    try:
        return FILE_COLLECTIONS[payload["filename"]]
    except (KeyError, TypeError):
        raise ValueError("Unsupported remaining HR/PF source filename.") from None


def document_collection(document):
    matching = [name for name, policy in COLLECTION_POLICIES.items() if policy == document.get("writer_policy")]
    if len(matching) != 1:
        raise ValueError("Unsupported remaining HR/PF writer policy.")
    return matching[0]


def encryption_context(document):
    return remaining_context(document_collection(document), document)


class DeliveryLedger(Protocol):
    """Adapter contract implemented by SqlRemainingLedger in the paired module."""

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
    """Rebuild original claims; review issues may be preserved but never erased.

    This is encrypted evidence delivery, not acceptance of a corrected record,
    current assignment, legal outcome, participant relationship or authority.
    """
    allowed = {'schema_version','policy_version','filename','officer_uid','raw_record_id',
        'record_classification','authority_result','authority_assessment','valid_from','valid_to',
        'reconstructed_state','effects_applied','needs_review','reference_evidence','review_issues',
        'observations','uncertainties','fields'}
    if not isinstance(payload, dict) or set(payload) != allowed:
        raise ValueError('Remaining payload shape differs.')
    filename = payload.get('filename')
    if filename not in ROUTES or (payload.get('schema_version'),payload.get('policy_version'),
        payload.get('record_classification'),payload.get('authority_assessment'),payload.get('authority_result'),
        payload.get('effects_applied')) != ('1.0', REMAINING_PLAN_POLICY,'UNASSESSED','NOT_RUN',None,False):
        raise ValueError('Remaining source policy or determination differs.')
    if payload['effects_applied'] is not False or any(payload.get(k) is not None for k in ('valid_from','valid_to','reconstructed_state')):
        raise ValueError('Unapproved remaining source determination.')
    fields = payload.get('fields')
    if not isinstance(fields,list) or any(not isinstance(f,dict) for f in fields) or tuple(f.get('source_column') for f in fields) != HEADERS[filename]:
        raise ValueError('Remaining field coverage/order differs.')
    if any(not isinstance(f.get('source_value'),str) for f in fields):
        raise ValueError('Original source text required.')
    row = {f['source_column']:f['source_value'] for f in fields}
    refs = payload.get('reference_evidence')
    if not isinstance(refs,dict) or not isinstance(refs.get('identity_candidates'),dict):
        raise ValueError('Remaining identity evidence required.')
    candidates = refs['identity_candidates']
    if set(candidates) != set(identity_fields(filename)):
        raise ValueError('Remaining identity candidate coverage differs.')
    parsed = {}
    for name, ref in candidates.items():
        if not isinstance(ref,dict) or set(ref) != {'candidate_state','officer_uid'} or ref['candidate_state'] not in CANDIDATE_STATES:
            raise ValueError('Unsupported identity candidate evidence.')
        if ref['candidate_state'] == 'EXACT_EVIDENCE_CANDIDATE':
            uid = UUID(ref['officer_uid'])
            if str(uid) != ref['officer_uid']: raise ValueError('Canonical candidate UUID required.')
            parsed[name] = uid
        elif ref['officer_uid'] is not None:
            raise ValueError('Unresolved candidate cannot supply an officer UID.')
    subject = parsed.get('officer_nic_no')
    if 'officer_nic_no' in row:
        if subject is None or str(subject) != payload['officer_uid']:
            raise ValueError('Single-subject exact identity evidence required before delivery.')
    elif payload['officer_uid'] is not None:
        raise ValueError('Multi-person source cannot have a fabricated single subject.')
    plan = plan_remaining(filename,row,officer_uid=subject,identity_candidates=parsed)
    expected_fields = [dict(source_column=f.source_column,destination=f.destination,target_field=f.target_field,
        source_value=f.source_value,value=encoded(f.value),status=f.status,issues=list(f.issues)) for f in plan.fields]
    if fields != expected_fields or payload['needs_review'] is not plan.needs_review or payload['review_issues'] != list(plan.review_issues) or payload['observations'] != list(plan.observations) or payload['uncertainties'] != list(plan.uncertainties):
        raise ValueError('Remaining plan differs from preserved source values.')
    # Review-required alternate NICs and malformed claims stay encrypted and flagged.
    # They cannot be upgraded to verified truth by delivering the envelope.
    return json.loads(json.dumps(payload,allow_nan=False))


def validate_document(document):
    """Reject malformed envelope metadata before any adapter is called."""
    if set(document) != set(properties(document_collection(document))):
        raise ValueError("Mongo envelope fields differ.")
    for name in ("_id", "source_assertion_uid"):
        value = document[name]
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("Canonical opaque UUID is required.")
    subject = document['officer_uid']
    if document_collection(document) in {'operation_records','court_records'}:
        if subject is not None: raise ValueError('Multi-person subject must be null.')
    elif not isinstance(subject,str) or str(UUID(subject)) != subject:
        raise ValueError('Canonical single-subject UUID required.')
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
        raise ValueError("Prepared destination differs from remaining HR/PF plan.")
    if (document["officer_uid"], document["raw_record_id"]) != (expected["officer_uid"], expected["raw_record_id"]):
        raise ValueError("Prepared source/officer binding differs.")
    binding = dict(key_version=document["payload_key_version"], context=encryption_context(document))
    # Both key copies must recover the exact source plan, not merely parse JSON.
    if crypto.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Prepared remaining HR/PF evidence differs from source plan.")
    if backup.decrypt_assertion(bytes(document["payload_ciphertext"]), **binding) != expected:
        raise ValueError("Backup remaining HR/PF recovery differs.")
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
        raise ValueError("Wrong remaining HR/PF Mongo destination.")
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
        raise ValueError("Wrong remaining HR/PF Mongo destination.")
    document = verify_delivery(prepared, crypto, backup, expected_payload)
    if not verify_mongo(collection, document):
        raise ValueError("Mongo evidence is missing.")
    if ledger.completion_digest(document["_id"]) != prepared.document_sha256:
        raise ValueError("SQL completion receipt is missing or differs.")
    return "VERIFIED_EXISTING"
