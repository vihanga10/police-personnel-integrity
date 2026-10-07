"""Real PostgreSQL adapter for immutable remaining HR/PF preparation and completion.

Only the coordinated delivery protocol may call completion after Mongo readback.
This module does not expose an intake API or grant human import authorization.
"""
from copy import deepcopy
import hashlib
from uuid import UUID, uuid4

from sqlalchemy import Engine, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.identity.remaining_delivery import PreparedDelivery, verify_delivery, encryption_context
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.models.remaining_delivery_storage import RemainingDeliveryCompletion, RemainingDeliveryPreparation, RemainingSourceAssertion
from app.staging.models import RawRecord

PREP = RemainingDeliveryPreparation.__table__
DONE = RemainingDeliveryCompletion.__table__
ASSERTION = RemainingSourceAssertion.__table__


# The shared binding/check verifies exact encrypted identifiers, not historical eligibility.
from dataclasses import dataclass
import re
from app.identity.service_sql_ledger import check_nic


@dataclass(frozen=True)
class RemainingSourceBinding:
    raw_record_id: str
    identifier_version_id: UUID | None
    confirmation_sha256: str
    code_revision: str

    def validate(self):
        for value, size in ((self.raw_record_id,64),(self.confirmation_sha256,64),(self.code_revision,40)):
            if not isinstance(value,str) or re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is None:
                raise ValueError('Invalid remaining source fingerprint.')
        if self.identifier_version_id is not None and not isinstance(self.identifier_version_id,UUID):
            raise ValueError('Identifier version must be UUID or unknown for multi-person events.')

from app.identity.remaining_delivery import check_payload, collection_for, document_collection
from app.identity.inspect_history_sources import inspected_link
from app.identity.inspect_remaining_sources import HEADERS as REMAINING_HEADERS, SOURCES
from app.staging.models import IntakeFile
from app.identity.remaining_delivery import identity_fields
from app.staging.models import IntakeBatch


ASSERTION_TYPES = {'officer_education.csv':'HR_EDUCATION_EVIDENCE','operations.csv':'PF_OPERATION_EVIDENCE',
    'court_details.csv':'PF_COURT_EVIDENCE','public_complaints.csv':'PF_COMPLAINT_EVIDENCE','_demotions_enacted.csv':'PF_DEMOTION_EVIDENCE'}


def subject_uuid(document):
    return UUID(document['officer_uid']) if document['officer_uid'] is not None else None


def check_candidate_references(connection, crypto, backup, raw, row, expected):
    """Rediscover exact or unresolved candidates independently of the supplied plan."""
    candidates = expected['reference_evidence']['identity_candidates']; cache = {}
    for name in identity_fields(expected['filename']):
        state, uid = inspected_link(connection,crypto,backup,row[name],cache)
        if candidates[name] != dict(candidate_state=state,officer_uid=str(uid) if uid else None):
            raise ValueError('Remaining identity candidate evidence differs.')


def check_source(connection, crypto, backup, binding, document, expected):
    """Recover the staged original and compare every source cell before preparation."""
    binding.validate()
    expected = check_payload(expected)
    raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == binding.raw_record_id)).mappings().one()
    if document["raw_record_id"] != raw["raw_record_id"] or raw["archive_path"].rsplit("/", 1)[-1] != expected["filename"]:
        raise ValueError("Wrong remaining HR/PF source row.")
    file = connection.execute(select(IntakeFile.__table__).where(IntakeFile.import_file_id == raw["import_file_id"])).mappings().one()
    if tuple(file["columns"]) != REMAINING_HEADERS[expected["filename"]] or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("remaining HR/PF source header or file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original["columns"] != file["columns"] or open_row(backup, stored_row(raw)) != original:
        raise ValueError("Staged remaining-source backup differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    fields = expected["fields"]
    if len(row) != len(fields) or {f["source_column"]: f["source_value"] for f in fields} != row:
        raise ValueError("Planned original remaining HR/PF values differ from staging.")
    batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == raw['batch_id'])).mappings().one()
    source = dict(batch_id=raw['batch_id'],archive_sha256=batch['archive_sha256'],confirmation_sha256=binding.confirmation_sha256,
        source_system_code=SOURCES[expected['filename']],raw_record_id=raw['raw_record_id'],import_file_id=str(raw['import_file_id']),
        source_file_sha256=raw['source_file_sha256'],source_row_number=raw['source_row_number'])
    references = expected['reference_evidence']
    if any(references.get(k) != v for k,v in source.items()) or references.get('historical_eligibility') != 'UNASSESSED' or references.get('reference_linkage') != 'UNASSESSED':
        raise ValueError('Remaining source provenance/applicability differs.')
    check_candidate_references(connection,crypto,backup,raw,row,expected)
    if document['officer_uid'] is not None:
        if binding.identifier_version_id is None: raise ValueError('Single subject requires stored NIC version.')
        check_nic(connection,crypto,backup,row,subject_uuid(document),binding,expected)
    elif binding.identifier_version_id is not None:
        raise ValueError('Multi-person evidence cannot have a fabricated NIC binding.')
    return raw


def assert_saved(connection, saved, crypto, backup, binding, expected):
    prepared = PreparedDelivery(bytes(saved["document_bson"]), saved["document_sha256"])
    document = verify_delivery(prepared, crypto, backup, expected)
    if (saved["delivery_id"], saved["officer_uid"], saved["source_assertion_id"], saved["raw_record_id"],
        saved["writer_policy"], saved["recorded_at"], saved["confirmation_sha256"], saved["identifier_version_id"]) != (
        UUID(document["_id"]), subject_uuid(document), UUID(document["source_assertion_uid"]), document["raw_record_id"],
        document["writer_policy"], document["recorded_at"], binding.confirmation_sha256, binding.identifier_version_id):
        raise ValueError("Saved preparation routing or linkage differs.")
    review_count = sum(f["status"] == "REVIEW_REQUIRED" for f in expected["fields"])
    row_reviews = len(expected["review_issues"])
    if (saved["source_file_name"], saved["mongo_collection"], saved["field_review_count"], saved["row_review_count"], saved["review_state"]) != (
        expected["filename"], collection_for(expected), review_count, row_reviews, "STRUCTURAL_REVIEW_REQUIRED" if review_count or row_reviews else "NO_STRUCTURAL_REVIEW"):
        raise ValueError("Saved remaining HR/PF routing or review metadata differs.")
    expected_link = 'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH' if document['officer_uid'] is not None else 'MULTI_PERSON_SOURCE_NO_SINGLE_SUBJECT'
    if saved['linkage_method'] != expected_link or saved['historical_eligibility'] != 'UNASSESSED':
        raise ValueError('Saved linkage determination differs.')
    raw = check_source(connection, crypto, backup, binding, document, expected)
    assertion = connection.execute(select(ASSERTION).where(ASSERTION.c.source_assertion_id == saved["source_assertion_id"])).mappings().one()
    source_code = connection.execute(select(SourceSystem.source_system_code).where(SourceSystem.source_system_id == assertion["source_system_id"])).scalar_one()
    if (source_code != SOURCES[expected["filename"]] or assertion["assertion_type"] != ASSERTION_TYPES[expected["filename"]]
        or assertion["officer_uid"] != saved["officer_uid"] or assertion["raw_record_id"] != raw["raw_record_id"]
        or assertion["intake_batch_id"] != raw["batch_id"] or assertion["import_file_id"] != str(raw["import_file_id"])
        or assertion["source_file_sha256"] != raw["source_file_sha256"] or assertion["source_row_number"] != raw["source_row_number"]
        or assertion["asserted_value_ciphertext"] != bytes(document["payload_ciphertext"])
        or assertion["encryption_key_version"] != document["payload_key_version"]
        or assertion["source_file_name"] != expected["filename"] or assertion["assertion_state"] != "ACTIVE"
        or assertion["transaction_start"] != document["recorded_at"] or assertion["independence_status"] != "UNVERIFIED"
        or assertion["classification"] != "UNASSESSED"
        or any(assertion[f] is not None for f in ("valid_from", "valid_to", "transaction_end", "source_recorded_at", "captured_at", "source_record_id", "source_document_id", "source_page"))):
        raise ValueError("Saved remaining HR/PF assertion differs.")
    # The assertion reuses the same authenticated remaining-source evidence envelope;
    # it does not introduce another plaintext or differently bound copy.
    if crypto.decrypt_assertion(assertion["asserted_value_ciphertext"], key_version=assertion["encryption_key_version"],
                                context=encryption_context(document)) != expected:
        raise ValueError("remaining HR/PF assertion encrypted recovery differs.")
    return prepared


def prepare_on_connection(connection, proposed, *, crypto, backup, binding, expected_payload):
    """SQL transaction body; caller must commit before performing any Mongo write."""
    document = verify_delivery(proposed, crypto, backup, expected_payload)
    binding.validate()
    # A stable per-source transaction lock serializes cooperating prepare/retry
    # workers. Unique constraints remain the final database concurrency guard.
    lock = int.from_bytes(hashlib.sha256((binding.raw_record_id + document["writer_policy"]).encode()).digest()[:8], "big", signed=True)
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})
    raw = check_source(connection, crypto, backup, binding, document, expected_payload)
    existing = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                    PREP.c.writer_policy == document["writer_policy"])).mappings().one_or_none()
    if existing is not None:
        return assert_saved(connection, existing, crypto, backup, binding, expected_payload)
    # Supplying sources were registered in earlier verified imports. Never change them.
    sources = SourceSystem.__table__
    source = connection.execute(select(sources).where(sources.c.source_system_code == SOURCES[expected_payload['filename']])).mappings().one()
    if not source['is_active'] or len(document['payload_key_version']) > 128:
        raise ValueError('Inactive source or unsupported key version.')
    connection.execute(insert(ASSERTION).values(source_assertion_id=UUID(document["source_assertion_uid"]),
        officer_uid=subject_uuid(document), source_system_id=source["source_system_id"], assertion_type=ASSERTION_TYPES[expected_payload["filename"]],
        asserted_value_ciphertext=bytes(document["payload_ciphertext"]), encryption_key_version=document["payload_key_version"],
        intake_batch_id=raw["batch_id"], import_file_id=str(raw["import_file_id"]), raw_record_id=raw["raw_record_id"],
        source_file_name=expected_payload["filename"], source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        valid_from=None, valid_to=None, source_recorded_at=None, captured_at=None, transaction_start=document["recorded_at"],
        transaction_end=None, assertion_state="ACTIVE", independence_status="UNVERIFIED"))
    connection.execute(insert(PREP).values(delivery_id=UUID(document["_id"]), raw_record_id=raw["raw_record_id"],
        officer_uid=subject_uuid(document), source_assertion_id=UUID(document["source_assertion_uid"]),
        identifier_version_id=binding.identifier_version_id, confirmation_sha256=binding.confirmation_sha256,
        code_revision=binding.code_revision, writer_policy=document["writer_policy"],
        source_file_name=expected_payload["filename"], mongo_collection=collection_for(expected_payload),
        field_review_count=sum(f["status"] == "REVIEW_REQUIRED" for f in expected_payload["fields"]),
        row_review_count=len(expected_payload["review_issues"]),
        review_state="STRUCTURAL_REVIEW_REQUIRED" if expected_payload["needs_review"] else "NO_STRUCTURAL_REVIEW", linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH" if document["officer_uid"] is not None else "MULTI_PERSON_SOURCE_NO_SINGLE_SUBJECT",
        historical_eligibility="UNASSESSED", document_bson=proposed.document_bson,
        document_sha256=proposed.document_sha256, recorded_at=document["recorded_at"]))
    return assert_saved(connection, connection.execute(select(PREP).where(PREP.c.delivery_id == UUID(document["_id"]))).mappings().one(),
                        crypto, backup, binding, expected_payload)


def completion_on_connection(connection, prepared):
    """Append the receipt after protocol-verified Mongo readback; never change it."""
    event_id = UUID(prepared.document()["_id"])
    saved = connection.execute(select(PREP).where(PREP.c.delivery_id == event_id)).mappings().one()
    if bytes(saved["document_bson"]) != prepared.document_bson or saved["document_sha256"] != prepared.document_sha256:
        raise ValueError("Completion preparation differs.")
    connection.execute(pg_insert(DONE).values(delivery_id=event_id, document_sha256=prepared.document_sha256)
                       .on_conflict_do_nothing(index_elements=["delivery_id"]))
    digest = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == event_id)).scalar_one()
    if digest != prepared.document_sha256:
        raise ValueError("Completion digest differs.")
    return digest


class SqlRemainingLedger:
    """Production adapter: each write method returns only after its SQL commit."""

    def __init__(self, engine, *, crypto, backup, binding, expected_payload):
        if not isinstance(engine, Engine) or (engine.url.host, engine.url.port, engine.url.database, engine.url.username) != (
            "127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        binding.validate()
        self.engine, self.crypto, self.backup, self.binding = engine, crypto, backup, binding
        self.expected = check_payload(deepcopy(expected_payload))

    def prepare_once(self, proposed):
        with self.engine.begin() as connection:
            connection.execute(text("SET LOCAL lock_timeout = '5s'"))
            connection.execute(text("SET LOCAL statement_timeout = '30s'"))
            result = prepare_on_connection(connection, proposed, crypto=self.crypto, backup=self.backup,
                                           binding=self.binding, expected_payload=self.expected)
        # A fresh connection must see the committed bytes before Mongo insertion.
        with self.engine.connect() as connection:
            saved = connection.execute(select(PREP).where(PREP.c.delivery_id == UUID(result.document()["_id"]))).mappings().one()
            recovered = assert_saved(connection, saved, self.crypto, self.backup, self.binding, self.expected)
        if recovered != result:
            raise ValueError("Committed remaining HR/PF preparation recovery differs.")
        return result

    def completion_digest(self, event_id):
        with self.engine.connect() as connection:
            return connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(event_id))).scalar_one_or_none()

    def complete_once(self, prepared):
        # Enforce this adapter's source-plan binding even for direct internal calls.
        verify_delivery(prepared, self.crypto, self.backup, self.expected)
        with self.engine.begin() as connection:
            result = completion_on_connection(connection, prepared)
        if self.completion_digest(prepared.document()["_id"]) != result:
            raise ValueError("Committed remaining HR/PF receipt recovery differs.")
        return result
