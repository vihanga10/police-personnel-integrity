"""Real PostgreSQL adapter for immutable service preparation and completion.

Only the coordinated delivery protocol may call completion after Mongo readback.
This module does not expose an intake API or grant human import authorization.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import re
from uuid import UUID, uuid4

from sqlalchemy import Engine, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import evidence_context
from app.identity.service_delivery import PreparedDelivery, WRITER_POLICY, verify_delivery
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.models.service_delivery_storage import ServiceDeliveryCompletion, ServiceDeliveryPreparation
from app.staging.models import RawRecord
from app.storage.mongo_contract import encryption_context

PREP = ServiceDeliveryPreparation.__table__
DONE = ServiceDeliveryCompletion.__table__
ASSERTION = SourceAssertion.__table__


@dataclass(frozen=True)
class ServiceSourceBinding:
    raw_record_id: str
    identifier_version_id: UUID
    confirmation_sha256: str
    code_revision: str

    def validate(self):
        for value, length in ((self.raw_record_id, 64), (self.confirmation_sha256, 64), (self.code_revision, 40)):
            if not isinstance(value, str) or re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is None:
                raise ValueError("Invalid service provenance fingerprint.")
        if not isinstance(self.identifier_version_id, UUID):
            raise ValueError("A stored identifier version is required.")


def check_nic(connection, crypto, backup, row, officer_uid, binding, expected):
    """Validate exact encrypted NIC evidence; do not assert historical eligibility."""
    identifier = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    saved = connection.execute(select(OfficerIdentifierVersion.__table__).where(
        OfficerIdentifierVersion.identifier_version_id == binding.identifier_version_id)).mappings().one()
    assertion = connection.execute(select(ASSERTION).where(
        ASSERTION.c.source_assertion_id == saved["source_assertion_id"])).mappings().one()
    registry = connection.execute(select(Officer.registry_state).where(Officer.officer_uid == officer_uid)).scalar_one()
    if (registry != "REGISTERED" or saved["officer_uid"] != officer_uid or assertion["officer_uid"] != officer_uid
        or saved["identifier_type"] != "NIC" or saved["normalization_profile"] != NORMALIZATION_PROFILE
        or saved["record_state"] not in {"ASSERTED", "ACCEPTED"} or saved["transaction_end"] is not None
        or assertion["assertion_type"] != "IDENTIFIER_NIC" or assertion["assertion_state"] != "ACTIVE"
        or assertion["transaction_end"] is not None):
        raise ValueError("NIC evidence is not usable for this officer.")
    kwargs = dict(key_version=saved["encryption_key_version"], context=evidence_context("IDENTIFIER", saved["identifier_version_id"]))
    if crypto.decrypt(saved["identifier_value_ciphertext"], **kwargs) != identifier.value.encode() or backup.decrypt(saved["identifier_value_ciphertext"], **kwargs) != identifier.value.encode():
        raise ValueError("Exact NIC recovery differs.")
    digest, _ = crypto.lookup_hmac(identifier.value, identifier_type="NIC", key_version=saved["lookup_key_version"])
    if not hmac.compare_digest(digest, saved["identifier_lookup_hmac"]):
        raise ValueError("NIC lookup binding differs.")
    kwargs = dict(key_version=assertion["encryption_key_version"], context=evidence_context("ASSERTION", assertion["source_assertion_id"]))
    claim = crypto.decrypt_assertion(assertion["asserted_value_ciphertext"], **kwargs)
    if backup.decrypt_assertion(assertion["asserted_value_ciphertext"], **kwargs) != claim:
        raise ValueError("NIC assertion backup differs.")
    if (claim.get("normalized_value"), claim.get("identifier_type"), claim.get("normalization_profile"),
        claim.get("raw_record_id"), claim.get("source_confirmation_sha256"), claim.get("source_column")) != (
        identifier.value, "NIC", NORMALIZATION_PROFILE, assertion["raw_record_id"], binding.confirmation_sha256, "officer_nic_no"):
        raise ValueError("NIC assertion provenance differs.")
    if normalize_identifier(claim.get("reported_value"), identifier_type="NIC").value != identifier.value:
        raise ValueError("Original NIC claim differs.")
    reference = dict(identifier_version_id=str(saved["identifier_version_id"]), source_assertion_id=str(assertion["source_assertion_id"]),
                     linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH", historical_eligibility="UNASSESSED")
    if reference not in expected["reference_evidence"].get("identifier_evidence", []):
        raise ValueError("Planned NIC evidence reference differs.")


def check_source(connection, crypto, backup, binding, document, expected):
    """Recover the staged original and compare every source cell before preparation."""
    binding.validate()
    raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == binding.raw_record_id)).mappings().one()
    if document["raw_record_id"] != raw["raw_record_id"] or raw["archive_path"].rsplit("/", 1)[-1] != "officer_service_information.csv":
        raise ValueError("Wrong service source row.")
    original = open_row(crypto, stored_row(raw))
    if open_row(backup, stored_row(raw)) != original:
        raise ValueError("Staged service backup differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    fields = expected["fields"]
    if len(row) != len(fields) or {f["source_column"]: f["source_value"] for f in fields} != row:
        raise ValueError("Planned original service values differ from staging.")
    source = dict(batch_id=raw["batch_id"], raw_record_id=raw["raw_record_id"], import_file_id=str(raw["import_file_id"]),
                  source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
                  reported_source_system_code="POLICE_HR_IS", confirmation_sha256=binding.confirmation_sha256)
    if expected["reference_evidence"].get("service_source") != source:
        raise ValueError("Planned service provenance differs.")
    check_nic(connection, crypto, backup, row, UUID(document["officer_uid"]), binding, expected)
    return raw


def assert_saved(connection, saved, crypto, backup, binding, expected):
    prepared = PreparedDelivery(bytes(saved["document_bson"]), saved["document_sha256"])
    document = verify_delivery(prepared, crypto, backup, expected)
    if (saved["delivery_id"], saved["officer_uid"], saved["source_assertion_id"], saved["raw_record_id"],
        saved["writer_policy"], saved["recorded_at"], saved["confirmation_sha256"], saved["identifier_version_id"]) != (
        UUID(document["_id"]), UUID(document["officer_uid"]), UUID(document["source_assertion_uid"]), document["raw_record_id"],
        WRITER_POLICY, document["recorded_at"], binding.confirmation_sha256, binding.identifier_version_id):
        raise ValueError("Saved preparation routing or linkage differs.")
    raw = check_source(connection, crypto, backup, binding, document, expected)
    assertion = connection.execute(select(ASSERTION).where(ASSERTION.c.source_assertion_id == saved["source_assertion_id"])).mappings().one()
    source_code = connection.execute(select(SourceSystem.source_system_code).where(SourceSystem.source_system_id == assertion["source_system_id"])).scalar_one()
    if (source_code != "POLICE_HR_IS" or assertion["assertion_type"] != "HR_SERVICE_EVIDENCE"
        or assertion["officer_uid"] != saved["officer_uid"] or assertion["raw_record_id"] != raw["raw_record_id"]
        or assertion["intake_batch_id"] != raw["batch_id"] or assertion["import_file_id"] != str(raw["import_file_id"])
        or assertion["source_file_sha256"] != raw["source_file_sha256"] or assertion["source_row_number"] != raw["source_row_number"]
        or assertion["asserted_value_ciphertext"] != bytes(document["payload_ciphertext"])
        or assertion["encryption_key_version"] != document["payload_key_version"]):
        raise ValueError("Saved service assertion differs.")
    # The assertion reuses the same authenticated service evidence envelope;
    # it does not introduce another plaintext or differently bound copy.
    if crypto.decrypt_assertion(assertion["asserted_value_ciphertext"], key_version=assertion["encryption_key_version"],
                                context=encryption_context(document)) != expected:
        raise ValueError("Service assertion encrypted recovery differs.")
    return prepared


def prepare_on_connection(connection, proposed, *, crypto, backup, binding, expected_payload):
    """SQL transaction body; caller must commit before performing any Mongo write."""
    document = verify_delivery(proposed, crypto, backup, expected_payload)
    binding.validate()
    # A stable per-source transaction lock serializes cooperating prepare/retry
    # workers. Unique constraints remain the final database concurrency guard.
    lock = int.from_bytes(hashlib.sha256((binding.raw_record_id + WRITER_POLICY).encode()).digest()[:8], "big", signed=True)
    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})
    raw = check_source(connection, crypto, backup, binding, document, expected_payload)
    existing = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                    PREP.c.writer_policy == WRITER_POLICY)).mappings().one_or_none()
    if existing is not None:
        return assert_saved(connection, existing, crypto, backup, binding, expected_payload)
    sources = SourceSystem.__table__
    connection.execute(pg_insert(sources).values(source_system_id=uuid4(), source_system_code="POLICE_HR_IS",
        source_name="Police HR information system", source_description="Reported supplying source; independence remains unverified.",
        is_active=True).on_conflict_do_nothing(index_elements=["source_system_code"]))
    source = connection.execute(select(sources).where(sources.c.source_system_code == "POLICE_HR_IS")).mappings().one()
    if not source["is_active"] or len(document["payload_key_version"]) > 50:
        raise ValueError("Inactive supplying source or unsupported key version.")
    connection.execute(insert(ASSERTION).values(source_assertion_id=UUID(document["source_assertion_uid"]),
        officer_uid=UUID(document["officer_uid"]), source_system_id=source["source_system_id"], assertion_type="HR_SERVICE_EVIDENCE",
        asserted_value_ciphertext=bytes(document["payload_ciphertext"]), encryption_key_version=document["payload_key_version"],
        intake_batch_id=raw["batch_id"], import_file_id=str(raw["import_file_id"]), raw_record_id=raw["raw_record_id"],
        source_file_name="officer_service_information.csv", source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        valid_from=None, valid_to=None, source_recorded_at=None, captured_at=None, transaction_start=document["recorded_at"],
        transaction_end=None, assertion_state="ACTIVE", independence_status="UNVERIFIED"))
    connection.execute(insert(PREP).values(delivery_id=UUID(document["_id"]), raw_record_id=raw["raw_record_id"],
        officer_uid=UUID(document["officer_uid"]), source_assertion_id=UUID(document["source_assertion_uid"]),
        identifier_version_id=binding.identifier_version_id, confirmation_sha256=binding.confirmation_sha256,
        code_revision=binding.code_revision, writer_policy=WRITER_POLICY, linkage_method="EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH",
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


class SqlDeliveryLedger:
    """Production adapter: each write method returns only after its SQL commit."""

    def __init__(self, engine, *, crypto, backup, binding, expected_payload):
        if not isinstance(engine, Engine) or (engine.url.host, engine.url.port, engine.url.database, engine.url.username) != (
            "127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        binding.validate()
        self.engine, self.crypto, self.backup, self.binding = engine, crypto, backup, binding
        self.expected = deepcopy(expected_payload)

    def prepare_once(self, proposed):
        with self.engine.begin() as connection:
            connection.execute(text("SET LOCAL lock_timeout = '5s'"))
            connection.execute(text("SET LOCAL statement_timeout = '30s'"))
            result = prepare_on_connection(connection, proposed, crypto=self.crypto, backup=self.backup,
                                           binding=self.binding, expected_payload=self.expected)
        return result  # The context manager has committed before this return.

    def completion_digest(self, event_id):
        with self.engine.connect() as connection:
            return connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(event_id))).scalar_one_or_none()

    def complete_once(self, prepared):
        # Enforce this adapter's source-plan binding even for direct internal calls.
        verify_delivery(prepared, self.crypto, self.backup, self.expected)
        with self.engine.begin() as connection:
            result = completion_on_connection(connection, prepared)
        return result
