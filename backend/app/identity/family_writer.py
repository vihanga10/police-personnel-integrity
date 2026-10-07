"""Atomic HR family writes with exact source verification and read-only replay.

This is a local development workflow. Human import authorization and disclosure
remain pending. Existing PF relationships are never updated or superseded here.
"""
from dataclasses import dataclass
import hashlib
import re
from uuid import UUID, uuid4
from sqlalchemy import select, func, text
from app.models import (FamilyTransformReceipt, SourceAssertion, SourceSystem,
    OfficerFamilyRelation, OfficerFamilyCivilEventVersion, OfficerNextOfKinVersion, SourceAttestation)
from app.staging.models import RawRecord, IntakeFile, IntakeBatch
from app.identity.family_records import POLICY, FILENAME, check_payload, logical_records, context
from app.identity.inspect_remaining_sources import HEADERS
from app.identity.inspect_history_sources import inspected_link
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.identity.service_sql_ledger import check_nic
from app.identity.remaining_plan import plan_remaining
from app.identity.remaining_plan_crypto import seal_remaining_plan, open_remaining_plan
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row

RECEIPT = FamilyTransformReceipt.__table__
MODELS = {m.__tablename__: m.__table__ for m in (OfficerFamilyRelation, OfficerFamilyCivilEventVersion, OfficerNextOfKinVersion, SourceAttestation)}
IDS = {
    "officer_family_relation": ("family_relation_version_id", "relation_chain_uid", "supersedes_family_relation_version_id"),
    "officer_family_civil_event_version": ("civil_event_version_id", "civil_event_chain_uid", "supersedes_civil_event_version_id"),
    "officer_next_of_kin_version": ("next_of_kin_version_id", "next_of_kin_chain_uid", "supersedes_next_of_kin_version_id"),
    "source_attestation": ("attestation_version_id", "attestation_chain_uid", "supersedes_attestation_version_id"),
}


@dataclass(frozen=True)
class FamilyBinding:
    raw_record_id: str
    identifier_version_id: UUID
    confirmation_sha256: str
    code_revision: str

    def validate(self):
        for value, length in ((self.raw_record_id, 64), (self.confirmation_sha256, 64), (self.code_revision, 40)):
            if not isinstance(value, str) or re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is None:
                raise ValueError("Invalid family source binding.")
        if not isinstance(self.identifier_version_id, UUID) or self.confirmation_sha256 != CONFIRMATION:
            raise ValueError("Reviewed exact NIC evidence is required.")


def recover(crypto, backup, cipher, version, aad):
    value = crypto.decrypt_assertion(cipher, key_version=version, context=aad)
    if backup.decrypt_assertion(cipher, key_version=version, context=aad) != value:
        raise ValueError("Family backup recovery differs.")
    return value


def seal(crypto, backup, payload, aad):
    cipher, version = crypto.encrypt_assertion(payload, context=aad)
    if recover(crypto, backup, cipher, version, aad) != payload:
        raise ValueError("Family encrypted round trip differs.")
    return cipher, version


def check_source(connection, crypto, backup, binding, payload):
    """Independently recover and replan the staged source in the write transaction."""
    binding.validate(); check_payload(payload)
    raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == binding.raw_record_id)).mappings().one()
    file = connection.execute(select(IntakeFile.__table__).where(IntakeFile.import_file_id == raw["import_file_id"])).mappings().one()
    batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == raw["batch_id"])).mappings().one()
    if raw["batch_id"] != BATCH or batch["archive_sha256"] != ARCHIVE or raw["archive_path"].rsplit("/", 1)[-1] != FILENAME:
        raise ValueError("Family batch/source differs.")
    if tuple(file["columns"]) != HEADERS[FILENAME] or any(raw[k] != file[k] for k in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("Family file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
        raise ValueError("Family staged recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    refs = payload["reference_evidence"]
    provenance = dict(batch_id=BATCH, archive_sha256=ARCHIVE, confirmation_sha256=CONFIRMATION,
        source_system_code="POLICE_HR_IS", raw_record_id=binding.raw_record_id,
        import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"],
        source_row_number=raw["source_row_number"])
    if any(refs.get(k) != v for k, v in provenance.items()):
        raise ValueError("Family plan provenance differs.")
    officer = UUID(payload["officer_uid"])
    check_nic(connection, crypto, backup, row, officer, binding, payload)
    subject_state, subject = inspected_link(connection, crypto, backup, row["officer_nic_no"], {})
    if (subject_state, subject) != ("EXACT_EVIDENCE_CANDIDATE", officer):
        raise ValueError("Family subject candidate changed or became ambiguous.")
    # Actor candidates stay encrypted, unresolved and separate from action-time authority.
    state, actor = inspected_link(connection, crypto, backup, row["recorded_by_officer_nic"], {})
    identities = {"officer_nic_no": dict(candidate_state="EXACT_EVIDENCE_CANDIDATE", officer_uid=str(officer)),
        "recorded_by_officer_nic": dict(candidate_state=state, officer_uid=str(actor) if actor else None)}
    if refs.get("identity_candidates") != identities:
        raise ValueError("Family actor candidate evidence differs.")
    candidates = {"recorded_by_officer_nic": actor} if actor else {}
    plan = plan_remaining(FILENAME, row, officer_uid=officer, identity_candidates=candidates)
    cipher, version = seal_remaining_plan(crypto, plan, raw_record_id=binding.raw_record_id, reference_evidence=refs)
    recovered = open_remaining_plan(crypto, cipher, key_version=version, filename=FILENAME, raw_record_id=binding.raw_record_id)
    if recovered != payload or open_remaining_plan(backup, cipher, key_version=version, filename=FILENAME, raw_record_id=binding.raw_record_id) != payload:
        raise ValueError("Family source plan differs.")
    return raw


def receipt_binding(saved):
    return {k: str(saved[k]) for k in ("raw_record_id", "officer_uid", "identifier_version_id", "source_assertion_id", "confirmation_sha256", "code_revision", "policy_version")}


def aad(purpose, raw_id, officer, assertion, record_id, table, chain=None, relation=None):
    return context(purpose, raw_id=raw_id, officer=officer, assertion=assertion, record_id=record_id, table=table, chain=chain, relation=relation)


def verify_saved(connection, crypto, backup, binding, payload, saved, raw):
    officer, assertion = UUID(payload["officer_uid"]), saved["source_assertion_id"]
    if (saved["raw_record_id"], saved["officer_uid"], saved["identifier_version_id"], saved["confirmation_sha256"], saved["policy_version"]) != (binding.raw_record_id, officer, binding.identifier_version_id, binding.confirmation_sha256, POLICY):
        raise ValueError("Family receipt binding differs.")
    evidence = recover(crypto, backup, saved["evidence_ciphertext"], saved["encryption_key_version"],
        aad("RECEIPT", binding.raw_record_id, officer, assertion, assertion, RECEIPT.name))
    if evidence.get("binding") != receipt_binding(saved) or evidence.get("plan") != payload:
        raise ValueError("Family receipt evidence differs.")
    claim = connection.execute(select(SourceAssertion.__table__).where(SourceAssertion.source_assertion_id == assertion)).mappings().one()
    source = connection.execute(select(SourceSystem.source_system_code).where(SourceSystem.source_system_id == claim["source_system_id"])).scalar_one()
    for key, value in dict(officer_uid=officer, assertion_type="HR_FAMILY_EVIDENCE", raw_record_id=binding.raw_record_id,
        intake_batch_id=raw["batch_id"], import_file_id=str(raw["import_file_id"]), source_file_name=FILENAME,
        source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        independence_status="UNVERIFIED", assertion_state="ACTIVE", transaction_end=None, valid_from=None, valid_to=None,
        source_recorded_at=None).items():
        if claim[key] != value: raise ValueError("Family assertion provenance/state differs.")
    if source != "POLICE_HR_IS" or recover(crypto, backup, claim["asserted_value_ciphertext"], claim["encryption_key_version"],
        aad("ASSERTION", binding.raw_record_id, officer, assertion, assertion, "source_assertion")) != payload:
        raise ValueError("Family assertion recovery differs.")
    expected = {(r.table, r.kind): r for r in logical_records(payload)}
    refs = evidence.get("records", [])
    if len(refs) != len(expected) or len({(r["table"], r["kind"]) for r in refs}) != len(expected):
        raise ValueError("Family destination coverage differs.")
    spouse_id = next((UUID(r["record_id"]) for r in refs if (r["table"], r["kind"]) == ("officer_family_relation", "SPOUSE")), None)
    for ref in refs:
        record = expected.get((ref["table"], ref["kind"]))
        if record is None: raise ValueError("Unknown family destination.")
        table = MODELS[record.table]; pk, chain, previous = IDS[record.table]
        row = connection.execute(select(table).where(table.c[pk] == UUID(ref["record_id"]))).mappings().one()
        relation = spouse_id if record.relation_kind else None
        required = {"source_assertion_id": assertion, "version_number": 1, "transaction_end": None, previous: None,
            "record_state": "ACTIVE" if record.table == "source_attestation" else "ASSERTED", chain: UUID(ref["chain_id"])}
        if "officer_uid" in table.c: required["officer_uid"] = officer
        if "family_relation_version_id" in table.c and record.table != "officer_family_relation": required["family_relation_version_id"] = relation
        if "valid_from" in table.c: required.update(valid_from=None, valid_to=None)
        if record.table == "officer_family_relation": required["relationship_type"] = record.kind
        if record.table == "source_attestation": required.update(attestation_type="RECORDED_BY", actor_officer_uid=None, resolution_status="UNRESOLVED")
        if any(row[k] != v for k, v in required.items()): raise ValueError("Family destination metadata differs.")
        if recover(crypto, backup, row["profile_payload_ciphertext"], row["encryption_key_version"],
            aad("DESTINATION", binding.raw_record_id, officer, assertion, row[pk], table.name, row[chain], relation)) != record.payload():
            raise ValueError("Family destination recovery differs.")
    for name, table in MODELS.items():
        count = connection.execute(select(func.count()).select_from(table).where(table.c.source_assertion_id == assertion)).scalar_one()
        if count != sum(r.table == name for r in expected.values()): raise ValueError("Unexpected family destination row.")
    return len(refs)


def transform(connection, crypto, backup, *, binding, payload, allow_write=False):
    """Caller owns the transaction: assertion, all destinations and receipt commit together."""
    raw = check_source(connection, crypto, backup, binding, payload)
    if allow_write:
        lock = int.from_bytes(hashlib.sha256((POLICY + binding.raw_record_id).encode()).digest()[:8], "big", signed=True)
        connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})
    saved = connection.execute(select(RECEIPT).where(RECEIPT.c.raw_record_id == binding.raw_record_id)).mappings().one_or_none()
    if saved is not None:
        return "VERIFIED_EXISTING", verify_saved(connection, crypto, backup, binding, payload, saved, raw)
    # An assertion without its atomic receipt is an integrity error, not a retry target.
    orphan = connection.execute(select(SourceAssertion.source_assertion_id).where(SourceAssertion.raw_record_id == binding.raw_record_id,
        SourceAssertion.assertion_type == "HR_FAMILY_EVIDENCE")).first()
    if orphan is not None: raise ValueError("Family assertion lacks its atomic receipt.")
    records = logical_records(payload)
    if not allow_write: return "PLANNED", len(records)
    officer, assertion = UUID(payload["officer_uid"]), uuid4()
    source = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == "POLICE_HR_IS")).scalar_one()
    cipher, version = seal(crypto, backup, payload, aad("ASSERTION", binding.raw_record_id, officer, assertion, assertion, "source_assertion"))
    connection.execute(SourceAssertion.__table__.insert().values(source_assertion_id=assertion, officer_uid=officer,
        source_system_id=source, assertion_type="HR_FAMILY_EVIDENCE", asserted_value_ciphertext=cipher, encryption_key_version=version,
        intake_batch_id=raw["batch_id"], import_file_id=str(raw["import_file_id"]), raw_record_id=binding.raw_record_id,
        source_file_name=FILENAME, source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        captured_at=raw["staged_at"], independence_status="UNVERIFIED"))
    refs, relations = [], {}
    for record in records:
        table = MODELS[record.table]; pk, chain, previous = IDS[record.table]
        record_id, chain_id = uuid4(), uuid4()
        relation = relations.get(record.relation_kind) if record.relation_kind else None
        values = {pk: record_id, chain: chain_id, "source_assertion_id": assertion, "version_number": 1,
            "record_state": "ACTIVE" if record.table == "source_attestation" else "ASSERTED"}
        if "officer_uid" in table.c: values["officer_uid"] = officer
        if "valid_from" in table.c: values.update(valid_from=None, valid_to=None)
        if record.table == "officer_family_relation":
            values["relationship_type"] = record.kind; relations[record.kind] = record_id
        elif "family_relation_version_id" in table.c: values["family_relation_version_id"] = relation
        if record.table == "source_attestation": values.update(attestation_type="RECORDED_BY", actor_officer_uid=None, resolution_status="UNRESOLVED")
        cipher, version = seal(crypto, backup, record.payload(), aad("DESTINATION", binding.raw_record_id, officer, assertion, record_id, table.name, chain_id, relation))
        values.update(profile_payload_ciphertext=cipher, encryption_key_version=version)
        connection.execute(table.insert().values(**values))
        refs.append(dict(table=table.name, kind=record.kind, record_id=str(record_id), chain_id=str(chain_id)))
    receipt = dict(raw_record_id=binding.raw_record_id, officer_uid=officer, identifier_version_id=binding.identifier_version_id,
        source_assertion_id=assertion, confirmation_sha256=binding.confirmation_sha256, code_revision=binding.code_revision, policy_version=POLICY)
    evidence = dict(binding=receipt_binding(receipt), plan=payload, records=refs)
    cipher, version = seal(crypto, backup, evidence, aad("RECEIPT", binding.raw_record_id, officer, assertion, assertion, RECEIPT.name))
    connection.execute(RECEIPT.insert().values(**receipt, evidence_ciphertext=cipher, encryption_key_version=version))
    saved = connection.execute(select(RECEIPT).where(RECEIPT.c.raw_record_id == binding.raw_record_id)).mappings().one()
    return "CREATED", verify_saved(connection, crypto, backup, binding, payload, saved, raw)
