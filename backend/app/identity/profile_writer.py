"""Atomic protected profile import with verified replay; not a user-facing API.

The development CLI uses the restricted application DB account. Application
HQ Admin authentication and role enforcement remain pending; never expose
this service directly as an unauthenticated endpoint.
"""

from pathlib import PurePosixPath
from uuid import UUID, uuid4
from sqlalchemy import insert, select, func
from app.models import (
    OfficerNameVersion, OfficerAddressVersion, OfficerDemographicVersion,
    OfficerFamilyRelation, OfficerPhysicalProfileVersion, OfficerPreviousEmploymentVersion,
    OfficerRestrictedProfileVersion, OfficerContactVersion, SourceAssertion,
    ProfileTransformReceipt,
)
from app.identity.profile_records import WRITER_POLICY, PROTECTED_TABLES, logical_records, storage_context
from app.identity.profile_plan_crypto import seal_plan, open_plan


MODELS = {model.__tablename__: model for model in (
    OfficerNameVersion, OfficerAddressVersion, OfficerDemographicVersion,
    OfficerFamilyRelation, OfficerPhysicalProfileVersion, OfficerPreviousEmploymentVersion,
    OfficerRestrictedProfileVersion, OfficerContactVersion,
)}
PK = {
    "officer_name_version": "name_version_id", "officer_address_version": "address_version_id",
    "officer_demographic_version": "demographic_version_id", "officer_family_relation": "family_relation_version_id",
    "officer_physical_profile_version": "physical_profile_version_id",
    "officer_previous_employment_version": "employment_version_id",
    "officer_restricted_profile_version": "restricted_profile_version_id",
    "officer_contact_version": "contact_version_id",
}
CHAIN = {
    "officer_family_relation": "relation_chain_uid", "officer_previous_employment_version": "employment_chain_uid",
    "officer_restricted_profile_version": "restricted_profile_chain_uid", "officer_contact_version": "contact_chain_uid",
}


def _context(purpose, raw_id, officer, record, table):
    return storage_context(purpose, raw_record_id=raw_id, officer_uid=officer, record_id=record, table=table)


def _decrypt_both(crypto, backup, ciphertext, key_version, context):
    first = crypto.decrypt_assertion(ciphertext, key_version=key_version, context=context)
    second = backup.decrypt_assertion(ciphertext, key_version=key_version, context=context)
    if first != second:
        raise ValueError("Encrypted evidence backup recovery differs.")
    return first


def review_payload(crypto, backup, plan, officer_uid, raw_id, references):
    binding = dict(officer_uid=officer_uid, raw_record_id=raw_id)
    ciphertext, version = seal_plan(crypto, plan, reference_evidence=references, **binding)
    primary = open_plan(crypto, ciphertext, key_version=version, **binding)
    recovered = open_plan(backup, ciphertext, key_version=version, **binding)
    if primary != recovered:
        raise ValueError("Review-plan recovery differs.")
    return primary


def receipt_binding(receipt):
    return {key: str(receipt[key]) for key in (
        "raw_record_id", "officer_uid", "identity_decision_id", "source_assertion_id",
        "confirmation_sha256", "policy_version", "code_revision",
    )}


def verify_saved(connection, crypto, backup, receipt, *, raw, decision, expected_payload):
    raw_id, officer = raw["raw_record_id"], decision["officer_uid"]
    if (receipt["officer_uid"], receipt["identity_decision_id"], receipt["confirmation_sha256"], receipt["policy_version"]) != (
        officer, decision["decision_id"], decision["source_confirmation_sha256"], WRITER_POLICY,
    ):
        raise ValueError("Saved profile receipt binding differs; explicit review is required.")
    assertion_id = receipt["source_assertion_id"]
    evidence = _decrypt_both(crypto, backup, receipt["evidence_ciphertext"], receipt["encryption_key_version"],
        _context("RECEIPT", raw_id, officer, assertion_id, "profile_transform_receipt"))
    if evidence.get("binding") != receipt_binding(receipt) or evidence.get("profile_plan") != expected_payload:
        raise ValueError("Saved profile receipt evidence differs.")
    assertion = connection.execute(select(SourceAssertion.__table__).where(
        SourceAssertion.source_assertion_id == assertion_id
    )).mappings().one()
    for key, expected in (
        ("officer_uid", officer), ("raw_record_id", raw_id),
        ("source_system_id", decision["source_system_id"]), ("source_file_sha256", raw["source_file_sha256"]),
        ("source_row_number", raw["source_row_number"]), ("assertion_type", "PF_PERSONAL_PROFILE"),
        ("intake_batch_id", raw["batch_id"]), ("import_file_id", str(raw["import_file_id"])),
        ("source_file_name", PurePosixPath(raw["archive_path"]).name),
    ):
        if assertion[key] != expected:
            raise ValueError("Profile assertion provenance differs.")
    payload = _decrypt_both(crypto, backup, assertion["asserted_value_ciphertext"], assertion["encryption_key_version"],
        _context("ASSERTION", raw_id, officer, assertion_id, "source_assertion"))
    if payload != expected_payload:
        raise ValueError("Saved profile assertion differs from source plan.")
    expected_records = {(r.table, r.kind): r for r in logical_records_from_payload(expected_payload)}
    refs = evidence.get("records")
    if not isinstance(refs, list) or len(refs) != len(expected_records):
        raise ValueError("Profile destination coverage differs.")
    seen = set()
    for ref in refs:
        key = (ref["table"], ref["kind"])
        if key in seen or key not in expected_records:
            raise ValueError("Profile destination coverage is duplicated or unknown.")
        seen.add(key)
        model, record_id = MODELS[key[0]], UUID(ref["record_id"])
        saved = connection.execute(select(model.__table__).where(model.__table__.c[PK[key[0]]] == record_id)).mappings().one()
        if saved["officer_uid"] != officer or saved["source_assertion_id"] != assertion_id or saved["version_number"] != 1:
            raise ValueError("Profile destination source or version differs.")
        if saved["valid_from"] is not None or saved["valid_to"] is not None:
            raise ValueError("Unknown profile dates were replaced.")
        expected = expected_records[key].values
        if key[0] == "officer_name_version":
            if any(saved[k] != v for k, v in expected.items()):
                raise ValueError("Saved officer name differs.")
        else:
            column = "profile_payload_ciphertext" if key[0] in PROTECTED_TABLES else "contact_value_ciphertext"
            payload = _decrypt_both(crypto, backup, saved[column], saved["encryption_key_version"],
                _context("DESTINATION", raw_id, officer, record_id, key[0]))
            if payload != {"kind": key[1], "values": expected, "valid_from": None, "valid_to": None, "measured_at": None}:
                raise ValueError("Saved protected profile payload differs.")
        if key[0] == "officer_address_version" and saved["address_type"] != "PRESENT":
            raise ValueError("Address routing category differs.")
        if key[0] == "officer_family_relation" and saved["relationship_type"] != "FATHER":
            raise ValueError("Family routing category differs.")
        if key[0] == "officer_contact_version":
            digest, version = crypto.lookup_hmac(expected["value"], identifier_type="PROFILE_CONTACT_" + key[1], key_version=saved["lookup_key_version"])
            if (saved["contact_type"], saved["normalization_profile"], saved["contact_lookup_hmac"]) != (key[1], WRITER_POLICY, digest):
                raise ValueError("Contact lookup or routing binding differs.")
    for table, model in MODELS.items():
        actual = connection.execute(select(func.count()).select_from(model.__table__).where(
            model.source_assertion_id == assertion_id
        )).scalar_one()
        required = sum(1 for table_name, _ in expected_records if table_name == table)
        if actual != required:
            raise ValueError("Unexpected profile destination evidence coverage.")
    return len(refs)


def logical_records_from_payload(payload):
    # Reconstruct only validated parsed values; original date/decimal tags must
    # remain byte-for-byte comparable to the planned normalized payload.
    from app.identity.profile_records import LogicalRecord
    groups, contacts = {}, []
    for item in payload["fields"]:
        if item["value"] is None or item["table"] == "source_assertion":
            continue
        if item["table"] == "officer_contact_version":
            kind = "EMAIL" if item["source_column"] == "officer_email" else "MOBILE"
            contacts.append(LogicalRecord(item["table"], kind, {"value": item["value"]}))
        else:
            groups.setdefault(item["table"], {})[item["target_field"]] = item["value"]
    records = [LogicalRecord(t, "PRESENT" if t == "officer_address_version" else "FATHER" if t == "officer_family_relation" else "PROFILE", v) for t,v in groups.items()]
    return tuple(sorted(records + contacts, key=lambda r: (r.table, r.kind)))


def transform_row(connection, crypto, backup, *, raw, decision, plan, references, code_revision, allow_write):
    raw_id, officer = raw["raw_record_id"], decision["officer_uid"]
    logical = logical_records(plan)
    expected = review_payload(crypto, backup, plan, officer, raw_id, references)
    receipt = connection.execute(select(ProfileTransformReceipt.__table__).where(
        ProfileTransformReceipt.raw_record_id == raw_id
    )).mappings().one_or_none()
    if receipt is not None:
        count = verify_saved(connection, crypto, backup, receipt, raw=raw, decision=decision, expected_payload=expected)
        return "VERIFIED_EXISTING", count
    if not allow_write:
        return "PLANNED", len(logical)
    assertion_id = uuid4()
    context = _context("ASSERTION", raw_id, officer, assertion_id, "source_assertion")
    ciphertext, version = crypto.encrypt_assertion(expected, context=context)
    if _decrypt_both(crypto, backup, ciphertext, version, context) != expected:
        raise ValueError("Assertion encryption verification differs.")
    connection.execute(insert(SourceAssertion.__table__).values(
        source_assertion_id=assertion_id, officer_uid=officer,
        source_system_id=decision["source_system_id"], assertion_type="PF_PERSONAL_PROFILE",
        asserted_value_ciphertext=ciphertext, encryption_key_version=version,
        intake_batch_id=raw["batch_id"], import_file_id=str(raw["import_file_id"]),
        raw_record_id=raw_id, source_file_name=PurePosixPath(raw["archive_path"]).name,
        source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        captured_at=raw["staged_at"], independence_status="UNVERIFIED",
    ))
    refs = []
    for record in logical:
        record_id = uuid4()
        values = {PK[record.table]: record_id, "officer_uid": officer,
                  "source_assertion_id": assertion_id, "version_number": 1,
                  "valid_from": None, "valid_to": None, "record_state": "ASSERTED"}
        if record.table in CHAIN:
            values[CHAIN[record.table]] = uuid4()
        if record.table == "officer_name_version":
            values.update(record.values)
        else:
            payload = {"kind": record.kind, "values": record.values,
                       "valid_from": None, "valid_to": None, "measured_at": None}
            context = _context("DESTINATION", raw_id, officer, record_id, record.table)
            ciphertext, version = crypto.encrypt_assertion(payload, context=context)
            if _decrypt_both(crypto, backup, ciphertext, version, context) != payload:
                raise ValueError("Destination encryption verification differs.")
            values["profile_payload_ciphertext" if record.table in PROTECTED_TABLES else "contact_value_ciphertext"] = ciphertext
            values["encryption_key_version"] = version
            if record.table == "officer_contact_version":
                digest, lookup_version = crypto.lookup_hmac(record.values["value"], identifier_type="PROFILE_CONTACT_" + record.kind)
                values.update(contact_type=record.kind, contact_lookup_hmac=digest,
                              lookup_key_version=lookup_version, normalization_profile=WRITER_POLICY)
            if record.table == "officer_address_version":
                values["address_type"] = "PRESENT"
            if record.table == "officer_family_relation":
                values["relationship_type"] = "FATHER"
        connection.execute(insert(MODELS[record.table].__table__).values(**values))
        refs.append({"table": record.table, "kind": record.kind, "record_id": str(record_id)})
    receipt = dict(raw_record_id=raw_id, officer_uid=officer,
                   identity_decision_id=decision["decision_id"], source_assertion_id=assertion_id,
                   confirmation_sha256=decision["source_confirmation_sha256"], policy_version=WRITER_POLICY,
                   code_revision=code_revision)
    evidence = {"binding": receipt_binding(receipt), "profile_plan": expected, "records": refs}
    ciphertext, version = crypto.encrypt_assertion(evidence, context=_context("RECEIPT", raw_id, officer, assertion_id, "profile_transform_receipt"))
    receipt.update(evidence_ciphertext=ciphertext, encryption_key_version=version)
    connection.execute(insert(ProfileTransformReceipt.__table__).values(**receipt))
    count = verify_saved(connection, crypto, backup, receipt, raw=raw, decision=decision, expected_payload=expected)
    return "CREATED", count
