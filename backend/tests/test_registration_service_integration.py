"""Exercise real row encryption and registration writes, with rollback isolation.

These tests require an empty identity registry. They never clear existing data.
Successful commits across concurrent sessions require a disposable test database;
the contention test here verifies that another session cannot pass the writer lock.
"""

import base64
import copy
import csv
import hashlib
import io
import json
import os
from contextlib import contextmanager
from dataclasses import asdict
from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import func, insert, select, text
from sqlalchemy.exc import DBAPIError

from database import create_identity_engine
from settings import Settings
from app.identity import registration_service as service
from app.intake.staging_rows import seal_row
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.security.identity_crypto import IdentityCrypto
from app.staging.identity_decision import IdentityRegistrationDecision
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_IDENTITY_DB_TESTS") != "1",
    reason="Identity database tests require explicit enablement.",
)
DECISIONS = IdentityRegistrationDecision.__table__
IDENTIFIERS = OfficerIdentifierVersion.__table__
COUNT_MODELS = (
    Officer, SourceAssertion, OfficerIdentifierVersion,
    IdentityRegistrationDecision, SourceSystem,
)


class SavepointEngine:
    """Run the service within an outer test transaction, never a real commit."""

    def __init__(self, connection):
        self.connection = connection

    @contextmanager
    def begin(self):
        with self.connection.begin_nested():
            yield self.connection


def counts(connection):
    return tuple(
        connection.execute(select(func.count()).select_from(model.__table__)).scalar_one()
        for model in COUNT_MODELS
    )


@pytest.fixture
def case(tmp_path):
    engine = create_identity_engine(Settings())
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                account, database = connection.execute(
                    text("SELECT current_user, current_database()")
                ).one()
                if account != "police_identity_app" or database != "police_identity":
                    raise RuntimeError("Use the restricted identity application account.")
                # Do not mix test keyrings with an already populated identity registry.
                if any(counts(connection)[:4]):
                    pytest.skip(
                        "Service tests need an empty identity registry in an isolated "
                        "database. Existing identity records were not changed."
                    )

                def key():
                    return base64.b64encode(os.urandom(32)).decode("ascii")

                key_path = tmp_path / "test-keys.json"
                key_path.write_text(json.dumps({
                    "active_encryption_key_version": "test-enc-v1",
                    "encryption_keys": {"test-enc-v1": key()},
                    "active_lookup_key_version": "test-lookup-v1",
                    "lookup_keys": {
                        "test-lookup-v1": key(), "test-lookup-v2": key(),
                    },
                }), encoding="utf-8")
                key_path.chmod(0o600)
                crypto = IdentityCrypto(key_path)

                batch_id = f"TEST-REGISTRATION-{uuid4()}"
                file_id = uuid4()
                archive_path = f"{batch_id}/original/{service.PROFILE_FILENAME}"
                columns = list(service.IDENTIFIER_FIELDS)

                def profile():
                    token = uuid4().hex
                    # These fictional text identifiers are not NIC-validity fixtures.
                    return [f"TEST-NIC-{token}", f"TEST-POLICE-{token}", "", f"TEST-TIN-{token}"]

                first = profile()
                missing_nic = profile()
                missing_nic[0] = ""
                rows = [first, profile(), list(first), missing_nic, profile()]
                buffer = io.StringIO(newline="")
                writer = csv.writer(buffer)
                writer.writerow(columns)
                writer.writerows(rows)
                csv_bytes = buffer.getvalue().encode("utf-8")
                file_hash = hashlib.sha256(csv_bytes).hexdigest()
                archive_hash = hashlib.sha256(batch_id.encode("utf-8")).hexdigest()

                confirmation_path = tmp_path / "confirmation.json"
                confirmation_path.write_text(json.dumps({
                    "schema_version": "1.0",
                    "confirmation_id": f"TEST-CONFIRMATION-{uuid4()}",
                    "batch_id": batch_id,
                    "archive_sha256": archive_hash,
                    "confirmed_on": "2026-10-06",
                    "confirmed_by": "Test fixture",
                    "confirmation_basis": "Test-only attribution",
                    "scope": "Reported supplying source",
                    "original_archive_modified": False,
                    "independent_custodian_verification": "NOT_ESTABLISHED",
                    "source_independence": "UNVERIFIED",
                    "source_truth": "NOT_ASSESSED",
                    "files": [{
                        "file_name": service.PROFILE_FILENAME,
                        "reported_source_system_code": "PF_REGISTRY",
                    }],
                }), encoding="utf-8")
                confirmation_hash = hashlib.sha256(confirmation_path.read_bytes()).hexdigest()

                connection.execute(insert(IntakeBatch.__table__), {
                    "batch_id": batch_id, "archive_sha256": archive_hash,
                    "archive_size_bytes": len(csv_bytes), "expected_file_count": 1,
                    "registration_receipt_id": uuid4(),
                    "registration_receipt_sha256": "b" * 64, "schema_version": "1.0",
                })
                connection.execute(insert(IntakeFile.__table__), {
                    "import_file_id": file_id, "batch_id": batch_id,
                    "archive_path": archive_path, "source_file_sha256": file_hash,
                    "size_bytes": len(csv_bytes), "expected_row_count": len(rows),
                    "column_count": len(columns), "columns": columns,
                    "declared_encoding": "UTF-8", "delimiter": ",",
                })
                row_ids = []
                for number, values in enumerate(rows, 1):
                    sealed = seal_row(
                        crypto, batch_id=batch_id, archive_path=archive_path,
                        source_file_sha256=file_hash, source_row_number=number,
                        columns=columns, values=values,
                    )
                    stored = {**asdict(sealed), "import_file_id": file_id}
                    if number == 5:
                        # Insert a deliberately damaged test envelope, never alter real rows.
                        damaged = bytearray(stored["payload_ciphertext"])
                        damaged[-1] ^= 1
                        stored["payload_ciphertext"] = bytes(damaged)
                    connection.execute(insert(RawRecord.__table__), stored)
                    row_ids.append(sealed.raw_record_id)

                yield {
                    "connection": connection, "engine": engine,
                    "adapter": SavepointEngine(connection), "crypto": crypto,
                    "row_ids": row_ids, "rows": rows,
                    "confirmation_path": confirmation_path,
                    "confirmation_hash": confirmation_hash,
                }
            finally:
                # Roll back both staging fixtures and every successful service call.
                transaction.rollback()
    finally:
        engine.dispose()


def register(case, index=0, *, crypto=None, engine=None, **changes):
    arguments = {
        "raw_record_id": case["row_ids"][index],
        "confirmation_path": case["confirmation_path"],
        "expected_confirmation_sha256": case["confirmation_hash"],
        "code_revision": "a" * 40,
    }
    arguments.update(changes)
    return service.register_personal_row(
        engine if engine is not None else case["adapter"],
        crypto if crypto is not None else case["crypto"],
        **arguments,
    )


def decision_evidence(case, result):
    row = case["connection"].execute(
        select(DECISIONS).where(DECISIONS.c.decision_id == result.decision_id)
    ).mappings().one()
    return case["crypto"].decrypt_assertion(
        row["evidence_ciphertext"], key_version=row["encryption_key_version"],
        context=service.evidence_context("DECISION", result.decision_id),
    )


def test_created_records_have_protected_source_evidence(case):
    result = register(case)
    assert result.outcome == "CREATED"
    assert result.identifier_count == 3  # Blank regimental number stays absent.
    assert result.officer_uid is not None
    assert result.replayed is False
    assert counts(case["connection"])[:4] == (1, 3, 3, 1)
    evidence = decision_evidence(case, result)
    assert evidence["binding"]["source_confirmation_sha256"] == case["confirmation_hash"]
    assert evidence["source_independence"] == "UNVERIFIED"
    assert evidence["missing_identifier_types"] == ["REGIMENTAL_NUMBER"]
    for output in evidence["outputs"]:
        assertion_id = UUID(output["source_assertion_id"])
        assertion = case["connection"].execute(
            select(SourceAssertion.__table__).where(
                SourceAssertion.source_assertion_id == assertion_id
            )
        ).mappings().one()
        payload = case["crypto"].decrypt_assertion(
            assertion["asserted_value_ciphertext"],
            key_version=assertion["encryption_key_version"],
            context=service.evidence_context("ASSERTION", assertion_id),
        )
        field = payload["source_column"]
        field_index = list(service.IDENTIFIER_FIELDS).index(field)
        assert payload["reported_value"] == case["rows"][0][field_index]
        assert assertion["independence_status"] == "UNVERIFIED"
        assert assertion["valid_from"] is None
        assert assertion["valid_to"] is None


def test_same_row_retry_verifies_and_reuses_saved_outputs(case):
    first = register(case)
    before = counts(case["connection"])
    repeated = register(case, code_revision="b" * 40)
    assert repeated.replayed is True
    assert repeated.decision_id == first.decision_id
    assert repeated.officer_uid == first.officer_uid
    assert counts(case["connection"]) == before


def test_duplicate_identifiers_in_another_row_require_review(case):
    register(case)
    result = register(case, index=2)
    assert result.outcome == "REVIEW_REQUIRED"
    assert result.reason_code == "EXISTING_CANDIDATE_REQUIRES_REVIEW"
    assert result.officer_uid is None
    assert result.identifier_count == 0
    assert counts(case["connection"])[:4] == (1, 3, 3, 2)
    evidence = decision_evidence(case, result)
    assert evidence["lookup_scope_complete"] is True
    assert all(scope["key_material_checked"] for scope in evidence["stored_lookup_scopes"])


def test_missing_nic_saves_only_a_review_decision(case):
    result = register(case, index=3)
    assert result.reason_code == "MISSING_REQUIRED_IDENTIFIERS"
    assert counts(case["connection"])[:4] == (0, 0, 0, 1)
    repeated = register(case, index=3)
    assert repeated.replayed is True
    assert repeated.decision_id == result.decision_id


def test_wrong_confirmation_fingerprint_causes_no_identity_writes(case):
    before = counts(case["connection"])
    with pytest.raises(service.RegistrationError, match="fingerprint changed"):
        register(case, expected_confirmation_sha256="f" * 64)
    assert counts(case["connection"]) == before


def test_decision_encryption_failure_rolls_back_prior_identity_inserts(case, monkeypatch):
    original = case["crypto"].encrypt_assertion

    def fail_final_encryption(payload, *, context):
        if json.loads(context)[1] == "DECISION":
            raise RuntimeError("Injected final encryption failure.")
        return original(payload, context=context)

    before = counts(case["connection"])
    monkeypatch.setattr(case["crypto"], "encrypt_assertion", fail_final_encryption)
    with pytest.raises(RuntimeError, match="Injected final"):
        register(case)
    assert counts(case["connection"]) == before


def test_transaction_boundary_failure_does_not_report_success(case):
    class FailingBoundary(SavepointEngine):
        @contextmanager
        def begin(self):
            with self.connection.begin_nested():
                yield self.connection
                raise RuntimeError("Injected transaction boundary failure.")

    before = counts(case["connection"])
    with pytest.raises(RuntimeError, match="transaction boundary"):
        register(case, engine=FailingBoundary(case["connection"]))
    assert counts(case["connection"]) == before


def test_missing_retained_lookup_key_prevents_new_creation(case):
    register(case)
    limited = copy.copy(case["crypto"])
    limited.lookup_keys = {"test-lookup-v2": case["crypto"].lookup_keys["test-lookup-v2"]}
    limited.active_lookup_version = "test-lookup-v2"
    result = register(case, index=1, crypto=limited)
    assert result.reason_code == "INCOMPLETE_LOOKUP_SCOPE"
    assert counts(case["connection"])[:4] == (1, 3, 3, 2)


def test_wrong_key_bytes_with_same_version_prevent_duplicate_creation(case):
    register(case)
    wrong = copy.copy(case["crypto"])
    wrong.lookup_keys = dict(case["crypto"].lookup_keys)
    wrong.lookup_keys["test-lookup-v1"] = os.urandom(32)
    # Row 3 repeats the first row's identifiers; a false negative would duplicate it.
    result = register(case, index=2, crypto=wrong)
    assert result.reason_code == "INCOMPLETE_LOOKUP_SCOPE"
    assert counts(case["connection"])[:4] == (1, 3, 3, 2)


def test_retry_rejects_wrong_lookup_key_material(case):
    register(case)
    before = counts(case["connection"])
    wrong = copy.copy(case["crypto"])
    wrong.lookup_keys = {**case["crypto"].lookup_keys, "test-lookup-v1": os.urandom(32)}
    with pytest.raises(service.RegistrationError, match="identifier evidence"):
        register(case, crypto=wrong)
    assert counts(case["connection"]) == before


def test_unrecognized_retained_normalization_profile_prevents_creation(case):
    first = register(case)
    original = case["connection"].execute(
        select(IDENTIFIERS).where(IDENTIFIERS.c.officer_uid == first.officer_uid)
    ).mappings().first()
    clone = dict(original)
    identifier_id = uuid4()
    field = next(field for field, kind in service.IDENTIFIER_FIELDS.items()
                 if kind == original["identifier_type"])
    value = case["rows"][0][list(service.IDENTIFIER_FIELDS).index(field)]
    ciphertext, key_version = case["crypto"].encrypt(
        value.encode("utf-8"), context=service.evidence_context("IDENTIFIER", identifier_id),
    )
    clone.update(
        identifier_version_id=identifier_id, identifier_chain_uid=uuid4(),
        normalization_profile="UNSUPPORTED_TEST_PROFILE",
        identifier_value_ciphertext=ciphertext, encryption_key_version=key_version,
    )
    case["connection"].execute(insert(IDENTIFIERS), clone)
    result = register(case, index=1)
    assert result.reason_code == "INCOMPLETE_LOOKUP_SCOPE"
    assert counts(case["connection"])[0] == 1


def test_tampered_staging_ciphertext_rejected_before_identity_writes(case):
    before = counts(case["connection"])
    with pytest.raises(InvalidTag):
        register(case, index=4)
    assert counts(case["connection"]) == before


def test_saved_decision_ciphertext_cannot_be_transplanted(case):
    first = register(case)
    saved = dict(case["connection"].execute(
        select(DECISIONS).where(DECISIONS.c.decision_id == first.decision_id)
    ).mappings().one())
    # Create an invalid test record; do not update the legitimate saved decision.
    saved.update(decision_id=uuid4(), raw_record_id=case["row_ids"][1])
    case["connection"].execute(insert(DECISIONS), saved)
    before = counts(case["connection"])
    with pytest.raises(InvalidTag):
        register(case, index=1)
    assert counts(case["connection"]) == before


def test_another_session_cannot_pass_the_active_registration_lock(case):
    register(case)
    before = counts(case["connection"])
    # The outer fixture transaction still holds the lock after savepoint release.
    with case["engine"].connect() as second:
        with second.begin():
            second.execute(text("SET LOCAL lock_timeout = '200ms'"))
            with pytest.raises(DBAPIError) as error:
                register(case, engine=SavepointEngine(second))
            assert error.value.orig.sqlstate == "55P03"
    assert counts(case["connection"]) == before
