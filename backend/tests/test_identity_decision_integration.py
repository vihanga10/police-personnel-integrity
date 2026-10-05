"""Test decision constraints using temporary, rolled-back database records."""

import hashlib
import os
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError

from database import create_identity_engine
from settings import Settings
from app.models import Officer, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_IDENTITY_DB_TESTS") != "1",
    reason="Identity database tests require explicit enablement.",
)

DECISIONS = IdentityRegistrationDecision.__table__


@pytest.fixture
def case():
    """Build isolated fixtures and discard every change after each test."""
    engine = create_identity_engine(Settings())

    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                account = connection.execute(
                    text("SELECT current_user")
                ).scalar_one()
                if account != "police_identity_app":
                    raise RuntimeError(
                        "Run these tests as police_identity_app."
                    )

                batch_id = f"TEST-DECISION-{uuid4()}"
                file_id = uuid4()
                officer_id = uuid4()
                source_id = uuid4()
                root_id = uuid4()
                file_hash = "c" * 64
                archive_path = f"{batch_id}/original/test.csv"

                # Structural tests use dummy bytes, not real encrypted data.
                dummy_ciphertext = b"\x01" * 29
                row_ids = [
                    hashlib.sha256(
                        f"{batch_id}:{number}".encode("utf-8")
                    ).hexdigest()
                    for number in (1, 2)
                ]

                connection.execute(
                    insert(Officer.__table__),
                    {"officer_uid": officer_id},
                )
                connection.execute(
                    insert(SourceSystem.__table__),
                    {
                        "source_system_id": source_id,
                        "source_system_code": f"TEST_{source_id}",
                        "source_name": "Temporary decision test",
                    },
                )
                connection.execute(
                    insert(IntakeBatch.__table__),
                    {
                        "batch_id": batch_id,
                        "archive_sha256": "a" * 64,
                        "archive_size_bytes": 100,
                        "expected_file_count": 1,
                        "registration_receipt_id": uuid4(),
                        "registration_receipt_sha256": "b" * 64,
                        "schema_version": "1.0",
                    },
                )
                connection.execute(
                    insert(IntakeFile.__table__),
                    {
                        "import_file_id": file_id,
                        "batch_id": batch_id,
                        "archive_path": archive_path,
                        "source_file_sha256": file_hash,
                        "size_bytes": 100,
                        "expected_row_count": 2,
                        "column_count": 1,
                        "columns": ["test_value"],
                        "declared_encoding": "UTF-8",
                        "delimiter": ",",
                    },
                )

                for number, row_id in enumerate(row_ids, start=1):
                    connection.execute(
                        insert(RawRecord.__table__),
                        {
                            "raw_record_id": row_id,
                            "import_file_id": file_id,
                            "batch_id": batch_id,
                            "archive_path": archive_path,
                            "source_file_sha256": file_hash,
                            "source_row_number": number,
                            "schema_version": "1.0",
                            "payload_ciphertext": dummy_ciphertext,
                            "encryption_key_version": "test-key",
                        },
                    )

                root = {
                    "decision_id": root_id,
                    "raw_record_id": row_ids[0],
                    "version_number": 1,
                    "previous_decision_id": None,
                    "previous_version_number": None,
                    "outcome": "REVIEW_REQUIRED",
                    "reason_code": "TEST_REVIEW",
                    "officer_uid": None,
                    "source_system_id": source_id,
                    "source_confirmation_id": "TEST-CONFIRMATION",
                    "source_confirmation_sha256": "d" * 64,
                    "policy_version": "TEST_POLICY_V1",
                    "normalization_profile": "IDENTIFIER_EXACT_TEXT_V1",
                    "code_revision": "e" * 40,
                    "evidence_ciphertext": dummy_ciphertext,
                    "encryption_key_version": "test-key",
                }
                connection.execute(insert(DECISIONS), root)

                yield connection, root, row_ids, officer_id
            finally:
                # Even failed assertions must leave no committed test records.
                transaction.rollback()
    finally:
        engine.dispose()


def replacement(root, **changes):
    """Construct a proposed second decision with a fresh identifier."""
    values = {
        **root,
        "decision_id": uuid4(),
        "version_number": 2,
        "previous_decision_id": root["decision_id"],
        "previous_version_number": 1,
    }
    values.update(changes)
    return values


def assert_insert_rejected(connection, values, sqlstate):
    """Use a savepoint so an expected rejection does not abort the fixture."""
    with pytest.raises(DBAPIError) as error:
        with connection.begin_nested():
            connection.execute(insert(DECISIONS), values)

    # Check the database error category rather than accepting any exception.
    assert error.value.orig.sqlstate == sqlstate


def test_valid_replacement_preserves_original_decision(case):
    connection, root, _, officer_id = case
    connection.execute(
        insert(DECISIONS),
        replacement(
            root,
            outcome="MATCHED",
            reason_code="TEST_MATCH",
            officer_uid=officer_id,
        ),
    )

    rows = connection.execute(
        select(
            DECISIONS.c.version_number,
            DECISIONS.c.outcome,
            DECISIONS.c.officer_uid,
        )
        .where(DECISIONS.c.raw_record_id == root["raw_record_id"])
        .order_by(DECISIONS.c.version_number)
    ).all()

    assert [tuple(row) for row in rows] == [
        (1, "REVIEW_REQUIRED", None),
        (2, "MATCHED", officer_id),
    ]


@pytest.mark.parametrize(
    ("version", "has_previous", "previous_version"),
    [
        (0, False, None),
        (1, True, 1),
        (2, False, None),
        (2, True, None),
        (2, False, 1),
        (3, True, 1),
    ],
)
def test_invalid_version_structure_rejected(
    case, version, has_previous, previous_version
):
    connection, root, _, _ = case
    values = replacement(
        root,
        version_number=version,
        previous_decision_id=root["decision_id"] if has_previous else None,
        previous_version_number=previous_version,
    )
    assert_insert_rejected(connection, values, "23514")


def test_false_predecessor_version_rejected(case):
    connection, root, _, _ = case

    # The arithmetic is valid, but the referenced decision is version 1, not 2.
    values = replacement(
        root,
        version_number=3,
        previous_version_number=2,
    )
    assert_insert_rejected(connection, values, "23503")


def test_cross_row_predecessor_rejected(case):
    connection, root, row_ids, _ = case
    values = replacement(root, raw_record_id=row_ids[1])
    assert_insert_rejected(connection, values, "23503")


def test_duplicate_initial_decision_rejected(case):
    connection, root, _, _ = case
    values = {**root, "decision_id": uuid4()}
    assert_insert_rejected(connection, values, "23505")


def test_second_replacement_of_same_predecessor_rejected(case):
    connection, root, _, _ = case
    connection.execute(insert(DECISIONS), replacement(root))
    assert_insert_rejected(connection, replacement(root), "23505")


@pytest.mark.parametrize(
    ("outcome", "attach_officer"),
    [
        ("CREATED", False),
        ("MATCHED", False),
        ("REVIEW_REQUIRED", True),
        ("UNKNOWN", False),
    ],
)
def test_invalid_officer_outcome_combination_rejected(
    case, outcome, attach_officer
):
    connection, root, _, officer_id = case
    values = replacement(
        root,
        outcome=outcome,
        officer_uid=officer_id if attach_officer else None,
    )
    assert_insert_rejected(connection, values, "23514")


@pytest.mark.parametrize("target", ["raw_record", "source_system", "officer"])
def test_missing_referenced_record_rejected(case, target):
    connection, root, _, _ = case

    # Use a new root so predecessor constraints do not obscure these checks.
    values = {
        **root,
        "decision_id": uuid4(),
        "raw_record_id": case[2][1],
    }
    if target == "raw_record":
        values["raw_record_id"] = hashlib.sha256(
            uuid4().bytes
        ).hexdigest()
    elif target == "source_system":
        values["source_system_id"] = uuid4()
    else:
        values["outcome"] = "MATCHED"
        values["officer_uid"] = uuid4()

    assert_insert_rejected(connection, values, "23503")


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_application_cannot_modify_saved_decision(case, operation):
    connection, root, _, _ = case

    if operation == "update":
        statement = (
            DECISIONS.update()
            .where(DECISIONS.c.decision_id == root["decision_id"])
            .values(reason_code="TEST_CHANGED")
        )
    else:
        statement = DECISIONS.delete().where(
            DECISIONS.c.decision_id == root["decision_id"]
        )

    with pytest.raises(DBAPIError) as error:
        with connection.begin_nested():
            connection.execute(statement)

    assert error.value.orig.sqlstate == "42501"


def test_effective_application_privileges(case):
    connection, _, _, _ = case

    # Check effective permissions without attempting a table-wide TRUNCATE.
    for privilege, expected in {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }.items():
        actual = connection.execute(
            text(
                "SELECT has_table_privilege("
                "current_user, :table_name, :privilege)"
            ),
            {
                "table_name": "staging.identity_registration_decision",
                "privilege": privilege,
            },
        ).scalar_one()
        assert actual is expected, privilege