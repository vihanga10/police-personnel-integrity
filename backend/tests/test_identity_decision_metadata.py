"""Check the decision model before generating its database migration."""

from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.db.base import Base
from app.db.staging_base import StagingBase
from app.staging.identity_decision import IdentityRegistrationDecision


def test_decision_uses_staging_metadata():
    table = IdentityRegistrationDecision.__table__

    assert table.fullname == "staging.identity_registration_decision"
    assert StagingBase.metadata.tables[table.fullname] is table
    assert table.fullname not in Base.metadata.tables


def test_source_and_identity_foreign_keys_resolve():
    table = IdentityRegistrationDecision.__table__
    expected = {
        "raw_record_id": "staging.raw_record.raw_record_id",
        "officer_uid": "identity.officer.officer_uid",
        "source_system_id": "identity.source_system.source_system_id",
    }

    for field, target in expected.items():
        # Exclude the separate composite predecessor relationship.
        targets = {
            f"{fk.column.table.fullname}.{fk.column.name}"
            for fk in table.c[field].foreign_keys
        }
        assert target in targets


def test_predecessor_is_bound_to_same_row_and_version():
    table = IdentityRegistrationDecision.__table__
    constraint = next(
        item
        for item in table.foreign_key_constraints
        if item.name == "fk_identity_decision_previous"
    )

    pairs = [
        (element.parent.name, element.column.name)
        for element in constraint.elements
    ]
    assert pairs == [
        ("previous_decision_id", "decision_id"),
        ("raw_record_id", "raw_record_id"),
        ("previous_version_number", "version_number"),
    ]

    unique_columns = {
        tuple(column.name for column in item.columns)
        for item in table.constraints
        if isinstance(item, UniqueConstraint)
    }
    assert ("raw_record_id", "version_number") in unique_columns
    assert ("previous_decision_id",) in unique_columns


def test_explanation_storage_and_postgresql_compilation():
    table = IdentityRegistrationDecision.__table__

    assert table.c.evidence_ciphertext.nullable is False
    assert table.c.encryption_key_version.nullable is False
    assert "evidence_plaintext" not in table.c

    # Compile the complete definition, including cross-schema references.
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert "REFERENCES identity.officer" in ddl
    assert "REFERENCES staging.raw_record" in ddl
    assert "decision_officer_binding" in ddl
    assert "decision_version_chain" in ddl