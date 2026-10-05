from app.db.base import Base
from app.models import (
    Officer,
    OfficerContactVersion,
    OfficerIdentifierVersion,
    OfficerPhysicalProfileVersion,
    OfficerRestrictedProfileVersion,
    SourceAssertion,
)

EXPECTED_TABLES = {
    "identity.officer",
    "identity.officer_address_version",
    "identity.officer_contact_version",
    "identity.officer_demographic_version",
    "identity.officer_family_civil_event_version",
    "identity.officer_family_relation",
    "identity.officer_identifier_version",
    "identity.officer_name_version",
    "identity.officer_next_of_kin_version",
    "identity.officer_physical_profile_version",
    "identity.officer_previous_employment_version",
    "identity.officer_restricted_profile_version",
    "identity.source_assertion",
    "identity.source_attestation",
    "identity.source_system",
}

VERSIONED_TABLES = {
    "identity.officer_address_version",
    "identity.officer_contact_version",
    "identity.officer_demographic_version",
    "identity.officer_family_civil_event_version",
    "identity.officer_family_relation",
    "identity.officer_identifier_version",
    "identity.officer_name_version",
    "identity.officer_next_of_kin_version",
    "identity.officer_physical_profile_version",
    "identity.officer_previous_employment_version",
    "identity.officer_restricted_profile_version",
    "identity.source_attestation",
}


def test_expected_identity_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_all_tables_use_identity_schema() -> None:
    for table in Base.metadata.tables.values():
        assert table.schema == "identity"


def test_all_foreign_key_targets_resolve() -> None:
    for table in Base.metadata.sorted_tables:
        for foreign_key in table.foreign_keys:
            target_column = foreign_key.column

            assert target_column.table.fullname in EXPECTED_TABLES


def test_officer_table_contains_only_stable_registry_fields() -> None:
    officer_columns = set(Officer.__table__.c.keys())

    forbidden_operational_columns = {
        "current_rank",
        "current_station",
        "current_unit",
        "current_police_number",
        "current_service_status",
    }

    assert officer_columns.isdisjoint(forbidden_operational_columns)


def test_identifier_values_are_not_plaintext_columns() -> None:
    columns = set(OfficerIdentifierVersion.__table__.c.keys())

    assert "identifier_value" not in columns
    assert "identifier_value_ciphertext" in columns
    assert "identifier_lookup_hmac" in columns
    assert "encryption_key_version" in columns
    assert "lookup_key_version" in columns


def test_contact_values_are_not_plaintext_columns() -> None:
    columns = set(OfficerContactVersion.__table__.c.keys())

    assert "contact_value" not in columns
    assert "contact_value_ciphertext" in columns
    assert "contact_lookup_hmac" in columns
    assert "encryption_key_version" in columns
    assert "lookup_key_version" in columns


def test_blood_group_is_in_restricted_profile_only() -> None:
    physical_columns = set(OfficerPhysicalProfileVersion.__table__.c.keys())
    restricted_columns = set(OfficerRestrictedProfileVersion.__table__.c.keys())

    assert "blood_group_code" not in physical_columns
    assert "blood_group_code" in restricted_columns


def test_versioned_tables_have_version_and_transaction_fields() -> None:
    required_columns = {
        "version_number",
        "transaction_start",
        "transaction_end",
        "record_state",
    }

    for table_name in VERSIONED_TABLES:
        columns = set(Base.metadata.tables[table_name].c.keys())

        assert required_columns.issubset(columns), table_name


def test_civil_event_uses_event_date_as_valid_time() -> None:
    table = Base.metadata.tables[
        "identity.officer_family_civil_event_version"
    ]

    assert "event_date" in table.c
    assert "transaction_start" in table.c
    assert "transaction_end" in table.c


def test_source_assertion_has_required_provenance_fields() -> None:
    columns = set(SourceAssertion.__table__.c.keys())

    required_columns = {
        "intake_batch_id",
        "import_file_id",
        "raw_record_id",
        "source_file_name",
        "source_file_sha256",
        "source_row_number",
        "source_system_id",
        "transaction_start",
    }

    assert required_columns.issubset(columns)


def test_source_assertion_has_protected_payload_and_constraints() -> None:
    table = SourceAssertion.__table__

    assert "asserted_value" not in table.c
    assert "asserted_value_ciphertext" in table.c
    assert "encryption_key_version" in table.c

    assert table.c.asserted_value_ciphertext.nullable is False
    assert table.c.encryption_key_version.nullable is False

    constraint_names = {
        constraint.name
        for constraint in table.constraints
        if constraint.name is not None
    }

    required_suffixes = {
        "source_assertion_valid_sha256",
        "source_assertion_has_ciphertext",
        "source_assertion_encryption_key_version",
        "source_assertion_provenance_ids",
    }

    for suffix in required_suffixes:
        assert any(
            name.endswith(suffix)
            for name in constraint_names
        ), suffix

    assert not any(
        name.endswith("source_assertion_value_object")
        or name.endswith("source_assertion_value_not_empty")
        for name in constraint_names
    )
