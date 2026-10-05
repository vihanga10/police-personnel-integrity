"""validate identity evidence version links

Revision ID: 8757cc30d835
Revises: f4b076d62a38
Create Date: 2026-10-05 11:17:50.816180

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8757cc30d835'
down_revision: Union[str, Sequence[str], None] = 'f4b076d62a38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Table, primary key, previous-version reference, and chain identity fields.
# Some tables identify a chain through officer_uid plus a category.
VERSION_TABLES = (
    (
        "officer_address_version",
        "address_version_id",
        "supersedes_address_version_id",
        "officer_uid,address_type",
    ),
    (
        "officer_contact_version",
        "contact_version_id",
        "supersedes_contact_version_id",
        "officer_uid,contact_chain_uid,contact_type",
    ),
    (
        "officer_demographic_version",
        "demographic_version_id",
        "supersedes_demographic_version_id",
        "officer_uid",
    ),
    (
        "officer_family_relation",
        "family_relation_version_id",
        "supersedes_family_relation_version_id",
        "officer_uid,relation_chain_uid",
    ),
    (
        "officer_identifier_version",
        "identifier_version_id",
        "supersedes_identifier_version_id",
        "officer_uid,identifier_chain_uid,identifier_type",
    ),
    (
        "officer_name_version",
        "name_version_id",
        "supersedes_name_version_id",
        "officer_uid",
    ),
    (
        "officer_physical_profile_version",
        "physical_profile_version_id",
        "supersedes_physical_profile_version_id",
        "officer_uid",
    ),
    (
        "officer_previous_employment_version",
        "employment_version_id",
        "supersedes_employment_version_id",
        "officer_uid,employment_chain_uid",
    ),
    (
        "officer_restricted_profile_version",
        "restricted_profile_version_id",
        "supersedes_restricted_profile_version_id",
        "officer_uid,restricted_profile_chain_uid",
    ),
    (
        "source_attestation",
        "attestation_version_id",
        "supersedes_attestation_version_id",
        "source_assertion_id,attestation_chain_uid",
    ),
    (
        "officer_family_civil_event_version",
        "civil_event_version_id",
        "supersedes_civil_event_version_id",
        "officer_uid,civil_event_chain_uid",
    ),
    (
        "officer_next_of_kin_version",
        "next_of_kin_version_id",
        "supersedes_next_of_kin_version_id",
        "officer_uid,next_of_kin_chain_uid",
    ),
)


def upgrade() -> None:
    """Enforce version links before importing evidence."""

    # This migration targets our empty foundation.
    # Refuse to silently leave existing records unvalidated.
    for table_name, _, _, _ in VERSION_TABLES:
        op.execute(
            f"LOCK TABLE identity.{table_name} "
            "IN ACCESS EXCLUSIVE MODE"
        )
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM identity.{table_name}) THEN
                    RAISE EXCEPTION
                        'Version-link migration requires empty evidence tables; '
                        'existing records need a separate validation plan.';
                END IF;
            END;
            $$;
            """
        )

    op.execute(
        """
        CREATE FUNCTION identity.guard_version_insert()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            new_record jsonb := to_jsonb(NEW);
            previous_record jsonb;
            previous_id uuid;
            field_name text;
            assertion_owner uuid;
        BEGIN
            -- Officer evidence must be supported by that officer's assertion.
            IF new_record ? 'officer_uid' THEN
                SELECT officer_uid
                INTO assertion_owner
                FROM identity.source_assertion
                WHERE source_assertion_id =
                    (new_record ->> 'source_assertion_id')::uuid;

                IF NOT FOUND THEN
                    RAISE EXCEPTION 'Supporting assertion does not exist.';
                END IF;

                IF assertion_owner IS DISTINCT FROM
                    (new_record ->> 'officer_uid')::uuid THEN
                    RAISE EXCEPTION
                        'Supporting assertion belongs to another officer.';
                END IF;
            END IF;

            -- Newly inserted versions begin with an open knowledge period.
            IF NEW.transaction_end IS NOT NULL
               OR NEW.record_state IN ('SUPERSEDED', 'WITHDRAWN') THEN
                RAISE EXCEPTION
                    'Insert an open evidence version, not a closed version.';
            END IF;

            previous_id := (new_record ->> TG_ARGV[1])::uuid;

            -- A new chain begins at version 1.
            IF previous_id IS NULL THEN
                IF NEW.version_number <> 1 THEN
                    RAISE EXCEPTION
                        'First version must be 1 with no predecessor.';
                END IF;
                RETURN NEW;
            END IF;

            -- Prevent a record from pointing to itself.
            IF previous_id = (new_record ->> TG_ARGV[0])::uuid THEN
                RAISE EXCEPTION 'A version cannot supersede itself.';
            END IF;

            -- Lock the predecessor while checking its identity and closure.
            EXECUTE format(
                'SELECT to_jsonb(p) FROM %I.%I AS p '
                'WHERE p.%I = $1 FOR UPDATE',
                TG_TABLE_SCHEMA,
                TG_TABLE_NAME,
                TG_ARGV[0]
            )
            INTO previous_record
            USING previous_id;

            IF previous_record IS NULL THEN
                RAISE EXCEPTION 'Previous version does not exist.';
            END IF;

            -- Every configured chain field must remain unchanged.
            FOREACH field_name IN ARRAY string_to_array(TG_ARGV[2], ',')
            LOOP
                IF (new_record -> field_name) IS DISTINCT FROM
                   (previous_record -> field_name) THEN
                    RAISE EXCEPTION
                        'Previous version belongs to another officer or chain.';
                END IF;
            END LOOP;

            -- Corrections cannot skip or reverse version numbers.
            IF NEW.version_number <>
                (previous_record ->> 'version_number')::integer + 1 THEN
                RAISE EXCEPTION
                    'New version must immediately follow its predecessor.';
            END IF;

            -- Close the previous version and insert its replacement
            -- in the same backend transaction at the same timestamp.
            IF previous_record ->> 'record_state' <> 'SUPERSEDED'
               OR previous_record ->> 'transaction_end' IS NULL THEN
                RAISE EXCEPTION
                    'Previous version must be closed as SUPERSEDED.';
            END IF;

            IF NEW.transaction_start IS DISTINCT FROM
                (previous_record ->> 'transaction_end')::timestamptz THEN
                RAISE EXCEPTION
                    'Replacement must start when its predecessor closes.';
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )

    for table_name, primary_key, previous_column, chain_fields in VERSION_TABLES:
        # Uniqueness also rejects competing replacements under concurrency.
        op.create_index(
            f"uq_{table_name}_predecessor",
            table_name,
            [previous_column],
            unique=True,
            schema="identity",
            postgresql_where=sa.text(f"{previous_column} IS NOT NULL"),
        )

        # Fixed developer-defined names are used here, not user input.
        op.execute(
            f"""
            CREATE TRIGGER guard_version_insert
            BEFORE INSERT ON identity.{table_name}
            FOR EACH ROW
            EXECUTE FUNCTION identity.guard_version_insert(
                '{primary_key}',
                '{previous_column}',
                '{chain_fields}'
            )
            """
        )


def downgrade() -> None:
    """Remove the version-link protections without deleting evidence."""
    for table_name, _, _, _ in reversed(VERSION_TABLES):
        op.execute(
            f"DROP TRIGGER guard_version_insert ON identity.{table_name}"
        )
        op.drop_index(
            f"uq_{table_name}_predecessor",
            table_name=table_name,
            schema="identity",
        )

    op.execute("DROP FUNCTION identity.guard_version_insert()")