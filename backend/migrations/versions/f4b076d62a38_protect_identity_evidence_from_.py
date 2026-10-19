"""protect identity evidence from uncontrolled updates

Revision ID: f4b076d62a38
Revises: 4db5f9b38c2b
Create Date: 2026-10-05 08:22:08.905147

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4b076d62a38'
down_revision: Union[str, Sequence[str], None] = '4db5f9b38c2b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


EVIDENCE_TABLES = (
    "source_assertion",
    "source_attestation",
    "officer_address_version",
    "officer_contact_version",
    "officer_demographic_version",
    "officer_family_relation",
    "officer_identifier_version",
    "officer_name_version",
    "officer_physical_profile_version",
    "officer_previous_employment_version",
    "officer_restricted_profile_version",
    "officer_family_civil_event_version",
    "officer_next_of_kin_version",
)


def upgrade() -> None:
    """Protect evidence content and permit one-time version closure."""
    op.execute(
        """
        CREATE FUNCTION identity.guard_evidence_update()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            old_record jsonb;
            new_record jsonb;
            state_column text;
        BEGIN
            old_record := to_jsonb(OLD);
            new_record := to_jsonb(NEW);
            state_column := TG_ARGV[0];

            IF (
                old_record - 'transaction_end' - state_column
            ) IS DISTINCT FROM (
                new_record - 'transaction_end' - state_column
            ) THEN
                RAISE EXCEPTION
                    'Evidence content cannot be overwritten; insert a new version.';
            END IF;

            IF OLD.transaction_end IS NOT NULL THEN
                RAISE EXCEPTION
                    'A closed evidence version cannot be changed.';
            END IF;

            IF NEW.transaction_end IS NULL
               OR NEW.transaction_end <= OLD.transaction_start THEN
                RAISE EXCEPTION
                    'Version closure requires a valid transaction_end.';
            END IF;

            IF new_record ->> state_column
               NOT IN ('SUPERSEDED', 'WITHDRAWN') THEN
                RAISE EXCEPTION
                    'Version closure requires a terminal evidence state.';
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )

    for table_name in EVIDENCE_TABLES:
        state_column = (
            "assertion_state"
            if table_name == "source_assertion"
            else "record_state"
        )

        op.execute(
            f"""
            REVOKE UPDATE
            ON TABLE identity.{table_name}
            FROM police_identity_app
            """
        )

        op.execute(
            f"""
            GRANT UPDATE (transaction_end, {state_column})
            ON TABLE identity.{table_name}
            TO police_identity_app
            """
        )

        op.execute(
            f"""
            CREATE TRIGGER guard_evidence_update
            BEFORE UPDATE ON identity.{table_name}
            FOR EACH ROW
            EXECUTE FUNCTION identity.guard_evidence_update(
                '{state_column}'
            )
            """
        )


def downgrade() -> None:
    """Restore the preceding application permissions."""
    for table_name in reversed(EVIDENCE_TABLES):
        state_column = (
            "assertion_state"
            if table_name == "source_assertion"
            else "record_state"
        )

        op.execute(
            f"""
            DROP TRIGGER guard_evidence_update
            ON identity.{table_name}
            """
        )

        op.execute(
            f"""
            REVOKE UPDATE (transaction_end, {state_column})
            ON TABLE identity.{table_name}
            FROM police_identity_app
            """
        )

        op.execute(
            f"""
            GRANT UPDATE
            ON TABLE identity.{table_name}
            TO police_identity_app
            """
        )

    op.execute(
        "DROP FUNCTION identity.guard_evidence_update()"
    )