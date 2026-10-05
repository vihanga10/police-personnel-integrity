"""protect source assertion payload

Revision ID: 4db5f9b38c2b
Revises: bd872fe5ccc0
Create Date: 2026-10-05 07:47:43.304703

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4db5f9b38c2b'
down_revision: Union[str, Sequence[str], None] = 'bd872fe5ccc0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _require_empty_assertion_table() -> None:
    """Prevent column replacement when evidence exists."""
    op.execute(
        """
        LOCK TABLE identity.source_assertion
        IN ACCESS EXCLUSIVE MODE
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM identity.source_assertion
            ) THEN
                RAISE EXCEPTION
                    'Migration requires an empty source_assertion table; '
                    'existing evidence needs an explicit conversion.';
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    """Replace plaintext assertion storage on an empty table."""
    _require_empty_assertion_table()

    op.drop_constraint(
        op.f("ck_source_assertion_source_assertion_value_object"),
        "source_assertion",
        schema="identity",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_source_assertion_source_assertion_value_not_empty"),
        "source_assertion",
        schema="identity",
        type_="check",
    )

    op.add_column(
        "source_assertion",
        sa.Column(
            "asserted_value_ciphertext",
            sa.LargeBinary(),
            nullable=False,
        ),
        schema="identity",
    )
    op.add_column(
        "source_assertion",
        sa.Column(
            "encryption_key_version",
            sa.String(length=50),
            nullable=False,
        ),
        schema="identity",
    )

    op.create_check_constraint(
        op.f("ck_source_assertion_source_assertion_has_ciphertext"),
        "source_assertion",
        "octet_length(asserted_value_ciphertext) > 0",
        schema="identity",
    )
    op.create_check_constraint(
        op.f("ck_source_assertion_source_assertion_encryption_key_version"),
        "source_assertion",
        "length(trim(encryption_key_version)) > 0",
        schema="identity",
    )

    op.drop_column(
        "source_assertion",
        "asserted_value",
        schema="identity",
    )


def downgrade() -> None:
    """Restore the previous structure only when no evidence exists."""
    _require_empty_assertion_table()

    op.drop_constraint(
        op.f("ck_source_assertion_source_assertion_has_ciphertext"),
        "source_assertion",
        schema="identity",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_source_assertion_source_assertion_encryption_key_version"),
        "source_assertion",
        schema="identity",
        type_="check",
    )

    op.add_column(
        "source_assertion",
        sa.Column(
            "asserted_value",
            postgresql.JSONB(),
            nullable=False,
        ),
        schema="identity",
    )

    op.create_check_constraint(
        op.f("ck_source_assertion_source_assertion_value_object"),
        "source_assertion",
        "jsonb_typeof(asserted_value) = 'object'",
        schema="identity",
    )
    op.create_check_constraint(
        op.f("ck_source_assertion_source_assertion_value_not_empty"),
        "source_assertion",
        "asserted_value <> '{}'::jsonb",
        schema="identity",
    )

    op.drop_column(
        "source_assertion",
        "encryption_key_version",
        schema="identity",
    )
    op.drop_column(
        "source_assertion",
        "asserted_value_ciphertext",
        schema="identity",
    )