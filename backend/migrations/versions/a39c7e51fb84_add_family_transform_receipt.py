"""Add append-only HR family transformation receipts; no family import.

Revision ID: a39c7e51fb84
Revises: f28b6d40ea73
"""
from alembic import op

revision = "a39c7e51fb84"
down_revision = "f28b6d40ea73"
branch_labels = None
depends_on = None


def upgrade():
    # Frozen DDL does not depend on future model changes.
    op.execute("""CREATE TABLE staging.family_transform_receipt (
        raw_record_id varchar(64) PRIMARY KEY,
        officer_uid uuid NOT NULL,
        identifier_version_id uuid NOT NULL,
        source_assertion_id uuid NOT NULL,
        confirmation_sha256 varchar(64) NOT NULL,
        code_revision varchar(40) NOT NULL,
        policy_version varchar(50) NOT NULL,
        evidence_ciphertext bytea NOT NULL,
        encryption_key_version varchar(50) NOT NULL,
        recorded_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT fk_family_receipt_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record(raw_record_id) ON DELETE RESTRICT,
        CONSTRAINT fk_family_receipt_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer(officer_uid) ON DELETE RESTRICT,
        CONSTRAINT fk_family_receipt_identifier FOREIGN KEY(identifier_version_id) REFERENCES identity.officer_identifier_version(identifier_version_id) ON DELETE RESTRICT,
        CONSTRAINT fk_family_receipt_assertion FOREIGN KEY(source_assertion_id) REFERENCES identity.source_assertion(source_assertion_id) ON DELETE RESTRICT,
        CONSTRAINT uq_family_receipt_assertion UNIQUE(source_assertion_id),
        CONSTRAINT ck_family_transform_receipt_family_receipt_raw CHECK(raw_record_id ~ '^[0-9a-f]{64}$'),
        CONSTRAINT ck_family_transform_receipt_family_receipt_confirmation CHECK(confirmation_sha256 ~ '^[0-9a-f]{64}$'),
        CONSTRAINT ck_family_transform_receipt_family_receipt_revision CHECK(code_revision ~ '^[0-9a-f]{40}$'),
        CONSTRAINT ck_family_transform_receipt_family_receipt_policy CHECK(policy_version = 'HR_FAMILY_WRITER_V1'),
        CONSTRAINT ck_family_transform_receipt_family_receipt_cipher CHECK(octet_length(evidence_ciphertext) > 28),
        CONSTRAINT ck_family_transform_receipt_family_receipt_key CHECK(length(trim(encryption_key_version)) > 0)
    )""")
    op.execute("""CREATE FUNCTION identity.guard_family_receipt_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM identity.source_assertion a
          JOIN staging.raw_record r ON r.raw_record_id = NEW.raw_record_id
          JOIN identity.source_system s ON s.source_system_id = a.source_system_id
          JOIN identity.officer_identifier_version i ON i.identifier_version_id = NEW.identifier_version_id
          WHERE a.source_assertion_id = NEW.source_assertion_id
            AND a.officer_uid = NEW.officer_uid AND i.officer_uid = NEW.officer_uid
            AND i.identifier_type = 'NIC'
            AND a.assertion_type = 'HR_FAMILY_EVIDENCE' AND s.source_system_code = 'POLICE_HR_IS'
            AND a.assertion_state = 'ACTIVE' AND a.transaction_end IS NULL
            AND a.raw_record_id = r.raw_record_id AND a.intake_batch_id = r.batch_id
            AND a.import_file_id = r.import_file_id::text
            AND a.source_file_sha256 = r.source_file_sha256 AND a.source_row_number = r.source_row_number
            AND a.source_file_name = 'officer_family_details.csv'
            AND r.archive_path ~ '(^|/)officer_family_details[.]csv$'
        ) THEN RAISE EXCEPTION 'Family receipt provenance differs.'; END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_family_receipt_insert BEFORE INSERT
        ON staging.family_transform_receipt FOR EACH ROW EXECUTE FUNCTION identity.guard_family_receipt_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_family_receipt_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Family receipts are append-only.'; RETURN NULL; END; $$""")
    op.execute("""CREATE TRIGGER protect_family_receipt_rows BEFORE UPDATE OR DELETE
        ON staging.family_transform_receipt FOR EACH ROW EXECUTE FUNCTION identity.reject_family_receipt_mutation()""")
    op.execute("""CREATE TRIGGER protect_family_receipt_truncate BEFORE TRUNCATE
        ON staging.family_transform_receipt FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_family_receipt_mutation()""")
    op.execute("REVOKE ALL ON staging.family_transform_receipt FROM PUBLIC, police_identity_app")
    op.execute("GRANT SELECT, INSERT ON staging.family_transform_receipt TO police_identity_app")


def downgrade():
    raise RuntimeError("No automatic downgrade: preserve family evidence and receipts.")
