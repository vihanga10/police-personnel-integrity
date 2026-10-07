"""Encrypt empty normalized profile destinations and add immutable receipts.

Revision ID: e62c9a01bd47
Revises: c91a4b7e2036
"""
from alembic import op
import sqlalchemy as sa

revision = "e62c9a01bd47"
down_revision = "c91a4b7e2036"
branch_labels = None
depends_on = None

SPEC = {'officer_address_version': {'columns': ['address_text', 'local_station_reference'], 'checks': ['ck_officer_address_version_officer_address_has_value']}, 'officer_demographic_version': {'columns': ['date_of_birth', 'place_of_birth', 'nationality_code', 'religion_code', 'gender_code', 'marital_status_code'], 'checks': ['ck_officer_demographic_version_officer_demographic_has_value']}, 'officer_family_relation': {'columns': ['related_person_name', 'related_person_gender_code', 'related_person_date_of_birth', 'related_person_place_of_birth', 'related_person_address'], 'checks': ['ck_officer_family_relation_officer_family_related_person_name']}, 'officer_physical_profile_version': {'columns': ['height_cm', 'chest_cm', 'measured_at'], 'checks': ['ck_officer_physical_profile_version_officer_physical_profile_has_value', 'ck_officer_physical_profile_version_officer_physical_profile_positive_height', 'ck_officer_physical_profile_version_officer_physical_profile_positive_chest']}, 'officer_previous_employment_version': {'columns': ['employer_department_name'], 'checks': ['ck_officer_previous_employment_version_officer_previous_employment_has_department']}, 'officer_restricted_profile_version': {'columns': ['blood_group_code', 'identifying_marks_ciphertext', 'medical_officer_remark_ciphertext', 'encryption_key_version'], 'checks': ['ck_officer_restricted_profile_version_officer_restricted_profile_has_value', 'ck_officer_restricted_profile_version_officer_restricted_profile_identifying_marks', 'ck_officer_restricted_profile_version_officer_restricted_profile_medical_remark', 'ck_officer_restricted_profile_version_officer_restricted_profile_encryption_key']}}


def upgrade():
    tables = sorted(SPEC)
    op.execute("LOCK TABLE " + ", ".join("identity." + t for t in tables) + " IN ACCESS EXCLUSIVE MODE")
    for table in tables:
        op.execute(f"""DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM identity.{table}) THEN
                RAISE EXCEPTION 'Encrypted profile conversion requires empty target tables.';
            END IF;
        END; $$""")
    for table, spec in SPEC.items():
        for name in spec["checks"]:
            op.drop_constraint(op.f(name), table, schema="identity", type_="check")
        for column in spec["columns"]:
            op.drop_column(table, column, schema="identity")
        op.add_column(table, sa.Column("profile_payload_ciphertext", sa.LargeBinary(), nullable=False), schema="identity")
        op.add_column(table, sa.Column("encryption_key_version", sa.String(50), nullable=False), schema="identity")
        for suffix, rule in (
            ("profile_payload_present", "octet_length(profile_payload_ciphertext) > 28"),
            ("profile_key_present", "length(trim(encryption_key_version)) > 0"),
            ("profile_dates_protected", "valid_from IS NULL AND valid_to IS NULL"),
        ):
            op.create_check_constraint(op.f("ck_" + table + "_" + suffix), table, rule, schema="identity")
    op.execute("""
        CREATE TABLE staging.profile_transform_receipt (
            raw_record_id varchar(64) NOT NULL,
            officer_uid uuid NOT NULL,
            identity_decision_id uuid NOT NULL,
            source_assertion_id uuid NOT NULL,
            confirmation_sha256 varchar(64) NOT NULL,
            policy_version varchar(50) NOT NULL,
            code_revision varchar(40) NOT NULL,
            evidence_ciphertext bytea NOT NULL,
            encryption_key_version varchar(50) NOT NULL,
            recorded_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT pk_profile_transform_receipt PRIMARY KEY (raw_record_id),
            CONSTRAINT fk_profile_receipt_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record(raw_record_id) ON DELETE RESTRICT,
            CONSTRAINT fk_profile_receipt_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer(officer_uid) ON DELETE RESTRICT,
            CONSTRAINT fk_profile_receipt_decision FOREIGN KEY(identity_decision_id) REFERENCES staging.identity_registration_decision(decision_id) ON DELETE RESTRICT,
            CONSTRAINT fk_profile_receipt_assertion FOREIGN KEY(source_assertion_id) REFERENCES identity.source_assertion(source_assertion_id) ON DELETE RESTRICT,
            CONSTRAINT uq_profile_receipt_assertion UNIQUE(source_assertion_id),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_raw_id CHECK(raw_record_id ~ '^[0-9a-f]{64}$'),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_confirmation CHECK(confirmation_sha256 ~ '^[0-9a-f]{64}$'),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_revision CHECK(code_revision ~ '^[0-9a-f]{40}$'),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_evidence CHECK(octet_length(evidence_ciphertext) > 28),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_key CHECK(length(trim(encryption_key_version)) > 0),
            CONSTRAINT ck_profile_transform_receipt_profile_receipt_policy CHECK(length(trim(policy_version)) > 0)
        )
    """)
    op.execute("""CREATE FUNCTION identity.guard_profile_receipt_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM staging.identity_registration_decision d
            JOIN identity.source_assertion a ON a.source_assertion_id = NEW.source_assertion_id
            JOIN staging.raw_record r ON r.raw_record_id = NEW.raw_record_id
            WHERE d.decision_id = NEW.identity_decision_id
              AND d.raw_record_id = NEW.raw_record_id AND d.officer_uid = NEW.officer_uid
              AND d.outcome IN ('CREATED', 'MATCHED')
              AND d.source_confirmation_sha256 = NEW.confirmation_sha256
              AND a.officer_uid = NEW.officer_uid AND a.raw_record_id = NEW.raw_record_id
              AND a.source_system_id = d.source_system_id
              AND a.assertion_type = 'PF_PERSONAL_PROFILE'
              AND a.intake_batch_id = r.batch_id
              AND a.import_file_id = r.import_file_id::text
              AND a.source_file_sha256 = r.source_file_sha256
              AND a.source_row_number = r.source_row_number
        ) THEN
            RAISE EXCEPTION 'Profile receipt provenance does not match registered evidence.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_profile_receipt_insert BEFORE INSERT
        ON staging.profile_transform_receipt FOR EACH ROW
        EXECUTE FUNCTION identity.guard_profile_receipt_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_profile_receipt_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Profile receipts are append-only.';
        RETURN NULL; END; $$""")
    op.execute("""CREATE TRIGGER protect_profile_receipt_rows BEFORE UPDATE OR DELETE
        ON staging.profile_transform_receipt FOR EACH ROW
        EXECUTE FUNCTION identity.reject_profile_receipt_mutation()""")
    op.execute("""CREATE TRIGGER protect_profile_receipt_truncate BEFORE TRUNCATE
        ON staging.profile_transform_receipt FOR EACH STATEMENT
        EXECUTE FUNCTION identity.reject_profile_receipt_mutation()""")
    op.execute("REVOKE ALL ON TABLE staging.profile_transform_receipt FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE staging.profile_transform_receipt FROM police_identity_app")
    op.execute("GRANT SELECT, INSERT ON TABLE staging.profile_transform_receipt TO police_identity_app")


def downgrade():
    raise RuntimeError("No automatic downgrade: preserve protected data and use a reviewed recovery migration.")
