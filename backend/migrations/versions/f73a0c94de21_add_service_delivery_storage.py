"""Add immutable service delivery preparation and completion storage.

Revision ID: f73a0c94de21
Revises: e62c9a01bd47
"""
from alembic import op

revision = "f73a0c94de21"
down_revision = "e62c9a01bd47"
branch_labels = None
depends_on = None

# The table DDL below is a frozen migration snapshot, not a live model import.
TABLE_DDL = (
    """CREATE TABLE staging.service_delivery_preparation (
	delivery_id UUID NOT NULL,
	raw_record_id VARCHAR(64) NOT NULL,
	officer_uid UUID NOT NULL,
	source_assertion_id UUID NOT NULL,
	identifier_version_id UUID NOT NULL,
	confirmation_sha256 VARCHAR(64) NOT NULL,
	code_revision VARCHAR(40) NOT NULL,
	writer_policy VARCHAR(50) NOT NULL,
	linkage_method VARCHAR(50) NOT NULL,
	historical_eligibility VARCHAR(20) NOT NULL,
	document_bson BYTEA NOT NULL,
	document_sha256 VARCHAR(64) NOT NULL,
	recorded_at TIMESTAMP WITH TIME ZONE NOT NULL,
	CONSTRAINT pk_service_delivery_preparation PRIMARY KEY (delivery_id),
	CONSTRAINT uq_service_preparation_source_policy UNIQUE (raw_record_id, writer_policy),
	CONSTRAINT uq_service_preparation_assertion UNIQUE (source_assertion_id),
	CONSTRAINT uq_service_preparation_digest UNIQUE (delivery_id, document_sha256),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_raw CHECK (raw_record_id ~ '^[0-9a-f]{64}$'),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_con_9ab8 CHECK (confirmation_sha256 ~ '^[0-9a-f]{64}$'),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_revision CHECK (code_revision ~ '^[0-9a-f]{40}$'),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_policy CHECK (writer_policy = 'HR_SERVICE_EVIDENCE_V1'),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_linkage CHECK (linkage_method = 'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH' AND historical_eligibility = 'UNASSESSED'),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_size CHECK (octet_length(document_bson) BETWEEN 29 AND 12582912),
	CONSTRAINT ck_service_delivery_preparation_service_preparation_digest CHECK (document_sha256 = encode(sha256(document_bson), 'hex')),
	CONSTRAINT fk_service_preparation_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record (raw_record_id) ON DELETE RESTRICT,
	CONSTRAINT fk_service_preparation_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer (officer_uid) ON DELETE RESTRICT,
	CONSTRAINT fk_service_preparation_assertion FOREIGN KEY(source_assertion_id) REFERENCES identity.source_assertion (source_assertion_id) ON DELETE RESTRICT,
	CONSTRAINT fk_service_preparation_identifier FOREIGN KEY(identifier_version_id) REFERENCES identity.officer_identifier_version (identifier_version_id) ON DELETE RESTRICT
)""",
    """CREATE TABLE staging.service_delivery_completion (
	delivery_id UUID NOT NULL,
	document_sha256 VARCHAR(64) NOT NULL,
	recorded_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT pk_service_delivery_completion PRIMARY KEY (delivery_id),
	CONSTRAINT fk_service_completion_prepared_digest FOREIGN KEY(delivery_id, document_sha256) REFERENCES staging.service_delivery_preparation (delivery_id, document_sha256) ON DELETE RESTRICT
)""",
)


def upgrade():
    for ddl in TABLE_DDL:
        op.execute(ddl)
    op.execute("""CREATE FUNCTION identity.guard_service_preparation_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM staging.raw_record r
            JOIN identity.source_assertion a ON a.source_assertion_id = NEW.source_assertion_id
            JOIN identity.source_system s ON s.source_system_id = a.source_system_id
            JOIN identity.officer o ON o.officer_uid = NEW.officer_uid
            JOIN identity.officer_identifier_version i ON i.identifier_version_id = NEW.identifier_version_id
            JOIN identity.source_assertion ia ON ia.source_assertion_id = i.source_assertion_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND regexp_replace(r.archive_path, '^.*/', '') = 'officer_service_information.csv'
              AND a.officer_uid = NEW.officer_uid AND a.raw_record_id = r.raw_record_id
              AND a.intake_batch_id = r.batch_id AND a.import_file_id = r.import_file_id::text
              AND a.source_file_name = 'officer_service_information.csv'
              AND a.source_file_sha256 = r.source_file_sha256 AND a.source_row_number = r.source_row_number
              AND a.assertion_type = 'HR_SERVICE_EVIDENCE'
              AND a.assertion_state = 'ACTIVE' AND a.transaction_end IS NULL
              AND a.valid_from IS NULL AND a.valid_to IS NULL
              AND a.source_recorded_at IS NULL AND a.captured_at IS NULL
              AND a.source_record_id IS NULL AND a.source_document_id IS NULL AND a.source_page IS NULL
              AND a.independence_status = 'UNVERIFIED' AND a.transaction_start = NEW.recorded_at
              AND s.source_system_code = 'POLICE_HR_IS' AND s.is_active
              AND o.registry_state = 'REGISTERED'
              AND i.officer_uid = NEW.officer_uid AND i.identifier_type = 'NIC'
              AND i.record_state IN ('ASSERTED', 'ACCEPTED') AND i.transaction_end IS NULL
              AND ia.officer_uid = NEW.officer_uid AND ia.assertion_type = 'IDENTIFIER_NIC'
              AND ia.assertion_state = 'ACTIVE' AND ia.transaction_end IS NULL
        ) THEN
            RAISE EXCEPTION 'Service preparation provenance does not match usable source evidence.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_service_preparation_insert BEFORE INSERT
        ON staging.service_delivery_preparation FOR EACH ROW
        EXECUTE FUNCTION identity.guard_service_preparation_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_service_completion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.service_delivery_preparation p
            WHERE p.delivery_id = NEW.delivery_id AND p.document_sha256 = NEW.document_sha256
              AND NEW.recorded_at >= p.recorded_at) THEN
            RAISE EXCEPTION 'Service completion must follow and match its preparation.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_service_completion_insert BEFORE INSERT
        ON staging.service_delivery_completion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_service_completion_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_service_delivery_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Service delivery evidence is append-only.';
        RETURN NULL; END; $$""")
    for table in ("service_delivery_preparation", "service_delivery_completion"):
        # Defense in depth: role ACLs reject ordinary mutations; triggers also
        # reject accidental UPDATE/DELETE/TRUNCATE by privileged maintenance code.
        op.execute(f"CREATE TRIGGER protect_service_rows BEFORE UPDATE OR DELETE ON staging.{table} FOR EACH ROW EXECUTE FUNCTION identity.reject_service_delivery_mutation()")
        op.execute(f"CREATE TRIGGER protect_service_truncate BEFORE TRUNCATE ON staging.{table} FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_service_delivery_mutation()")
        op.execute(f"REVOKE ALL ON TABLE staging.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE staging.{table} FROM police_identity_app")
        op.execute(f"GRANT SELECT, INSERT ON TABLE staging.{table} TO police_identity_app")


def downgrade():
    # Even an empty foundation should not provide a reusable evidence-deletion path.
    raise RuntimeError("No automatic downgrade: preserve service evidence and use a reviewed recovery migration.")
