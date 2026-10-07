"""Add immutable historical delivery preparations and completion receipts.

Revision ID: b84d2f06ac39
Revises: f73a0c94de21
"""
from alembic import op

revision = "b84d2f06ac39"
down_revision = "f73a0c94de21"
branch_labels = None
depends_on = None

# Frozen DDL: future ORM changes must not alter this migration's meaning.
TABLE_DDL = ('CREATE TABLE staging.history_delivery_preparation (\n'
 '\tdelivery_id UUID NOT NULL, \n'
 '\traw_record_id VARCHAR(64) NOT NULL, \n'
 '\tofficer_uid UUID NOT NULL, \n'
 '\tsource_assertion_id UUID NOT NULL, \n'
 '\tidentifier_version_id UUID NOT NULL, \n'
 '\tconfirmation_sha256 VARCHAR(64) NOT NULL, \n'
 '\tcode_revision VARCHAR(40) NOT NULL, \n'
 '\tsource_file_name VARCHAR(100) NOT NULL, \n'
 '\tmongo_collection VARCHAR(50) NOT NULL, \n'
 '\tfield_review_count INTEGER NOT NULL, \n'
 '\treview_state VARCHAR(30) NOT NULL, \n'
 '\twriter_policy VARCHAR(50) NOT NULL, \n'
 '\tlinkage_method VARCHAR(50) NOT NULL, \n'
 '\thistorical_eligibility VARCHAR(20) NOT NULL, \n'
 '\tdocument_bson BYTEA NOT NULL, \n'
 '\tdocument_sha256 VARCHAR(64) NOT NULL, \n'
 '\trecorded_at TIMESTAMP WITH TIME ZONE NOT NULL, \n'
 '\tCONSTRAINT pk_history_delivery_preparation PRIMARY KEY (delivery_id), \n'
 '\tCONSTRAINT uq_history_preparation_source_policy UNIQUE (raw_record_id, writer_policy), \n'
 '\tCONSTRAINT uq_history_preparation_assertion UNIQUE (source_assertion_id), \n'
 '\tCONSTRAINT uq_history_preparation_digest UNIQUE (delivery_id, document_sha256), \n'
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_raw CHECK (raw_record_id ~ '
 "'^[0-9a-f]{64}$'), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_con_f1cf CHECK '
 "(confirmation_sha256 ~ '^[0-9a-f]{64}$'), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_revision CHECK (code_revision ~ '
 "'^[0-9a-f]{40}$'), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_routing CHECK '
 "((source_file_name = 'transfer_history.csv' AND mongo_collection = 'transfer_events' AND "
 "writer_policy = 'PF_TRANSFER_EVIDENCE_V1') OR (source_file_name = 'promotion_history.csv' AND "
 "mongo_collection = 'promotion_events' AND writer_policy = 'PF_PROMOTION_EVIDENCE_V1')), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_rev_1ede CHECK '
 "(field_review_count BETWEEN 0 AND 35 AND (source_file_name <> 'promotion_history.csv' OR "
 'field_review_count <= 21)), \n'
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_rev_0e19 CHECK '
 "((field_review_count = 0 AND review_state = 'NO_FIELD_REVIEW') OR (field_review_count > 0 AND "
 "review_state = 'FIELD_REVIEW_REQUIRED')), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_linkage CHECK (linkage_method = '
 "'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH' AND historical_eligibility = 'UNASSESSED'), \n"
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_size CHECK '
 '(octet_length(document_bson) BETWEEN 29 AND 12582912), \n'
 '\tCONSTRAINT ck_history_delivery_preparation_history_preparation_digest CHECK (document_sha256 = '
 "encode(sha256(document_bson), 'hex')), \n"
 '\tCONSTRAINT fk_history_preparation_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record '
 '(raw_record_id) ON DELETE RESTRICT, \n'
 '\tCONSTRAINT fk_history_preparation_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer '
 '(officer_uid) ON DELETE RESTRICT, \n'
 '\tCONSTRAINT fk_history_preparation_assertion FOREIGN KEY(source_assertion_id) REFERENCES '
 'identity.source_assertion (source_assertion_id) ON DELETE RESTRICT, \n'
 '\tCONSTRAINT fk_history_preparation_identifier FOREIGN KEY(identifier_version_id) REFERENCES '
 'identity.officer_identifier_version (identifier_version_id) ON DELETE RESTRICT\n'
 ')',
 'CREATE TABLE staging.history_delivery_completion (\n'
 '\tdelivery_id UUID NOT NULL, \n'
 '\tdocument_sha256 VARCHAR(64) NOT NULL, \n'
 '\trecorded_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL, \n'
 '\tCONSTRAINT pk_history_delivery_completion PRIMARY KEY (delivery_id), \n'
 '\tCONSTRAINT fk_history_completion_prepared_digest FOREIGN KEY(delivery_id, document_sha256) '
 'REFERENCES staging.history_delivery_preparation (delivery_id, document_sha256) ON DELETE '
 'RESTRICT\n'
 ')')


def upgrade():
    for ddl in TABLE_DDL:
        op.execute(ddl)
    op.execute("""CREATE FUNCTION identity.guard_history_preparation_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM staging.raw_record r
            JOIN identity.source_assertion a ON a.source_assertion_id = NEW.source_assertion_id
            JOIN identity.source_system s ON s.source_system_id = a.source_system_id
            JOIN identity.officer o ON o.officer_uid = NEW.officer_uid
            JOIN identity.officer_identifier_version i ON i.identifier_version_id = NEW.identifier_version_id
            JOIN identity.source_assertion ia ON ia.source_assertion_id = i.source_assertion_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND regexp_replace(r.archive_path, '^.*/', '') = NEW.source_file_name
              AND a.officer_uid = NEW.officer_uid AND a.raw_record_id = r.raw_record_id
              AND a.intake_batch_id = r.batch_id AND a.import_file_id = r.import_file_id::text
              AND a.source_file_name = NEW.source_file_name
              AND a.source_file_sha256 = r.source_file_sha256 AND a.source_row_number = r.source_row_number
              AND a.assertion_type = CASE NEW.source_file_name
                  WHEN 'transfer_history.csv' THEN 'PF_TRANSFER_EVIDENCE'
                  WHEN 'promotion_history.csv' THEN 'PF_PROMOTION_EVIDENCE' ELSE NULL END
              AND a.assertion_state = 'ACTIVE' AND a.transaction_end IS NULL
              AND a.valid_from IS NULL AND a.valid_to IS NULL
              AND a.source_recorded_at IS NULL AND a.captured_at IS NULL
              AND a.source_record_id IS NULL AND a.source_document_id IS NULL AND a.source_page IS NULL
              AND a.independence_status = 'UNVERIFIED' AND a.transaction_start = NEW.recorded_at
              AND s.source_system_code = 'PF_REGISTRY' AND s.is_active
              AND o.registry_state = 'REGISTERED'
              AND i.officer_uid = NEW.officer_uid AND i.identifier_type = 'NIC'
              AND i.record_state IN ('ASSERTED', 'ACCEPTED') AND i.transaction_end IS NULL
              AND ia.officer_uid = NEW.officer_uid AND ia.assertion_type = 'IDENTIFIER_NIC'
              AND ia.assertion_state = 'ACTIVE' AND ia.transaction_end IS NULL
        ) THEN
            RAISE EXCEPTION 'Historical preparation provenance does not match usable source evidence.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_history_preparation_insert BEFORE INSERT
        ON staging.history_delivery_preparation FOR EACH ROW
        EXECUTE FUNCTION identity.guard_history_preparation_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_history_completion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.history_delivery_preparation p
            WHERE p.delivery_id = NEW.delivery_id AND p.document_sha256 = NEW.document_sha256
              AND NEW.recorded_at >= p.recorded_at) THEN
            RAISE EXCEPTION 'Historical completion must follow and match its preparation.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_history_completion_insert BEFORE INSERT
        ON staging.history_delivery_completion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_history_completion_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_history_delivery_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Historical delivery evidence is append-only.';
        RETURN NULL; END; $$""")
    for table in ("history_delivery_preparation", "history_delivery_completion"):
        # Defense in depth: role ACLs reject ordinary mutations; triggers also
        # reject accidental UPDATE/DELETE/TRUNCATE by privileged maintenance code.
        op.execute(f"CREATE TRIGGER protect_history_rows BEFORE UPDATE OR DELETE ON staging.{table} FOR EACH ROW EXECUTE FUNCTION identity.reject_history_delivery_mutation()")
        op.execute(f"CREATE TRIGGER protect_history_truncate BEFORE TRUNCATE ON staging.{table} FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_history_delivery_mutation()")
        op.execute(f"REVOKE ALL ON TABLE staging.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE staging.{table} FROM police_identity_app")
        op.execute(f"GRANT SELECT, INSERT ON TABLE staging.{table} TO police_identity_app")


def downgrade():
    # Even an empty foundation should not provide a reusable evidence-deletion path.
    raise RuntimeError("No automatic downgrade: preserve history evidence and use a reviewed recovery migration.")
