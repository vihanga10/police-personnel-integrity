"""Add append-only station reference assertions and delivery receipts.

Revision ID: b40d8f62ac95
Revises: a39c7e51fb84
"""
from alembic import op

revision = 'b40d8f62ac95'
down_revision = 'a39c7e51fb84'
branch_labels = None
depends_on = None

# Frozen DDL is inserted below after compilation against the registered models.
TABLE_DDL = ("CREATE TABLE identity.reference_source_assertion (\n\tsource_assertion_id UUID NOT NULL, \n\tsource_system_id UUID NOT NULL, \n\traw_record_id VARCHAR(64) NOT NULL, \n\tintake_batch_id VARCHAR(100) NOT NULL, \n\timport_file_id VARCHAR(100) NOT NULL, \n\tsource_file_name VARCHAR(100) NOT NULL, \n\tsource_file_sha256 VARCHAR(64) NOT NULL, \n\tsource_row_number INTEGER NOT NULL, \n\tassertion_type VARCHAR(50) NOT NULL, \n\tasserted_value_ciphertext BYTEA NOT NULL, \n\tencryption_key_version VARCHAR(128) NOT NULL, \n\tassertion_state VARCHAR(20) DEFAULT 'ACTIVE' NOT NULL, \n\tindependence_status VARCHAR(20) DEFAULT 'UNVERIFIED' NOT NULL, \n\tclassification VARCHAR(20) DEFAULT 'UNASSESSED' NOT NULL, \n\tvalid_from TIMESTAMP WITH TIME ZONE, \n\tvalid_to TIMESTAMP WITH TIME ZONE, \n\ttransaction_end TIMESTAMP WITH TIME ZONE, \n\tsource_recorded_at TIMESTAMP WITH TIME ZONE, \n\tcaptured_at TIMESTAMP WITH TIME ZONE, \n\tsource_record_id VARCHAR(100), \n\tsource_document_id VARCHAR(100), \n\tsource_page VARCHAR(100), \n\ttransaction_start TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL, \n\tCONSTRAINT pk_reference_source_assertion PRIMARY KEY (source_assertion_id), \n\tCONSTRAINT uq_reference_assertion_source_type UNIQUE (raw_record_id, assertion_type), \n\tCONSTRAINT ck_reference_source_assertion_reference_assertion_type CHECK ((source_file_name = 'station_master.csv' AND assertion_type = 'HR_STATION_REFERENCE_EVIDENCE') OR (source_file_name = 'sri_lanka_police_stations_sinhala.csv' AND assertion_type = 'HR_STATION_SINHALA_REFERENCE_EVIDENCE')), \n\tCONSTRAINT ck_reference_source_assertion_reference_assertion_state CHECK (assertion_state = 'ACTIVE' AND independence_status = 'UNVERIFIED' AND classification = 'UNASSESSED'), \n\tCONSTRAINT ck_reference_source_assertion_reference_assertion_unkno_54a6 CHECK (valid_from IS NULL AND valid_to IS NULL AND transaction_end IS NULL AND source_recorded_at IS NULL AND captured_at IS NULL AND source_record_id IS NULL AND source_document_id IS NULL AND source_page IS NULL), \n\tCONSTRAINT ck_reference_source_assertion_reference_assertion_cipher CHECK (octet_length(asserted_value_ciphertext) BETWEEN 29 AND 12582912 AND length(encryption_key_version) BETWEEN 1 AND 128), \n\tCONSTRAINT ck_reference_source_assertion_reference_assertion_source CHECK (source_row_number > 0 AND source_file_sha256 ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT fk_reference_source_assertion_source_system_id_source_system FOREIGN KEY(source_system_id) REFERENCES identity.source_system (source_system_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_reference_source_assertion_raw_record_id_raw_record FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record (raw_record_id) ON DELETE RESTRICT\n)", "CREATE TABLE staging.reference_delivery_preparation (\n\tdelivery_id UUID NOT NULL, \n\traw_record_id VARCHAR(64) NOT NULL, \n\tsource_assertion_id UUID NOT NULL, \n\tmaster_import_file_id UUID NOT NULL, \n\tmaster_file_sha256 VARCHAR(64) NOT NULL, \n\tmaster_row_count INTEGER NOT NULL, \n\tconfirmation_sha256 VARCHAR(64) NOT NULL, \n\tcode_revision VARCHAR(40) NOT NULL, \n\tsource_file_name VARCHAR(100) NOT NULL, \n\tmongo_collection VARCHAR(50) NOT NULL, \n\tfield_review_count INTEGER NOT NULL, \n\trow_review_count INTEGER NOT NULL, \n\treview_state VARCHAR(30) NOT NULL, \n\twriter_policy VARCHAR(50) NOT NULL, \n\tlinkage_method VARCHAR(50) NOT NULL, \n\thistorical_eligibility VARCHAR(20) NOT NULL, \n\tdocument_bson BYTEA NOT NULL, \n\tdocument_sha256 VARCHAR(64) NOT NULL, \n\trecorded_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_reference_delivery_preparation PRIMARY KEY (delivery_id), \n\tCONSTRAINT uq_reference_preparation_source_policy UNIQUE (raw_record_id, writer_policy), \n\tCONSTRAINT uq_reference_preparation_assertion UNIQUE (source_assertion_id), \n\tCONSTRAINT uq_reference_preparation_digest UNIQUE (delivery_id, document_sha256), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_master_snapshot CHECK (master_file_sha256 ~ '^[0-9a-f]{64}$' AND master_row_count > 0), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_raw CHECK (raw_record_id ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_4fd5 CHECK (confirmation_sha256 ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_0a05 CHECK (code_revision ~ '^[0-9a-f]{40}$'), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_routing CHECK ((source_file_name = 'station_master.csv' AND mongo_collection = 'station_reference_records' AND writer_policy = 'HR_STATION_REFERENCE_EVIDENCE_V1') OR (source_file_name = 'sri_lanka_police_stations_sinhala.csv' AND mongo_collection = 'station_sinhala_reference_records' AND writer_policy = 'HR_STATION_SINHALA_REFERENCE_EVIDENCE_V1')), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_7cef CHECK ((source_file_name = 'station_master.csv' AND field_review_count BETWEEN 0 AND 13) OR (source_file_name = 'sri_lanka_police_stations_sinhala.csv' AND field_review_count BETWEEN 0 AND 5)), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_8add CHECK (row_review_count BETWEEN 0 AND 32), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_e3c3 CHECK ((field_review_count = 0 AND row_review_count = 0 AND review_state = 'NO_STRUCTURAL_REVIEW') OR ((field_review_count > 0 OR row_review_count > 0) AND review_state = 'STRUCTURAL_REVIEW_REQUIRED')), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_linkage CHECK (historical_eligibility = 'UNASSESSED' AND linkage_method = 'SOURCE_SCOPED_REFERENCE_CANDIDATES_UNASSESSED'), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_size CHECK (octet_length(document_bson) BETWEEN 29 AND 12582912), \n\tCONSTRAINT ck_reference_delivery_preparation_reference_preparation_digest CHECK (document_sha256 = encode(sha256(document_bson), 'hex')), \n\tCONSTRAINT fk_reference_preparation_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record (raw_record_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_reference_preparation_assertion FOREIGN KEY(source_assertion_id) REFERENCES identity.reference_source_assertion (source_assertion_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_reference_preparation_master_file FOREIGN KEY(master_import_file_id) REFERENCES staging.intake_file (import_file_id) ON DELETE RESTRICT\n)", 'CREATE TABLE staging.reference_delivery_completion (\n\tdelivery_id UUID NOT NULL, \n\tdocument_sha256 VARCHAR(64) NOT NULL, \n\trecorded_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL, \n\tCONSTRAINT pk_reference_delivery_completion PRIMARY KEY (delivery_id), \n\tCONSTRAINT fk_reference_completion_prepared_digest FOREIGN KEY(delivery_id, document_sha256) REFERENCES staging.reference_delivery_preparation (delivery_id, document_sha256) ON DELETE RESTRICT\n)')


def upgrade():
    for ddl in TABLE_DDL:
        op.execute(ddl)
    op.execute("""CREATE FUNCTION identity.guard_reference_assertion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.raw_record r
            JOIN staging.intake_file f ON f.import_file_id = r.import_file_id
            JOIN identity.source_system s ON s.source_system_id = NEW.source_system_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND r.batch_id = NEW.intake_batch_id AND r.import_file_id::text = NEW.import_file_id
              AND f.batch_id = r.batch_id AND f.archive_path = r.archive_path
              AND f.source_file_sha256 = r.source_file_sha256
              AND regexp_replace(r.archive_path, '^.*/', '') = NEW.source_file_name
              AND r.source_file_sha256 = NEW.source_file_sha256 AND r.source_row_number = NEW.source_row_number
              AND s.is_active AND s.source_system_code = 'POLICE_HR_IS'
              AND NEW.assertion_type = CASE NEW.source_file_name
                  WHEN 'station_master.csv' THEN 'HR_STATION_REFERENCE_EVIDENCE'
                  WHEN 'sri_lanka_police_stations_sinhala.csv' THEN 'HR_STATION_SINHALA_REFERENCE_EVIDENCE' ELSE NULL END)
        THEN RAISE EXCEPTION 'Reference assertion source provenance differs.'; END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_reference_assertion_insert BEFORE INSERT
        ON identity.reference_source_assertion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_reference_assertion_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_reference_preparation_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM staging.raw_record r
            JOIN identity.reference_source_assertion a ON a.source_assertion_id = NEW.source_assertion_id
            JOIN identity.source_system s ON s.source_system_id = a.source_system_id
            JOIN staging.intake_file m ON m.import_file_id = NEW.master_import_file_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND regexp_replace(r.archive_path, '^.*/', '') = NEW.source_file_name
              AND a.raw_record_id = r.raw_record_id AND a.intake_batch_id = r.batch_id
              AND a.import_file_id = r.import_file_id::text AND a.source_file_name = NEW.source_file_name
              AND a.source_file_sha256 = r.source_file_sha256 AND a.source_row_number = r.source_row_number
              AND a.assertion_type = CASE NEW.source_file_name
                  WHEN 'station_master.csv' THEN 'HR_STATION_REFERENCE_EVIDENCE'
                  WHEN 'sri_lanka_police_stations_sinhala.csv' THEN 'HR_STATION_SINHALA_REFERENCE_EVIDENCE' ELSE NULL END
              AND a.assertion_state = 'ACTIVE' AND a.independence_status = 'UNVERIFIED' AND a.classification = 'UNASSESSED'
              AND a.transaction_end IS NULL AND a.valid_from IS NULL AND a.valid_to IS NULL
              AND a.source_recorded_at IS NULL AND a.captured_at IS NULL
              AND a.source_record_id IS NULL AND a.source_document_id IS NULL AND a.source_page IS NULL
              AND a.transaction_start = NEW.recorded_at
              AND s.is_active AND s.source_system_code = 'POLICE_HR_IS'
              AND m.batch_id = r.batch_id AND regexp_replace(m.archive_path, '^.*/', '') = 'station_master.csv'
              AND m.source_file_sha256 = NEW.master_file_sha256 AND m.expected_row_count = NEW.master_row_count
              AND (SELECT count(*) FROM staging.raw_record mr WHERE mr.import_file_id = m.import_file_id
                    AND mr.batch_id = m.batch_id AND mr.archive_path = m.archive_path
                    AND mr.source_file_sha256 = m.source_file_sha256) = NEW.master_row_count
              AND (NEW.source_file_name <> 'station_master.csv' OR r.import_file_id = m.import_file_id)
        ) THEN RAISE EXCEPTION 'Reference preparation source/master snapshot differs.'; END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_reference_preparation_insert BEFORE INSERT
        ON staging.reference_delivery_preparation FOR EACH ROW
        EXECUTE FUNCTION identity.guard_reference_preparation_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_reference_completion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.reference_delivery_preparation p
            WHERE p.delivery_id = NEW.delivery_id AND p.document_sha256 = NEW.document_sha256
              AND NEW.recorded_at >= p.recorded_at)
        THEN RAISE EXCEPTION 'Reference completion must follow and match its preparation.'; END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_reference_completion_insert BEFORE INSERT
        ON staging.reference_delivery_completion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_reference_completion_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_reference_delivery_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Reference delivery evidence is append-only.';
        RETURN NULL; END; $$""")
    for table in ('identity.reference_source_assertion', 'staging.reference_delivery_preparation', 'staging.reference_delivery_completion'):
        # Triggers also prevent accidental maintenance mutations; ordinary app
        # roles receive SELECT/INSERT only. No existing table grants are changed.
        op.execute(f'CREATE TRIGGER protect_reference_rows BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION identity.reject_reference_delivery_mutation()')
        op.execute(f'CREATE TRIGGER protect_reference_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_reference_delivery_mutation()')
        op.execute(f'REVOKE ALL ON TABLE {table} FROM PUBLIC')
        op.execute(f'REVOKE ALL ON TABLE {table} FROM police_identity_app')
        op.execute(f'GRANT SELECT, INSERT ON TABLE {table} TO police_identity_app')


def downgrade():
    raise RuntimeError('No automatic downgrade: preserve reference evidence and use a reviewed recovery migration.')
