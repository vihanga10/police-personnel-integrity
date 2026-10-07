"""Add immutable remaining HR/PF preparation and completion storage.

Revision ID: e17a5c39df62
Revises: d06f4b28ce51
"""
from alembic import op

revision = "e17a5c39df62"
down_revision = "d06f4b28ce51"
branch_labels = None
depends_on = None

# Frozen DDL: future ORM changes must not alter an applied migration.
TABLE_DDL = ("CREATE TABLE identity.remaining_source_assertion (\n\tsource_assertion_id UUID NOT NULL, \n\tofficer_uid UUID, \n\tsource_system_id UUID NOT NULL, \n\traw_record_id VARCHAR(64) NOT NULL, \n\tintake_batch_id VARCHAR(100) NOT NULL, \n\timport_file_id VARCHAR(100) NOT NULL, \n\tsource_file_name VARCHAR(100) NOT NULL, \n\tsource_file_sha256 VARCHAR(64) NOT NULL, \n\tsource_row_number INTEGER NOT NULL, \n\tassertion_type VARCHAR(50) NOT NULL, \n\tasserted_value_ciphertext BYTEA NOT NULL, \n\tencryption_key_version VARCHAR(128) NOT NULL, \n\tassertion_state VARCHAR(20) DEFAULT 'ACTIVE' NOT NULL, \n\tindependence_status VARCHAR(20) DEFAULT 'UNVERIFIED' NOT NULL, \n\tclassification VARCHAR(20) DEFAULT 'UNASSESSED' NOT NULL, \n\tvalid_from TIMESTAMP WITH TIME ZONE, \n\tvalid_to TIMESTAMP WITH TIME ZONE, \n\ttransaction_end TIMESTAMP WITH TIME ZONE, \n\tsource_recorded_at TIMESTAMP WITH TIME ZONE, \n\tcaptured_at TIMESTAMP WITH TIME ZONE, \n\tsource_record_id VARCHAR(100), \n\tsource_document_id VARCHAR(100), \n\tsource_page VARCHAR(100), \n\ttransaction_start TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL, \n\tCONSTRAINT pk_remaining_source_assertion PRIMARY KEY (source_assertion_id), \n\tCONSTRAINT uq_remaining_assertion_source_type UNIQUE (raw_record_id, assertion_type), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_type CHECK (assertion_type IN ('HR_EDUCATION_EVIDENCE', 'PF_OPERATION_EVIDENCE', 'PF_COURT_EVIDENCE', 'PF_COMPLAINT_EVIDENCE', 'PF_DEMOTION_EVIDENCE')), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_subject CHECK ((source_file_name IN ('operations.csv','court_details.csv') AND officer_uid IS NULL) OR (source_file_name IN ('officer_education.csv','public_complaints.csv','_demotions_enacted.csv') AND officer_uid IS NOT NULL)), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_state CHECK (assertion_state = 'ACTIVE' AND independence_status = 'UNVERIFIED' AND classification = 'UNASSESSED'), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_unkno_60af CHECK (valid_from IS NULL AND valid_to IS NULL AND transaction_end IS NULL AND source_recorded_at IS NULL AND captured_at IS NULL AND source_record_id IS NULL AND source_document_id IS NULL AND source_page IS NULL), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_cipher CHECK (octet_length(asserted_value_ciphertext) BETWEEN 29 AND 12582912 AND length(encryption_key_version) BETWEEN 1 AND 128), \n\tCONSTRAINT ck_remaining_source_assertion_remaining_assertion_source CHECK (source_row_number > 0 AND source_file_sha256 ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT fk_remaining_source_assertion_officer_uid_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer (officer_uid) ON DELETE RESTRICT, \n\tCONSTRAINT fk_remaining_source_assertion_source_system_id_source_system FOREIGN KEY(source_system_id) REFERENCES identity.source_system (source_system_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_remaining_source_assertion_raw_record_id_raw_record FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record (raw_record_id) ON DELETE RESTRICT\n)", "CREATE TABLE staging.remaining_delivery_preparation (\n\tdelivery_id UUID NOT NULL, \n\traw_record_id VARCHAR(64) NOT NULL, \n\tofficer_uid UUID, \n\tsource_assertion_id UUID NOT NULL, \n\tidentifier_version_id UUID, \n\tconfirmation_sha256 VARCHAR(64) NOT NULL, \n\tcode_revision VARCHAR(40) NOT NULL, \n\tsource_file_name VARCHAR(100) NOT NULL, \n\tmongo_collection VARCHAR(50) NOT NULL, \n\tfield_review_count INTEGER NOT NULL, \n\trow_review_count INTEGER NOT NULL, \n\treview_state VARCHAR(30) NOT NULL, \n\twriter_policy VARCHAR(50) NOT NULL, \n\tlinkage_method VARCHAR(50) NOT NULL, \n\thistorical_eligibility VARCHAR(20) NOT NULL, \n\tdocument_bson BYTEA NOT NULL, \n\tdocument_sha256 VARCHAR(64) NOT NULL, \n\trecorded_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tCONSTRAINT pk_remaining_delivery_preparation PRIMARY KEY (delivery_id), \n\tCONSTRAINT uq_remaining_preparation_source_policy UNIQUE (raw_record_id, writer_policy), \n\tCONSTRAINT uq_remaining_preparation_assertion UNIQUE (source_assertion_id), \n\tCONSTRAINT uq_remaining_preparation_digest UNIQUE (delivery_id, document_sha256), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_raw CHECK (raw_record_id ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_56e2 CHECK (confirmation_sha256 ~ '^[0-9a-f]{64}$'), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_b49c CHECK (code_revision ~ '^[0-9a-f]{40}$'), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_routing CHECK ((source_file_name = 'officer_education.csv' AND mongo_collection = 'education_records' AND writer_policy = 'HR_EDUCATION_EVIDENCE_V1') OR (source_file_name = 'operations.csv' AND mongo_collection = 'operation_records' AND writer_policy = 'PF_OPERATION_EVIDENCE_V1') OR (source_file_name = 'court_details.csv' AND mongo_collection = 'court_records' AND writer_policy = 'PF_COURT_EVIDENCE_V1') OR (source_file_name = 'public_complaints.csv' AND mongo_collection = 'complaint_records' AND writer_policy = 'PF_COMPLAINT_EVIDENCE_V1') OR (source_file_name = '_demotions_enacted.csv' AND mongo_collection = 'demotion_events' AND writer_policy = 'PF_DEMOTION_EVIDENCE_V1')), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_4cd2 CHECK ((source_file_name = 'officer_education.csv' AND field_review_count BETWEEN 0 AND 19) OR (source_file_name = 'operations.csv' AND field_review_count BETWEEN 0 AND 32) OR (source_file_name = 'court_details.csv' AND field_review_count BETWEEN 0 AND 16) OR (source_file_name = 'public_complaints.csv' AND field_review_count BETWEEN 0 AND 54) OR (source_file_name = '_demotions_enacted.csv' AND field_review_count BETWEEN 0 AND 4)), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_ab4b CHECK (row_review_count BETWEEN 0 AND 32), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_2db6 CHECK ((field_review_count = 0 AND row_review_count = 0 AND review_state = 'NO_STRUCTURAL_REVIEW') OR ((field_review_count > 0 OR row_review_count > 0) AND review_state = 'STRUCTURAL_REVIEW_REQUIRED')), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_linkage CHECK (historical_eligibility = 'UNASSESSED' AND ((source_file_name IN ('operations.csv','court_details.csv') AND officer_uid IS NULL AND identifier_version_id IS NULL AND linkage_method = 'MULTI_PERSON_SOURCE_NO_SINGLE_SUBJECT') OR (source_file_name NOT IN ('operations.csv','court_details.csv') AND officer_uid IS NOT NULL AND identifier_version_id IS NOT NULL AND linkage_method = 'EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH'))), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_size CHECK (octet_length(document_bson) BETWEEN 29 AND 12582912), \n\tCONSTRAINT ck_remaining_delivery_preparation_remaining_preparation_digest CHECK (document_sha256 = encode(sha256(document_bson), 'hex')), \n\tCONSTRAINT fk_remaining_preparation_raw FOREIGN KEY(raw_record_id) REFERENCES staging.raw_record (raw_record_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_remaining_preparation_officer FOREIGN KEY(officer_uid) REFERENCES identity.officer (officer_uid) ON DELETE RESTRICT, \n\tCONSTRAINT fk_remaining_preparation_assertion FOREIGN KEY(source_assertion_id) REFERENCES identity.remaining_source_assertion (source_assertion_id) ON DELETE RESTRICT, \n\tCONSTRAINT fk_remaining_preparation_identifier FOREIGN KEY(identifier_version_id) REFERENCES identity.officer_identifier_version (identifier_version_id) ON DELETE RESTRICT\n)", 'CREATE TABLE staging.remaining_delivery_completion (\n\tdelivery_id UUID NOT NULL, \n\tdocument_sha256 VARCHAR(64) NOT NULL, \n\trecorded_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp() NOT NULL, \n\tCONSTRAINT pk_remaining_delivery_completion PRIMARY KEY (delivery_id), \n\tCONSTRAINT fk_remaining_completion_prepared_digest FOREIGN KEY(delivery_id, document_sha256) REFERENCES staging.remaining_delivery_preparation (delivery_id, document_sha256) ON DELETE RESTRICT\n)')


def upgrade():
    for ddl in TABLE_DDL:
        op.execute(ddl)
    op.execute("""CREATE FUNCTION identity.guard_remaining_assertion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.raw_record r
            JOIN identity.source_system s ON s.source_system_id = NEW.source_system_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND r.batch_id = NEW.intake_batch_id AND r.import_file_id::text = NEW.import_file_id
              AND regexp_replace(r.archive_path, '^.*/', '') = NEW.source_file_name
              AND r.source_file_sha256 = NEW.source_file_sha256 AND r.source_row_number = NEW.source_row_number
              AND s.is_active AND s.source_system_code = CASE NEW.source_file_name
                    WHEN 'officer_education.csv' THEN 'POLICE_HR_IS' ELSE 'PF_REGISTRY' END
              AND NEW.assertion_type = CASE NEW.source_file_name
                  WHEN 'officer_education.csv' THEN 'HR_EDUCATION_EVIDENCE'
                  WHEN 'operations.csv' THEN 'PF_OPERATION_EVIDENCE'
                  WHEN 'court_details.csv' THEN 'PF_COURT_EVIDENCE'
                  WHEN 'public_complaints.csv' THEN 'PF_COMPLAINT_EVIDENCE'
                  WHEN '_demotions_enacted.csv' THEN 'PF_DEMOTION_EVIDENCE' ELSE NULL END)
        THEN RAISE EXCEPTION 'Remaining assertion source provenance differs.'; END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_remaining_assertion_insert BEFORE INSERT
        ON identity.remaining_source_assertion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_remaining_assertion_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_remaining_preparation_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM staging.raw_record r
            JOIN identity.remaining_source_assertion a ON a.source_assertion_id = NEW.source_assertion_id
            JOIN identity.source_system s ON s.source_system_id = a.source_system_id
            LEFT JOIN identity.officer o ON o.officer_uid = NEW.officer_uid
            LEFT JOIN identity.officer_identifier_version i ON i.identifier_version_id = NEW.identifier_version_id
            LEFT JOIN identity.source_assertion ia ON ia.source_assertion_id = i.source_assertion_id
            WHERE r.raw_record_id = NEW.raw_record_id
              AND regexp_replace(r.archive_path, '^.*/', '') = NEW.source_file_name
              AND a.officer_uid IS NOT DISTINCT FROM NEW.officer_uid AND a.raw_record_id = r.raw_record_id
              AND a.intake_batch_id = r.batch_id AND a.import_file_id = r.import_file_id::text
              AND a.source_file_name = NEW.source_file_name
              AND a.source_file_sha256 = r.source_file_sha256 AND a.source_row_number = r.source_row_number
              AND a.assertion_type = CASE NEW.source_file_name
                  WHEN 'officer_education.csv' THEN 'HR_EDUCATION_EVIDENCE'
                  WHEN 'operations.csv' THEN 'PF_OPERATION_EVIDENCE'
                  WHEN 'court_details.csv' THEN 'PF_COURT_EVIDENCE'
                  WHEN 'public_complaints.csv' THEN 'PF_COMPLAINT_EVIDENCE'
                  WHEN '_demotions_enacted.csv' THEN 'PF_DEMOTION_EVIDENCE'
                  ELSE NULL END
              AND a.assertion_state = 'ACTIVE' AND a.transaction_end IS NULL
              AND a.valid_from IS NULL AND a.valid_to IS NULL
              AND a.source_recorded_at IS NULL AND a.captured_at IS NULL
              AND a.source_record_id IS NULL AND a.source_document_id IS NULL AND a.source_page IS NULL
              AND a.independence_status = 'UNVERIFIED' AND a.transaction_start = NEW.recorded_at
              AND s.source_system_code = CASE NEW.source_file_name WHEN 'officer_education.csv' THEN 'POLICE_HR_IS' ELSE 'PF_REGISTRY' END AND s.is_active
              AND ((NEW.source_file_name IN ('operations.csv','court_details.csv')
                    AND NEW.officer_uid IS NULL AND NEW.identifier_version_id IS NULL)
                OR (o.registry_state = 'REGISTERED'
                    AND i.officer_uid = NEW.officer_uid AND i.identifier_type = 'NIC'
                    AND i.record_state IN ('ASSERTED','ACCEPTED') AND i.transaction_end IS NULL
                    AND ia.officer_uid = NEW.officer_uid AND ia.assertion_type = 'IDENTIFIER_NIC'
                    AND ia.assertion_state = 'ACTIVE' AND ia.transaction_end IS NULL))
        ) THEN
            RAISE EXCEPTION 'remaining HR/PF preparation provenance does not match usable source evidence.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_remaining_preparation_insert BEFORE INSERT
        ON staging.remaining_delivery_preparation FOR EACH ROW
        EXECUTE FUNCTION identity.guard_remaining_preparation_insert()""")
    op.execute("""CREATE FUNCTION identity.guard_remaining_completion_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM staging.remaining_delivery_preparation p
            WHERE p.delivery_id = NEW.delivery_id AND p.document_sha256 = NEW.document_sha256
              AND NEW.recorded_at >= p.recorded_at) THEN
            RAISE EXCEPTION 'remaining HR/PF completion must follow and match its preparation.';
        END IF;
        RETURN NEW; END; $$""")
    op.execute("""CREATE TRIGGER guard_remaining_completion_insert BEFORE INSERT
        ON staging.remaining_delivery_completion FOR EACH ROW
        EXECUTE FUNCTION identity.guard_remaining_completion_insert()""")
    op.execute("""CREATE FUNCTION identity.reject_remaining_delivery_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'remaining HR/PF delivery evidence is append-only.';
        RETURN NULL; END; $$""")
    for table in ("staging.remaining_delivery_preparation", "staging.remaining_delivery_completion", "identity.remaining_source_assertion"):
        # Defense in depth: role ACLs reject ordinary mutations; triggers also
        # reject accidental UPDATE/DELETE/TRUNCATE by privileged maintenance code.
        op.execute(f"CREATE TRIGGER protect_remaining_rows BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION identity.reject_remaining_delivery_mutation()")
        op.execute(f"CREATE TRIGGER protect_remaining_truncate BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_remaining_delivery_mutation()")
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE {table} FROM police_identity_app")
        op.execute(f"GRANT SELECT, INSERT ON TABLE {table} TO police_identity_app")


def downgrade():
    # Even an empty foundation should not provide a reusable evidence-deletion path.
    raise RuntimeError("No automatic downgrade: preserve remaining evidence and use a reviewed recovery migration.")
