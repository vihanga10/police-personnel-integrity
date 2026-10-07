"""Add append-only assertion classification history.

Revision ID: c91a4b7e2036
Revises: a805e70f2e08

No existing evidence is rewritten or automatically classified.
"""

from alembic import op


revision = "c91a4b7e2036"
down_revision = "a805e70f2e08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE identity.source_assertion_classification (
            classification_id uuid NOT NULL,
            source_assertion_id uuid NOT NULL,
            version_number integer NOT NULL,
            previous_classification_id uuid,
            previous_version_number integer,
            classification varchar(30) NOT NULL,
            restricted_unit varchar(20),
            reason_code varchar(80) NOT NULL,
            policy_version varchar(50) NOT NULL,
            recorded_by varchar(200) NOT NULL,
            evidence_ciphertext bytea NOT NULL,
            encryption_key_version varchar(50) NOT NULL,
            recorded_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT pk_source_assertion_classification PRIMARY KEY (classification_id),
            CONSTRAINT fk_class_assertion FOREIGN KEY (source_assertion_id)
                REFERENCES identity.source_assertion (source_assertion_id) ON DELETE RESTRICT,
            CONSTRAINT ck_source_assertion_classification_class_value CHECK (
                classification IN ('ORDINARY', 'CID_CCIB_RESTRICTED', 'UNASSESSED')),
            CONSTRAINT ck_source_assertion_classification_class_unit CHECK (
                (classification = 'CID_CCIB_RESTRICTED' AND restricted_unit IS NOT NULL
                 AND restricted_unit IN ('CID', 'CCIB', 'CID_AND_CCIB')) OR
                (classification IN ('ORDINARY', 'UNASSESSED') AND restricted_unit IS NULL)),
            CONSTRAINT ck_source_assertion_classification_class_chain CHECK (
                (version_number = 1 AND previous_classification_id IS NULL
                 AND previous_version_number IS NULL) OR
                (version_number > 1 AND previous_classification_id IS NOT NULL
                 AND previous_version_number IS NOT NULL
                 AND previous_version_number = version_number - 1)),
            CONSTRAINT ck_source_assertion_classification_class_evidence CHECK (
                octet_length(evidence_ciphertext) > 28),
            CONSTRAINT ck_source_assertion_classification_class_key CHECK (
                length(trim(encryption_key_version)) > 0),
            CONSTRAINT ck_source_assertion_classification_class_policy CHECK (
                length(trim(policy_version)) > 0),
            CONSTRAINT ck_source_assertion_classification_class_actor CHECK (
                length(trim(recorded_by)) > 0),
            CONSTRAINT ck_source_assertion_classification_class_reason CHECK (
                reason_code ~ '^[A-Z][A-Z0-9_]{0,79}$'),
            CONSTRAINT uq_class_assertion_version UNIQUE (source_assertion_id, version_number),
            CONSTRAINT uq_class_identity_binding UNIQUE (
                classification_id, source_assertion_id, version_number),
            CONSTRAINT uq_class_predecessor UNIQUE (previous_classification_id),
            CONSTRAINT fk_class_predecessor_binding FOREIGN KEY (
                previous_classification_id, source_assertion_id, previous_version_number)
                REFERENCES identity.source_assertion_classification (
                    classification_id, source_assertion_id, version_number) ON DELETE RESTRICT
        )
    """)
    op.execute("""
        CREATE FUNCTION identity.reject_classification_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Classification history is append-only; append a new assessment.';
            RETURN NULL;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER protect_classification_rows
        BEFORE UPDATE OR DELETE ON identity.source_assertion_classification
        FOR EACH ROW EXECUTE FUNCTION identity.reject_classification_mutation()
    """)
    op.execute("""
        CREATE TRIGGER protect_classification_truncate
        BEFORE TRUNCATE ON identity.source_assertion_classification
        FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_classification_mutation()
    """)
    op.execute("REVOKE ALL ON TABLE identity.source_assertion_classification FROM PUBLIC")
    op.execute("REVOKE ALL ON TABLE identity.source_assertion_classification FROM police_identity_app")
    # Read only until the evidence classifier and its write authorization exist.
    op.execute("GRANT SELECT ON TABLE identity.source_assertion_classification TO police_identity_app")


def downgrade() -> None:
    op.execute("LOCK TABLE identity.source_assertion_classification IN ACCESS EXCLUSIVE MODE")
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM identity.source_assertion_classification) THEN
                RAISE EXCEPTION 'Cannot remove populated classification history.';
            END IF;
        END; $$
    """)
    op.execute("DROP TABLE identity.source_assertion_classification")
    op.execute("DROP FUNCTION identity.reject_classification_mutation()")
