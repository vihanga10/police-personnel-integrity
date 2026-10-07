"""Encrypt empty family civil, next-of-kin and attestation destinations.

Revision ID: f28b6d40ea73
Revises: e17a5c39df62
"""
from alembic import op
import sqlalchemy as sa

revision = "f28b6d40ea73"
down_revision = "e17a5c39df62"
branch_labels = None
depends_on = None

SPEC = {'officer_family_civil_event_version': {'columns': ['event_type', 'event_date', 'evidence_reference_ciphertext', 'encryption_key_version'], 'checks': ['officer_family_civil_event_type', 'officer_family_civil_event_has_value', 'officer_family_civil_event_evidence_reference', 'officer_family_civil_event_encryption_key'], 'indexes': ['ix_officer_family_civil_event_officer_type', 'ix_officer_family_civil_event_date']}, 'officer_next_of_kin_version': {'columns': ['related_person_name', 'relationship_type', 'address_ciphertext', 'encryption_key_version'], 'checks': ['officer_next_of_kin_has_name', 'officer_next_of_kin_has_relationship', 'officer_next_of_kin_address', 'officer_next_of_kin_encryption_key'], 'indexes': []}, 'source_attestation': {'columns': ['actor_name_ciphertext', 'actor_identifier_type', 'actor_identifier_ciphertext', 'actor_identifier_lookup_hmac', 'actor_rank_asserted', 'signature_reference_ciphertext', 'attested_on', 'encryption_key_version', 'lookup_key_version'], 'checks': ['attestation_has_value', 'attestation_actor_name', 'attestation_actor_identifier', 'attestation_signature', 'attestation_encryption_key', 'attestation_lookup_hmac', 'attestation_lookup_key', 'attestation_identifier_type'], 'indexes': []}}


def upgrade():
    # Lock all destinations before checking emptiness or changing any column.
    # Nonempty tables require a separately reviewed preserving conversion.
    tables = sorted(SPEC)
    op.execute("LOCK TABLE " + ", ".join("identity."+t for t in tables) + " IN ACCESS EXCLUSIVE MODE")
    for table in tables:
        op.execute(f"""DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM identity.{table}) THEN
                RAISE EXCEPTION 'Family encryption conversion requires empty destinations.';
            END IF;
        END; $$""")
    for table, rule in SPEC.items():
        for name in rule['indexes']:
            op.drop_index(name, table_name=table, schema='identity')
        for name in rule['checks']:
            op.drop_constraint(op.f('ck_'+table+'_'+name),table,schema='identity',type_='check')
        for name in rule['columns']:
            op.drop_column(table,name,schema='identity')
        op.add_column(table,sa.Column('profile_payload_ciphertext',sa.LargeBinary(),nullable=False),schema='identity')
        op.add_column(table,sa.Column('encryption_key_version',sa.String(50),nullable=False),schema='identity')
        for name,expression in (
            ('family_payload_present','octet_length(profile_payload_ciphertext) > 28'),
            ('family_key_present','length(trim(encryption_key_version)) > 0'),
        ):
            op.create_check_constraint(op.f('ck_'+table+'_'+name),table,expression,schema='identity')
    op.create_check_constraint(op.f('ck_officer_next_of_kin_version_family_dates_protected'),
        'officer_next_of_kin_version','valid_from IS NULL AND valid_to IS NULL',schema='identity')
    op.create_index('ix_officer_family_civil_event_officer','officer_family_civil_event_version',['officer_uid'],schema='identity')

    # Existing assertion ownership, chain-version and controlled closure guards
    # remain active. Check nullable/required family relation ownership as well.
    op.execute("""CREATE FUNCTION identity.guard_family_relation_owner()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.family_relation_version_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM identity.officer_family_relation r
            WHERE r.family_relation_version_id = NEW.family_relation_version_id
              AND r.officer_uid = NEW.officer_uid
        ) THEN
            RAISE EXCEPTION 'Supporting family relation belongs to another officer or does not exist.';
        END IF;
        RETURN NEW; END; $$""")
    for table in ('officer_family_civil_event_version','officer_next_of_kin_version'):
        op.execute(f"""CREATE TRIGGER guard_family_relation_owner BEFORE INSERT
            ON identity.{table} FOR EACH ROW EXECUTE FUNCTION identity.guard_family_relation_owner()""")
    op.execute("""CREATE FUNCTION identity.reject_family_evidence_removal()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Family evidence cannot be deleted or truncated.';
        RETURN NULL; END; $$""")
    for table in tables:
        op.execute(f"""CREATE TRIGGER protect_family_delete BEFORE DELETE ON identity.{table}
            FOR EACH ROW EXECUTE FUNCTION identity.reject_family_evidence_removal()""")
        op.execute(f"""CREATE TRIGGER protect_family_truncate BEFORE TRUNCATE ON identity.{table}
            FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_family_evidence_removal()""")
        # Preserve column-level version closure; no blanket UPDATE grant.
        op.execute(f"REVOKE DELETE, TRUNCATE ON TABLE identity.{table} FROM PUBLIC, police_identity_app")


def downgrade():
    raise RuntimeError('No automatic downgrade: preserve encrypted evidence and use reviewed recovery.')
