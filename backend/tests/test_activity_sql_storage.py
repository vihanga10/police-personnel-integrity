"""Storage invariants; real PostgreSQL enforcement uses the rollback-only checker."""
import importlib.util
from pathlib import Path
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import ActivityDeliveryPreparation, ActivityDeliveryCompletion


def test_receipt_binds_both_event_and_digest_without_cascading_deletion():
    constraint = next(c for c in ActivityDeliveryCompletion.__table__.foreign_key_constraints
                      if c.name == 'fk_activity_completion_prepared_digest')
    assert [(e.parent.name, e.column.name) for e in constraint.elements] == [
        ('delivery_id', 'delivery_id'), ('document_sha256', 'document_sha256')]
    assert constraint.ondelete == 'RESTRICT'


def test_activity_provenance_foreign_keys_resolve_across_metadata():
    table = ActivityDeliveryPreparation.__table__
    assert table.fullname in StagingBase.metadata.tables and table.fullname not in Base.metadata.tables
    assert {fk.column.table.fullname for fk in table.foreign_keys} == {
        'staging.raw_record', 'identity.officer', 'identity.source_assertion', 'identity.officer_identifier_version'}
    assert all(fk.ondelete == 'RESTRICT' for fk in table.foreign_keys)
    assert set(table.c.keys()).isdisjoint({'name', 'nic', 'police_no', 'restriction_id', 'restriction_reason', 'restriction_effect', 'override_reason', 'override_authority_nic'})


def test_source_delivery_is_unique_and_review_metadata_is_explicit():
    table = ActivityDeliveryPreparation.__table__
    unique_columns = {tuple(c.name for c in constraint.columns) for constraint in table.constraints if isinstance(constraint, UniqueConstraint)}
    assert ('raw_record_id', 'writer_policy') in unique_columns
    assert ('source_assertion_id',) in unique_columns
    rules = ' '.join(str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint))
    assert "encode(sha256(document_bson), 'hex')" in rules
    assert all(policy in rules for policy in ('SRB_DUTY_EVIDENCE_V1', 'SRB_FIREARMS_EVIDENCE_V1', 'SRB_GOOD_CONDUCT_EVIDENCE_V1', 'SRB_BAD_CONDUCT_EVIDENCE_V1'))
    assert 'STRUCTURAL_REVIEW_REQUIRED' in rules and 'field_review_count > 0' in rules and 'row_review_count > 0' in rules
    assert "historical_eligibility = 'UNASSESSED'" in rules
    assert table.c.field_review_count.nullable is False
    assert table.c.review_state.nullable is False
    assert table.c.row_review_count.nullable is False


def test_frozen_migration_ddl_matches_registered_models():
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/d06f4b28ce51_add_activity_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('activity_storage_test_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    compiled = tuple(str(CreateTable(m.__table__).compile(dialect=postgresql.dialect())).strip()
                     for m in (ActivityDeliveryPreparation, ActivityDeliveryCompletion))
    assert migration.TABLE_DDL == compiled
    assert migration.down_revision == 'c95e3a17bd40'
    assert migration.revision == 'd06f4b28ce51'


def test_migration_does_not_offer_destructive_downgrade():
    import pytest
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/d06f4b28ce51_add_activity_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('activity_storage_downgrade_test', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with pytest.raises(RuntimeError, match='No automatic downgrade'):
        migration.downgrade()


def test_migration_guards_routes_and_both_mutation_paths(monkeypatch):
    """Capture DDL without a database; actual enforcement is checked on PostgreSQL."""
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/d06f4b28ce51_add_activity_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('activity_guard_test', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    statements = []
    monkeypatch.setattr(migration.op, 'execute', statements.append)
    migration.upgrade()
    guard = next(s for s in statements if 'CREATE FUNCTION identity.guard_activity_preparation_insert' in s)
    from app.identity.srb_activity_plan import DESTINATIONS
    from app.storage.activity_mongo_contract import COLLECTION_POLICIES
    for filename, destination in DESTINATIONS.items():
        policy = COLLECTION_POLICIES[destination.split('.', 1)[1]]
        assert f"WHEN '{filename}' THEN '{policy.removesuffix('_V1')}'" in guard
    assert "s.source_system_code = 'SRB' AND s.is_active" in guard
    assert "a.independence_status = 'UNVERIFIED'" in guard
    assert "i.record_state IN ('ASSERTED', 'ACCEPTED')" in guard
    for table in ('activity_delivery_preparation', 'activity_delivery_completion'):
        assert any(f'BEFORE UPDATE OR DELETE ON staging.{table}' in s for s in statements)
        assert any(f'BEFORE TRUNCATE ON staging.{table}' in s for s in statements)
        assert f'GRANT SELECT, INSERT ON TABLE staging.{table} TO police_identity_app' in statements
    assert not any('DROP ' in s or 'ALTER TABLE ' in s for s in statements)


def test_rollback_checker_fixtures_preserve_each_source_and_recover_ciphertext(tmp_path):
    """Run fixture construction against an inert sink, never a database driver."""
    import base64
    import hashlib
    import json
    import os
    from uuid import uuid4
    from bson import BSON
    from bson.codec_options import CodecOptions
    from app.security.identity_crypto import IdentityCrypto
    from app.storage.activity_mongo_contract import encryption_context
    path = Path(__file__).resolve().parents[1] / 'scripts/check_activity_storage.py'
    spec = importlib.util.spec_from_file_location('activity_checker_fixture_test', path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    key = base64.b64encode(os.urandom(32)).decode()
    material = dict(active_encryption_key_version='EPHEMERAL', active_lookup_key_version='EPHEMERAL',
        encryption_keys={'EPHEMERAL': key}, lookup_keys={'EPHEMERAL': key})
    copies = []
    for name in ('primary.json', 'backup.json'):
        key_path = tmp_path / name
        key_path.write_text(json.dumps(material))
        key_path.chmod(0o600)
        copies.append(IdentityCrypto(key_path))
    class Sink:
        def execute(self, statement):
            return self
        def scalar_one_or_none(self):
            return uuid4()
    for filename in checker.ROUTES:
        assertion, prep, payload = checker.fixture(Sink(), *copies, filename)
        assert assertion['assertion_type'] == prep['writer_policy'].removesuffix('_V1')
        assert prep['document_sha256'] == hashlib.sha256(prep['document_bson']).hexdigest()
        assert prep['field_review_count'] == (1 if filename == 'officer_duty_periods.csv' else 0)
        assert prep['row_review_count'] == 0
        doc = BSON(prep['document_bson']).decode(codec_options=CodecOptions(tz_aware=True))
        for crypto in copies:
            assert crypto.decrypt_assertion(bytes(doc['payload_ciphertext']),
                key_version=doc['payload_key_version'],
                context=encryption_context(prep['mongo_collection'], doc)) == payload
        assert payload['record_classification'] == 'UNASSESSED'
        assert payload['valid_from'] is None and payload['valid_to'] is None
        assert payload['reconstructed_state'] is None
        fields = {f['source_column']: f for f in payload['fields']}
        assert fields[{'officer_duty_periods.csv': 'period_id',
            'officer_firearms_expertise.csv': 'gun_record_id',
            'good_conduct_register.csv': 'good_conduct_id',
            'bad_conduct_register.csv': 'punishment_id'}[filename]]['value'] == '00012'
        if filename == 'officer_duty_periods.csv':
            assert fields['period_to']['source_value'] == 'not a date'
            assert fields['period_to']['value'] is None
        if filename == 'good_conduct_register.csv':
            assert fields['accused_arrested']['value'] is True
            assert fields['accused_convicted']['value'] is False
        if filename == 'officer_firearms_expertise.csv':
            assert fields['h2_total_points']['value'] is None
