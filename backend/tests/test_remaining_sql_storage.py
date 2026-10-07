"""Storage invariants; real PostgreSQL enforcement uses the rollback-only checker."""
import importlib.util
from pathlib import Path
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import RemainingDeliveryPreparation, RemainingDeliveryCompletion, RemainingSourceAssertion


def test_receipt_binds_both_event_and_digest_without_cascading_deletion():
    constraint = next(c for c in RemainingDeliveryCompletion.__table__.foreign_key_constraints
                      if c.name == 'fk_remaining_completion_prepared_digest')
    assert [(e.parent.name, e.column.name) for e in constraint.elements] == [
        ('delivery_id', 'delivery_id'), ('document_sha256', 'document_sha256')]
    assert constraint.ondelete == 'RESTRICT'


def test_remaining_provenance_foreign_keys_resolve_across_metadata():
    table = RemainingDeliveryPreparation.__table__
    assert table.fullname in StagingBase.metadata.tables and table.fullname not in Base.metadata.tables
    assert {fk.column.table.fullname for fk in table.foreign_keys} == {
        'staging.raw_record', 'identity.officer', 'identity.remaining_source_assertion', 'identity.officer_identifier_version'}
    assert all(fk.ondelete == 'RESTRICT' for fk in table.foreign_keys)
    assert set(table.c.keys()).isdisjoint({'name', 'nic', 'police_no', 'restriction_id', 'restriction_reason', 'restriction_effect', 'override_reason', 'override_authority_nic'})


def test_source_delivery_is_unique_and_review_metadata_is_explicit():
    table = RemainingDeliveryPreparation.__table__
    unique_columns = {tuple(c.name for c in constraint.columns) for constraint in table.constraints if isinstance(constraint, UniqueConstraint)}
    assert ('raw_record_id', 'writer_policy') in unique_columns
    assert ('source_assertion_id',) in unique_columns
    rules = ' '.join(str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint))
    assert "encode(sha256(document_bson), 'hex')" in rules
    assert all(policy in rules for policy in ('HR_EDUCATION_EVIDENCE_V1','PF_OPERATION_EVIDENCE_V1','PF_COURT_EVIDENCE_V1','PF_COMPLAINT_EVIDENCE_V1','PF_DEMOTION_EVIDENCE_V1'))
    assert 'STRUCTURAL_REVIEW_REQUIRED' in rules and 'field_review_count > 0' in rules and 'row_review_count > 0' in rules
    assert "historical_eligibility = 'UNASSESSED'" in rules
    assert table.c.field_review_count.nullable is False
    assert table.c.review_state.nullable is False
    assert table.c.row_review_count.nullable is False


def test_frozen_migration_ddl_matches_registered_models():
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/e17a5c39df62_add_remaining_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('remaining_storage_test_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    compiled = tuple(str(CreateTable(m.__table__).compile(dialect=postgresql.dialect())).strip()
                     for m in (RemainingSourceAssertion, RemainingDeliveryPreparation, RemainingDeliveryCompletion))
    assert migration.TABLE_DDL == compiled
    assert migration.down_revision == 'd06f4b28ce51'
    assert migration.revision == 'e17a5c39df62'


def test_migration_does_not_offer_destructive_downgrade():
    import pytest
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/e17a5c39df62_add_remaining_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('remaining_storage_downgrade_test', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with pytest.raises(RuntimeError, match='No automatic downgrade'):
        migration.downgrade()


def test_migration_guards_routes_and_both_mutation_paths(monkeypatch):
    """Capture DDL without a database; actual enforcement is checked on PostgreSQL."""
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/e17a5c39df62_add_remaining_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('remaining_guard_test', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    statements = []
    monkeypatch.setattr(migration.op, 'execute', statements.append)
    migration.upgrade()
    guard = next(s for s in statements if 'CREATE FUNCTION identity.guard_remaining_preparation_insert' in s)
    DESTINATIONS = {"officer_education.csv":"mongodb.education_records", "operations.csv":"mongodb.operation_records", "court_details.csv":"mongodb.court_records", "public_complaints.csv":"mongodb.complaint_records", "_demotions_enacted.csv":"mongodb.demotion_events"}
    from app.storage.remaining_mongo_contract import COLLECTION_POLICIES
    for filename, destination in DESTINATIONS.items():
        policy = COLLECTION_POLICIES[destination.split('.', 1)[1]]
        assert f"WHEN '{filename}' THEN '{policy.removesuffix('_V1')}'" in guard
    assert "THEN 'POLICE_HR_IS' ELSE 'PF_REGISTRY' END AND s.is_active" in guard
    assert "a.independence_status = 'UNVERIFIED'" in guard
    assert "i.record_state IN ('ASSERTED','ACCEPTED')" in guard
    for table in ('remaining_delivery_preparation', 'remaining_delivery_completion'):
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
    from app.storage.remaining_mongo_contract import encryption_context
    path = Path(__file__).resolve().parents[1] / 'scripts/check_remaining_storage.py'
    spec = importlib.util.spec_from_file_location('remaining_checker_fixture_test', path)
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
        assert prep['field_review_count'] == sum(f['status']=='REVIEW_REQUIRED' for f in payload['fields'])
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
        key = {'officer_education.csv':'ol_index','operations.csv':'operation_no','court_details.csv':'court_no',
            'public_complaints.csv':'complaint_id','_demotions_enacted.csv':'punishment_id'}[filename]
        assert fields[key]['source_value']=='00012'
        if filename in {'operations.csv','court_details.csv'}:
            assert prep['officer_uid'] is None and prep['identifier_version_id'] is None
            assert doc['officer_uid'] is None
        else:
            assert prep['officer_uid'] is not None and prep['identifier_version_id'] is not None


def test_multi_person_source_is_separate_without_weakening_existing_assertions():
    from app.models import SourceAssertion
    assert SourceAssertion.__table__.c.officer_uid.nullable is False
    assert RemainingSourceAssertion.__table__.c.officer_uid.nullable is True
    table=RemainingDeliveryPreparation.__table__
    assert table.c.officer_uid.nullable and table.c.identifier_version_id.nullable
    checks=' '.join(str(c.sqltext) for c in table.constraints if isinstance(c,CheckConstraint))
    assert 'MULTI_PERSON_SOURCE_NO_SINGLE_SUBJECT' in checks
    assert 'officer_uid IS NULL AND identifier_version_id IS NULL' in checks
    assert 'officer_uid IS NOT NULL AND identifier_version_id IS NOT NULL' in checks


def test_new_assertions_are_also_immutable_and_source_guarded(monkeypatch):
    path=Path(__file__).resolve().parents[1]/'migrations/versions/e17a5c39df62_add_remaining_delivery_storage.py'
    spec=importlib.util.spec_from_file_location('remaining_claim_guards',path)
    migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
    statements=[];monkeypatch.setattr(migration.op,'execute',statements.append);migration.upgrade()
    assert any('BEFORE UPDATE OR DELETE ON identity.remaining_source_assertion' in x for x in statements)
    assert any('BEFORE TRUNCATE ON identity.remaining_source_assertion' in x for x in statements)
    guard=next(x for x in statements if 'CREATE FUNCTION identity.guard_remaining_assertion_insert' in x)
    assert 'r.source_file_sha256 = NEW.source_file_sha256' in guard
    assert 'r.source_row_number = NEW.source_row_number' in guard
    assert "WHEN 'operations.csv' THEN 'PF_OPERATION_EVIDENCE'" in guard
    assert 'GRANT SELECT, INSERT ON TABLE identity.remaining_source_assertion TO police_identity_app' in statements
