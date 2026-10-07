"""Storage invariants; real PostgreSQL enforcement uses the rollback-only checker."""
import importlib.util
from pathlib import Path
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import SrbDeliveryPreparation, SrbDeliveryCompletion


def test_receipt_binds_both_event_and_digest_without_cascading_deletion():
    constraint = next(c for c in SrbDeliveryCompletion.__table__.foreign_key_constraints
                      if c.name == 'fk_srb_completion_prepared_digest')
    assert [(e.parent.name, e.column.name) for e in constraint.elements] == [
        ('delivery_id', 'delivery_id'), ('document_sha256', 'document_sha256')]
    assert constraint.ondelete == 'RESTRICT'


def test_srb_provenance_foreign_keys_resolve_across_metadata():
    table = SrbDeliveryPreparation.__table__
    assert table.fullname in StagingBase.metadata.tables and table.fullname not in Base.metadata.tables
    assert {fk.column.table.fullname for fk in table.foreign_keys} == {
        'staging.raw_record', 'identity.officer', 'identity.source_assertion', 'identity.officer_identifier_version'}
    assert all(fk.ondelete == 'RESTRICT' for fk in table.foreign_keys)
    assert set(table.c.keys()).isdisjoint({'name', 'nic', 'police_no', 'restriction_id', 'restriction_reason', 'restriction_effect', 'override_reason', 'override_authority_nic'})


def test_source_delivery_is_unique_and_review_metadata_is_explicit():
    table = SrbDeliveryPreparation.__table__
    unique_columns = {tuple(c.name for c in constraint.columns) for constraint in table.constraints if isinstance(constraint, UniqueConstraint)}
    assert ('raw_record_id', 'writer_policy') in unique_columns
    assert ('source_assertion_id',) in unique_columns
    rules = ' '.join(str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint))
    assert "encode(sha256(document_bson), 'hex')" in rules
    assert all(policy in rules for policy in ('SRB_POLICE_NUMBER_EVIDENCE_V1', 'SRB_RESTRICTION_EVIDENCE_V1', 'SRB_OVERRIDE_EVIDENCE_V1'))
    assert 'STRUCTURAL_REVIEW_REQUIRED' in rules and 'field_review_count > 0' in rules and 'row_review_count > 0' in rules
    assert "historical_eligibility = 'UNASSESSED'" in rules
    assert table.c.field_review_count.nullable is False
    assert table.c.review_state.nullable is False
    assert table.c.row_review_count.nullable is False


def test_frozen_migration_ddl_matches_registered_models():
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/c95e3a17bd40_add_srb_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('srb_storage_test_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    compiled = tuple(str(CreateTable(m.__table__).compile(dialect=postgresql.dialect())).strip()
                     for m in (SrbDeliveryPreparation, SrbDeliveryCompletion))
    assert migration.TABLE_DDL == compiled
    assert migration.down_revision == 'b84d2f06ac39'
    assert migration.revision == 'c95e3a17bd40'


def test_migration_does_not_offer_destructive_downgrade():
    import pytest
    path = Path(__file__).resolve().parents[1] / 'migrations/versions/c95e3a17bd40_add_srb_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('srb_storage_downgrade_test', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with pytest.raises(RuntimeError, match='No automatic downgrade'):
        migration.downgrade()
