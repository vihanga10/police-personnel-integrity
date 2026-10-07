"""Reference model/DDL invariants and inert synthetic fixture construction."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from uuid import uuid4
import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from bson import BSON
from bson.codec_options import CodecOptions
from app.models import ReferenceSourceAssertion, ReferenceDeliveryPreparation, ReferenceDeliveryCompletion, SourceAssertion
from app.security.identity_crypto import IdentityCrypto
from app.storage.reference_mongo_contract import encryption_context

MODELS=(ReferenceSourceAssertion,ReferenceDeliveryPreparation,ReferenceDeliveryCompletion)


def migration():
    path=Path(__file__).resolve().parents[1]/'migrations/versions/b40d8f62ac95_add_reference_delivery_storage.py'
    spec=importlib.util.spec_from_file_location('reference_storage_test',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def test_frozen_ddl_matches_registered_models():
    m=migration()
    assert m.TABLE_DDL==tuple(str(CreateTable(model.__table__).compile(dialect=postgresql.dialect())).strip() for model in MODELS)
    assert (m.revision,m.down_revision)==('b40d8f62ac95','a39c7e51fb84')


def test_source_claim_has_no_fabricated_officer_or_accepted_station():
    t=ReferenceSourceAssertion.__table__
    assert {'officer_uid','station_uid','station_code','station_name','nic','candidate_mappings'}.isdisjoint(t.c.keys())
    assert SourceAssertion.__table__.c.officer_uid.nullable is False
    assert t.c.asserted_value_ciphertext.nullable is False
    rules=' '.join(str(c.sqltext) for c in t.constraints if isinstance(c,CheckConstraint))
    assert "classification = 'UNASSESSED'" in rules and 'valid_from IS NULL' in rules and 'transaction_end IS NULL' in rules
    assert 'HR_STATION_REFERENCE_EVIDENCE' in rules and 'HR_STATION_SINHALA_REFERENCE_EVIDENCE' in rules


def test_preparation_foreign_keys_resolve_to_source_and_master_file():
    t=ReferenceDeliveryPreparation.__table__
    assert {fk.column.table.fullname for fk in t.foreign_keys}=={'staging.raw_record','identity.reference_source_assertion','staging.intake_file'}
    assert all(fk.ondelete=='RESTRICT' for fk in t.foreign_keys)
    assert {'officer_uid','identifier_version_id','station_code','station_uid','station_name'}.isdisjoint(t.c.keys())


def test_preparation_digest_uniqueness_and_review_guards():
    t=ReferenceDeliveryPreparation.__table__
    unique={tuple(c.name for c in con.columns) for con in t.constraints if isinstance(con,UniqueConstraint)}
    assert {('raw_record_id','writer_policy'),('source_assertion_id',),('delivery_id','document_sha256')}<=unique
    rules=' '.join(str(c.sqltext) for c in t.constraints if isinstance(c,CheckConstraint))
    for token in ("encode(sha256(document_bson), 'hex')",'station_reference_records','station_sinhala_reference_records',
        'field_review_count BETWEEN 0 AND 13','field_review_count BETWEEN 0 AND 5','STRUCTURAL_REVIEW_REQUIRED',
        "historical_eligibility = 'UNASSESSED'",'SOURCE_SCOPED_REFERENCE_CANDIDATES_UNASSESSED','master_row_count > 0'):
        assert token in rules


def test_completion_foreign_key_binds_exact_digest():
    con=next(iter(ReferenceDeliveryCompletion.__table__.foreign_key_constraints))
    assert [(e.parent.name,e.column.name) for e in con.elements]==[('delivery_id','delivery_id'),('document_sha256','document_sha256')]
    assert con.ondelete=='RESTRICT'


def test_migration_does_not_offer_deleting_downgrade():
    with pytest.raises(RuntimeError,match='No automatic downgrade'):migration().downgrade()


def test_guards_source_snapshot_and_mutations(monkeypatch):
    m=migration();statements=[];monkeypatch.setattr(m.op,'execute',statements.append);m.upgrade()
    assertion=next(s for s in statements if 'CREATE FUNCTION identity.guard_reference_assertion_insert' in s)
    preparation=next(s for s in statements if 'CREATE FUNCTION identity.guard_reference_preparation_insert' in s)
    completion=next(s for s in statements if 'CREATE FUNCTION identity.guard_reference_completion_insert' in s)
    for token in ('r.source_file_sha256 = NEW.source_file_sha256','r.source_row_number = NEW.source_row_number',"s.source_system_code = 'POLICE_HR_IS'",'HR_STATION_SINHALA_REFERENCE_EVIDENCE'):
        assert token in assertion
    for token in ('m.batch_id = r.batch_id','m.source_file_sha256 = NEW.master_file_sha256','m.expected_row_count = NEW.master_row_count',
                  'SELECT count(*) FROM staging.raw_record','a.transaction_start = NEW.recorded_at'):
        assert token in preparation
    assert 'NEW.recorded_at >= p.recorded_at' in completion
    for model in MODELS:
        table=model.__table__.fullname
        assert any('BEFORE UPDATE OR DELETE ON '+table in s for s in statements)
        assert any('BEFORE TRUNCATE ON '+table in s for s in statements)
        assert f'GRANT SELECT, INSERT ON TABLE {table} TO police_identity_app' in statements
    assert not any('DROP ' in s or 'ALTER TABLE ' in s for s in statements)


@pytest.mark.parametrize('filename',['station_master.csv','sri_lanka_police_stations_sinhala.csv'])
def test_checker_fixture_preserves_originals_and_dual_key_bson(tmp_path,filename):
    path=Path(__file__).resolve().parents[1]/'scripts/check_reference_storage.py'
    spec=importlib.util.spec_from_file_location('reference_checker_fixture',path);checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    key=base64.b64encode(os.urandom(32)).decode()
    material=dict(active_encryption_key_version='EPHEMERAL',active_lookup_key_version='EPHEMERAL',encryption_keys={'EPHEMERAL':key},lookup_keys={'EPHEMERAL':key})
    copies=[]
    for name in ('primary.json','backup.json'):
        p=tmp_path/name;p.write_text(json.dumps(material));copies.append(IdentityCrypto(p))
    class Sink:
        def execute(self,statement):return self
        def scalar_one(self):return uuid4()
    assertion,prep,payload=checker.fixture(Sink(),*copies,filename)
    assert assertion['assertion_type']==prep['writer_policy'].removesuffix('_V1')
    assert hashlib.sha256(prep['document_bson']).hexdigest()==prep['document_sha256']
    doc=BSON(prep['document_bson']).decode(codec_options=CodecOptions(tz_aware=True))
    for crypto in copies:
        assert crypto.decrypt_assertion(bytes(doc['payload_ciphertext']),key_version=doc['payload_key_version'],context=encryption_context(prep['mongo_collection'],doc))==payload
    assert 'officer_uid' not in assertion and 'officer_uid' not in prep and 'officer_uid' not in doc
    assert payload['plan']['accepted_station_uid'] is None and payload['plan']['valid_from'] is None
    assert prep['master_row_count']==1 and prep['master_file_sha256']=='b'*64
    if filename=='station_master.csv':
        assert next(f for f in payload['plan']['fields'] if f['source_column']=='station_code')['source_value']=='00012'
    else:
        assert prep['field_review_count']==1 and prep['row_review_count']==1
        assert payload['plan']['candidate_evidence'][0]['state']=='SINGLE_JOINT_CANDIDATE'


def test_checker_current_checkpoint_and_no_application_impersonation():
    path=Path(__file__).resolve().parents[1]/'scripts/check_reference_storage.py'
    text=path.read_text()
    assert "REVISION = 'a39c7e51fb84'" in text and "'identity.source_assertion':153923" in text
    assert 'SET LOCAL ROLE' not in text and 'outer.rollback()' in text
