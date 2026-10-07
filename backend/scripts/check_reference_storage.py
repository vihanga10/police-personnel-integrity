"""Rollback-only reference DDL and synthetic storage checks at a39c7e51fb84.

No Mongo connection, production encryption keys or personnel values. Fixtures
use the migrator; application ACLs are inspected without role impersonation.
"""
import base64
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from bson import BSON, Binary
from bson.codec_options import CodecOptions
from sqlalchemy import URL, create_engine, insert, select, text, func
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import ReferenceSourceAssertion, ReferenceDeliveryPreparation, ReferenceDeliveryCompletion, SourceSystem
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision
from app.identity.reference_plan import ReferenceCandidates, plan_reference
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL
from app.identity.registration_service import REGISTRATION_LOCK
from app.intake.staging_rows import seal_row
from app.security.identity_crypto import IdentityCrypto
from app.storage.reference_mongo_contract import COLLECTION_POLICIES, encryption_context
from migration_settings import MigrationSettings

REVISION = 'a39c7e51fb84'
TABLES = ('identity.reference_source_assertion', 'staging.reference_delivery_preparation', 'staging.reference_delivery_completion')
FUNCTIONS = ('guard_reference_assertion_insert', 'guard_reference_preparation_insert', 'guard_reference_completion_insert', 'reject_reference_delivery_mutation')
CHECKPOINT = {'identity.officer':6596, 'identity.officer_identifier_version':23966,
    'identity.source_assertion':153923, 'identity.remaining_source_assertion':36694,
    'identity.source_assertion_classification':0, 'identity.source_system':3,
    'identity.officer_family_relation':15585, 'identity.officer_family_civil_event_version':5245,
    'identity.officer_next_of_kin_version':6596, 'identity.source_attestation':6596,
    'staging.family_transform_receipt':6596, 'staging.profile_transform_receipt':6596,
    'staging.service_delivery_preparation':6596, 'staging.service_delivery_completion':6596,
    'staging.history_delivery_preparation':47290, 'staging.history_delivery_completion':47290,
    'staging.srb_delivery_preparation':26244, 'staging.srb_delivery_completion':26244,
    'staging.activity_delivery_preparation':36635, 'staging.activity_delivery_completion':36635,
    'staging.remaining_delivery_preparation':36694, 'staging.remaining_delivery_completion':36694}


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def counts(connection):
    # Every pre-existing mapped table is checked without reading payloads.
    tables = {**Base.metadata.tables, **StagingBase.metadata.tables}
    return {name:connection.execute(select(func.count()).select_from(table)).scalar_one()
            for name,table in tables.items() if name not in TABLES}


def fixture(connection, crypto, backup, filename):
    """Prepare a separate synthetic source batch/master snapshot inside rollback."""
    batch = 'REFERENCE-SMOKE-' + uuid4().hex
    master_file, source_file, assertion_id, delivery_id = (uuid4() for _ in range(4))
    master = dict.fromkeys(HEADERS[MASTER], '')
    master.update(station_code='00012',station_name='Example',station_name_si='උදාහරණ',division='Division',province='Province',latitude='6.90',longitude='79.90')
    source = dict.fromkeys(HEADERS[SINHALA], '')
    source.update({LABEL:'Example (උදාහරණ)', 'Division':'Division (අංශය)', 'Province ':'Province (පළාත)', 'Latitude':'not a coordinate', 'Longitude':''})
    if filename == MASTER:
        source_file, source = master_file, master
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch,archive_sha256='a'*64,archive_size_bytes=1,
        expected_file_count=1 if filename==MASTER else 2,registration_receipt_id=uuid4(),registration_receipt_sha256='c'*64,schema_version='1.0'))
    def stage(name, row, file_id, digest):
        connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id,batch_id=batch,archive_path=name,
            source_file_sha256=digest,size_bytes=1,expected_row_count=1,column_count=len(row),columns=list(row),declared_encoding='UTF-8',delimiter=','))
        sealed = seal_row(crypto,batch_id=batch,archive_path=name,source_file_sha256=digest,source_row_number=1,columns=list(row),values=list(row.values()))
        connection.execute(insert(RawRecord.__table__).values(**asdict(sealed),import_file_id=file_id))
        return sealed.raw_record_id
    master_raw = stage(MASTER, master, master_file, 'b'*64)
    source_hash = 'b'*64 if filename==MASTER else 'd'*64
    rid = master_raw if filename==MASTER else stage(SINHALA,source,source_file,source_hash)
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code=='POLICE_HR_IS', SourceSystem.is_active.is_(True))).scalar_one()
    plan = plan_reference(filename,source,raw_record_id=rid,candidates=ReferenceCandidates([(master_raw,master)]))
    payload = dict(synthetic=True,plan=plan.payload)
    collection = 'station_reference_records' if filename==MASTER else 'station_sinhala_reference_records'
    recorded = datetime.now(timezone.utc); recorded=recorded.replace(microsecond=recorded.microsecond//1000*1000)
    document = dict(_id=str(delivery_id),source_assertion_uid=str(assertion_id),raw_record_id=rid,
        writer_policy=COLLECTION_POLICIES[collection],schema_version=1,classification='UNASSESSED',recorded_at=recorded,
        payload_key_version=crypto.active_encryption_version)
    cipher,version=crypto.encrypt_assertion(payload,context=encryption_context(collection,document))
    document['payload_ciphertext']=Binary(cipher)
    encoded=bytes(BSON.encode(document))
    assertion=dict(source_assertion_id=assertion_id,source_system_id=source_id,raw_record_id=rid,intake_batch_id=batch,
        import_file_id=str(source_file),source_file_name=filename,source_file_sha256=source_hash,source_row_number=1,
        assertion_type=COLLECTION_POLICIES[collection].removesuffix('_V1'),asserted_value_ciphertext=cipher,
        encryption_key_version=version,transaction_start=recorded)
    field_reviews=sum(f['status']=='REVIEW_REQUIRED' for f in plan.payload['fields'])
    row_reviews=len(plan.payload['review_issues'])
    prep=dict(delivery_id=delivery_id,raw_record_id=rid,source_assertion_id=assertion_id,master_import_file_id=master_file,
        master_file_sha256='b'*64,master_row_count=1,confirmation_sha256='c'*64,code_revision='0'*40,
        source_file_name=filename,mongo_collection=collection,field_review_count=field_reviews,row_review_count=row_reviews,
        review_state='STRUCTURAL_REVIEW_REQUIRED' if plan.payload['needs_review'] else 'NO_STRUCTURAL_REVIEW',
        writer_policy=document['writer_policy'],linkage_method='SOURCE_SCOPED_REFERENCE_CANDIDATES_UNASSESSED',
        historical_eligibility='UNASSESSED',document_bson=encoded,document_sha256=hashlib.sha256(encoded).hexdigest(),recorded_at=recorded)
    return assertion,prep,payload


def main():
    settings=MigrationSettings()
    require((settings.host,settings.port,settings.user,settings.name)==('127.0.0.1',5432,'police_identity_migrator','police_identity'),'Unexpected migration target.')
    engine=create_engine(URL.create('postgresql+psycopg',username=settings.user,password=settings.password.get_secret_value(),host=settings.host,port=settings.port,database=settings.name),
        poolclass=NullPool,hide_parameters=True,connect_args={'connect_timeout':5})
    path=BACKEND/'migrations/versions/b40d8f62ac95_add_reference_delivery_storage.py'
    spec=importlib.util.spec_from_file_location('reference_storage_check_migration',path)
    migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
    baseline=None; checks=0
    try:
        with tempfile.TemporaryDirectory() as directory:
            key=base64.b64encode(os.urandom(32)).decode()
            material=dict(active_encryption_key_version='EPHEMERAL',active_lookup_key_version='EPHEMERAL',encryption_keys={'EPHEMERAL':key},lookup_keys={'EPHEMERAL':key})
            paths=[Path(directory)/n for n in ('primary.json','backup.json')]
            for p in paths:p.write_text(json.dumps(material));p.chmod(0o600)
            crypto,backup=(IdentityCrypto(p) for p in paths)
            with engine.connect() as connection:
                outer=connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout='5s'"));connection.execute(text("SET LOCAL statement_timeout='30s'"))
                    connection.execute(text('SELECT pg_advisory_xact_lock(:key)'),{'key':REGISTRATION_LOCK})
                    require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==[REVISION],'Unexpected applied revision.')
                    for table in TABLES:require(connection.execute(text('SELECT to_regclass(:name)'),{'name':table}).scalar_one() is None,'Run before reference migration.')
                    for function in FUNCTIONS:require(connection.execute(text('SELECT to_regprocedure(:name)'),{'name':'identity.'+function+'()'}).scalar_one() is None,'Unexpected existing reference guard.')
                    baseline=counts(connection)
                    require(all(baseline.get(name)==n for name,n in CHECKPOINT.items()),'Unexpected reconciled research counts.')
                    with Operations.context(MigrationContext.configure(connection)):migration.upgrade()
                    checks+=1
                    context=MigrationContext.configure(connection,opts={'include_schemas':True,'compare_type':True,'version_table':'alembic_version','version_table_schema':'identity',
                        'include_object':lambda obj,name,kind,reflected,other:kind!='table' or obj.schema in {'identity','staging'}})
                    require(not compare_metadata(context,[Base.metadata,StagingBase.metadata]),'Schema/model differences detected.');checks+=1
                    for table in TABLES:
                        for privilege,allowed in (('SELECT',True),('INSERT',True),('UPDATE',False),('DELETE',False),('TRUNCATE',False),('REFERENCES',False),('TRIGGER',False)):
                            actual=connection.execute(text("SELECT has_table_privilege('police_identity_app',:table,:privilege)"),{'table':table,'privilege':privilege}).scalar_one()
                            require(actual is allowed,'Unexpected application reference privileges.');checks+=1
                    def rejected(action,state):
                        nonlocal checks
                        savepoint=connection.begin_nested()
                        try:action()
                        except DBAPIError as error:
                            require(getattr(error.orig,'sqlstate',None)==state,'Unexpected SQL rejection type.');checks+=1
                        else:raise RuntimeError('Prohibited SQL operation accepted.')
                        finally:savepoint.rollback()
                    at,pt,ct=ReferenceSourceAssertion.__table__,ReferenceDeliveryPreparation.__table__,ReferenceDeliveryCompletion.__table__
                    for filename in HEADERS:
                        assertion,prep,payload=fixture(connection,crypto,backup,filename)
                        before=connection.execute(select(func.count()).select_from(at)).scalar_one()
                        def failed_pair():
                            connection.execute(insert(at).values(**assertion))
                            connection.execute(insert(pt).values(**dict(prep,document_sha256='0'*64)))
                        rejected(failed_pair,'23514')
                        require(connection.execute(select(func.count()).select_from(at)).scalar_one()==before,'Failed pair retained source assertion.');checks+=1
                        rejected(lambda:connection.execute(insert(at).values(**dict(assertion,source_file_sha256='0'*64))),'P0001')
                        rejected(lambda:connection.execute(insert(at).values(**dict(assertion,source_row_number=2))),'P0001')
                        rejected(lambda:connection.execute(insert(at).values(**dict(assertion,classification='ORDINARY'))),'23514')
                        connection.execute(insert(at).values(**assertion));connection.execute(insert(pt).values(**prep));checks+=2
                        saved=connection.execute(select(pt).where(pt.c.delivery_id==prep['delivery_id'])).mappings().one()
                        require(bytes(saved['document_bson'])==prep['document_bson'],'Exact BSON changed.');checks+=1
                        doc=BSON(bytes(saved['document_bson'])).decode(codec_options=CodecOptions(tz_aware=True))
                        for key_copy in (crypto,backup):
                            require(key_copy.decrypt_assertion(bytes(doc['payload_ciphertext']),key_version=doc['payload_key_version'],context=encryption_context(prep['mongo_collection'],doc))==payload,'Encrypted recovery differs.');checks+=1
                        require(saved['field_review_count']==sum(f['status']=='REVIEW_REQUIRED' for f in payload['plan']['fields']) and
                            saved['row_review_count']==len(payload['plan']['review_issues']),'Review evidence changed.');checks+=1
                        for changes,state in (({'master_file_sha256':'0'*64},'P0001'),({'master_import_file_id':uuid4()},'P0001'),
                            ({'master_row_count':2},'P0001'),({'raw_record_id':'0'*64},'P0001'),
                            ({'document_bson':prep['document_bson']+b'x'},'23514'),({'mongo_collection':'service_status_events'},'23514'),
                            ({'review_state':'INVALID'},'23514'),({'field_review_count':-1},'23514'),({'row_review_count':-1},'23514'),
                            ({'historical_eligibility':'ACCEPTED'},'23514'),({'linkage_method':'ACCEPTED'},'23514'),({},'23505')):
                            changed=dict(prep,delivery_id=uuid4(),**changes)
                            rejected(lambda changed=changed:connection.execute(insert(pt).values(**changed)),state)
                        receipt=dict(delivery_id=prep['delivery_id'],document_sha256=prep['document_sha256'])
                        rejected(lambda:connection.execute(insert(ct).values(**dict(receipt,document_sha256='0'*64))),'P0001')
                        rejected(lambda:connection.execute(insert(ct).values(**dict(receipt,delivery_id=uuid4()))),'P0001')
                        rejected(lambda:connection.execute(insert(ct).values(**receipt,recorded_at=prep['recorded_at']-timedelta(days=1))),'P0001')
                        connection.execute(insert(ct).values(**receipt));checks+=1
                        rejected(lambda:connection.execute(insert(ct).values(**receipt)),'23505')
                    for table in TABLES:
                        timestamp='transaction_start' if table=='identity.reference_source_assertion' else 'recorded_at'
                        for sql in (f'UPDATE {table} SET {timestamp}={timestamp}',f'DELETE FROM {table}'):
                            rejected(lambda sql=sql:connection.execute(text(sql)),'P0001')
                    rejected(lambda:connection.execute(text('TRUNCATE staging.reference_delivery_preparation, staging.reference_delivery_completion, identity.reference_source_assertion')),'P0001')
                    rejected(lambda:connection.execute(text('TRUNCATE staging.reference_delivery_completion')),'P0001')
                finally:outer.rollback()
            with engine.connect() as connection:
                require(counts(connection)==baseline,'Research counts changed after rollback.')
                require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==[REVISION],'Revision changed.')
                for table in TABLES:require(connection.execute(text('SELECT to_regclass(:name)'),{'name':table}).scalar_one() is None,'Reference table survived rollback.')
                for function in FUNCTIONS:require(connection.execute(text('SELECT to_regprocedure(:name)'),{'name':'identity.'+function+'()'}).scalar_one() is None,'Reference guard survived rollback.')
            print('Transactional reference storage checks: PASSED | checks=',checks)
            print('Rollback verified: reference tables/functions and synthetic rows not retained.')
            print('Applied revision remains:',REVISION)
            print('No Mongo connection, personnel values or production encryption keys used.')
            print('Application privileges inspected; fixtures used migrator. Reference delivery/import remain pending.')
        return 0
    except Exception as error:
        print('Reference storage check stopped:',type(error).__name__)
        if isinstance(error,RuntimeError):print(str(error))
        if isinstance(error,DBAPIError):
            print('SQL state:',getattr(error.orig,'sqlstate',None))
            print('Constraint:',getattr(getattr(error.orig,'diag',None),'constraint_name',None))
        print('No commit requested. Review before applying the reference upgrade.')
        return 1
    finally:engine.dispose()


if __name__=='__main__':raise SystemExit(main())
