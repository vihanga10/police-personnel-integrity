"""Real reference recovery checks: SQL rollback and isolated synthetic Mongo.

Savepoints exercise transaction bodies, not independent durable SQL commits.
Production uses fresh-connection commit readback; actual imports remain pending.
No research Mongo writes, station/personnel values or production encryption keys.
"""
import argparse
import base64
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
from uuid import UUID, uuid4
BACKEND=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BACKEND))
from sqlalchemy import URL, create_engine, func, select, text, insert
from sqlalchemy.pool import NullPool
from pymongo import MongoClient
from pymongo.errors import AutoReconnect
from app.identity.reference_delivery import deliver, reconcile, collection_for, make_delivery
from app.identity.reference_sql_ledger import ASSERTION,DONE,PREP,ReferenceSourceBinding,prepare_on_connection,completion_on_connection
from app.identity.reference_plan import ReferenceCandidates, plan_reference
from app.identity.station_vocabulary import HEADERS,MASTER,SINHALA,LABEL
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from app.intake.staging_rows import seal_row
from app.staging.models import IntakeBatch,IntakeFile,RawRecord
from app.storage.mongo_connection import client
from app.storage.reference_mongo_contract import COLLECTION_POLICIES,DATABASE,ROLE,privileges
from app.storage.reference_mongo_connection import reference_client
from app.storage.setup_reference_mongo import arguments,credentials,existing_readers,EXISTING_COUNTS,verify_existing,verify_accounts,create_reference_collection,verify_reference_collection
from migration_settings import MigrationSettings
from scripts.check_reference_storage import counts,require,CHECKPOINT


def fixture(connection, crypto, backup, filename):
    """Stage unrelated encrypted reference rows entirely inside SQL rollback."""
    batch = 'REFERENCE-SMOKE-' + uuid4().hex
    master_file, source_file = (uuid4() for _ in range(2))
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
    plan = plan_reference(filename,source,raw_record_id=rid,candidates=ReferenceCandidates([(master_raw,master)]))
    evidence=dict(batch_id=batch,archive_sha256='a'*64,confirmation_sha256='c'*64,source_system_code='POLICE_HR_IS',
        import_file_id=str(source_file),source_file_sha256=source_hash,source_row_number=1,
        master_import_file_id=str(master_file),master_file_sha256='b'*64,master_rows=1)
    payload=dict(plan=plan.payload,evidence=evidence)
    binding=ReferenceSourceBinding(rid,master_file,'b'*64,1,'c'*64,'0'*40)
    def candidate():
        return make_delivery(crypto,backup,payload,event_id=uuid4(),assertion_id=uuid4(),recorded_at=datetime.now(timezone.utc))
    return binding,payload,candidate


def delivery_counts(connection):
    return tuple(connection.execute(select(func.count()).select_from(table)).scalar_one() for table in (PREP,DONE,ASSERTION))


class RollbackLedger:
    """Checker-only adapter: SQL remains inside the outer rollback transaction."""
    def __init__(self, connection, kwargs, failure):
        self.connection, self.kwargs, self.failure = connection, kwargs, failure

    def interrupt(self, point):
        if self.failure == point:
            self.failure = None
            raise AutoReconnect("Injected lost acknowledgment")

    def prepare_once(self, proposed):
        with self.connection.begin_nested():
            saved = prepare_on_connection(self.connection, proposed, **self.kwargs)
        self.interrupt("after_prepare")
        return saved

    def completion_digest(self, event_id):
        return self.connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(event_id))).scalar_one_or_none()

    def complete_once(self, prepared):
        self.interrupt("before_receipt")
        with self.connection.begin_nested():
            digest = completion_on_connection(self.connection, prepared)
        self.interrupt("after_receipt")
        return digest


class InterruptedMongo:
    """Delegate to the real Mongo collection, injecting transport failures only."""
    def __init__(self, collection, failure):
        self.collection, self.failure = collection, failure
        self.name = collection.name

    def find_one(self, query):
        return self.collection.find_one(query)

    def insert_one(self, document):
        if self.failure == "before_mongo":
            self.failure = None
            raise AutoReconnect("Injected transport failure")
        result = self.collection.insert_one(document)
        if self.failure == "after_mongo":
            self.failure = None
            raise AutoReconnect("Injected lost Mongo acknowledgment")
        return result


def main():
    args=arguments(argparse.ArgumentParser(description=__doc__))
    settings=MigrationSettings()
    require((settings.host,settings.port,settings.user,settings.name)==('127.0.0.1',5432,'police_identity_migrator','police_identity'),'Unexpected SQL target.')
    engine=create_engine(URL.create('postgresql+psycopg',username=settings.user,password=settings.password.get_secret_value(),host=settings.host,port=settings.port,database=settings.name),
        poolclass=NullPool,hide_parameters=True,connect_args={'connect_timeout':5})
    baseline=None;cases=0
    try:
        root,*passwords=credentials(args)
        def research_counts():
            result={}
            for factory,password,collections in (*existing_readers(passwords[:-1]),(reference_client,passwords[-1],tuple(COLLECTION_POLICIES))):
                with factory(password) as reader:
                    result.update({name:reader[DATABASE][name].count_documents({}) for name in collections})
            return result
        mongo_before=research_counts()
        require(mongo_before==dict(EXISTING_COUNTS,**{name:0 for name in COLLECTION_POLICIES}),'Unexpected reconciled Mongo baseline.')
        sandbox='police_ref_delivery_'+uuid4().hex
        require(len(sandbox.encode())<64 and sandbox!=DATABASE,'Unsafe synthetic database name.')
        password=secrets.token_urlsafe(48)
        with client(root,bootstrap=True) as bootstrap:
            verify_existing(bootstrap[DATABASE]);verify_accounts(bootstrap[DATABASE],require_reference=True)
            for name in COLLECTION_POLICIES:verify_reference_collection(bootstrap[DATABASE],name)
            test=bootstrap[sandbox]
            try:
                for name in COLLECTION_POLICIES:
                    create_reference_collection(test,name);verify_reference_collection(test,name)
                test.command('createRole',ROLE,privileges=privileges(sandbox),roles=[])
                test.command('createUser','reference_delivery_smoke_app',pwd=password,roles=[{'role':ROLE,'db':sandbox}])
                with tempfile.TemporaryDirectory() as directory:
                    key=base64.b64encode(os.urandom(32)).decode()
                    material=dict(active_encryption_key_version='EPHEMERAL',active_lookup_key_version='EPHEMERAL',encryption_keys={'EPHEMERAL':key},lookup_keys={'EPHEMERAL':key})
                    paths=[Path(directory)/name for name in ('primary.json','backup.json')]
                    for path in paths:path.write_text(json.dumps(material));path.chmod(0o600)
                    crypto,backup=(IdentityCrypto(path) for path in paths)
                    with MongoClient('127.0.0.1',27018,username='reference_delivery_smoke_app',password=password,authSource=sandbox,
                        tz_aware=True,retryWrites=False,serverSelectionTimeoutMS=5000,socketTimeoutMS=10000) as smoke:
                        with engine.connect() as connection:
                            outer=connection.begin()
                            try:
                                connection.execute(text("SET LOCAL lock_timeout='5s'"));connection.execute(text("SET LOCAL statement_timeout='30s'"))
                                connection.execute(text('SELECT pg_advisory_xact_lock(:key)'),{'key':REGISTRATION_LOCK})
                                require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==['b40d8f62ac95'],'Unexpected applied reference revision.')
                                baseline=counts(connection)
                                require(all(baseline.get(name)==n for name,n in CHECKPOINT.items()),'Unexpected reconciled SQL baseline.')
                                delivery_baseline=delivery_counts(connection)
                                require(delivery_baseline==(0,0,0),'Recovery checker requires empty reference delivery tables.')
                                for filename in HEADERS:
                                    for failure in ('after_prepare','before_mongo','after_mongo','before_receipt','after_receipt'):
                                        case=connection.begin_nested()
                                        try:
                                            binding,payload,candidate=fixture(connection,crypto,backup,filename)
                                            kwargs=dict(crypto=crypto,backup=backup,binding=binding,expected_payload=payload)
                                            ledger=RollbackLedger(connection,kwargs,failure)
                                            collection=InterruptedMongo(smoke[sandbox][collection_for(payload)],failure)
                                            delivery_args=dict(crypto=crypto,backup=backup,expected_payload=payload)
                                            try:deliver(ledger,collection,candidate(),**delivery_args)
                                            except AutoReconnect:pass
                                            else:raise RuntimeError('Failure injection did not interrupt delivery.')
                                            committed=connection.execute(select(PREP).where(PREP.c.raw_record_id==binding.raw_record_id)).mappings().one()
                                            exact_bytes=bytes(committed['document_bson'])
                                            try:reconcile(ledger,collection,prepare_on_connection(connection,candidate(),**kwargs),**delivery_args)
                                            except ValueError:
                                                require(failure!='after_receipt','Completed evidence failed reconciliation.')
                                            else:require(failure=='after_receipt','Reconciliation unexpectedly completed pending evidence.')
                                            deliver(ledger,collection,candidate(),**delivery_args)
                                            saved=prepare_on_connection(connection,candidate(),**kwargs)
                                            require(saved.document_bson==exact_bytes,'Retry regenerated committed BSON.')
                                            require(reconcile(ledger,collection,saved,**delivery_args)=='VERIFIED_EXISTING','Driver reconciliation differs.')
                                            require(deliver(ledger,collection,candidate(),**delivery_args)=='VERIFIED_EXISTING','Driver replay differs.')
                                            require(smoke[sandbox][collection_for(payload)].count_documents({'raw_record_id':binding.raw_record_id})==1,'Mongo fixture duplicated.')
                                            require(connection.execute(select(DONE.c.delivery_id).where(DONE.c.delivery_id==UUID(saved.document()['_id']))).scalar_one() is not None,'SQL completion missing.')
                                            cases+=1
                                        finally:case.rollback()
                                        require(counts(connection)==baseline and delivery_counts(connection)==delivery_baseline,'Case rollback retained SQL rows.')
                            finally:outer.rollback()
                        with engine.connect() as connection:
                            require(counts(connection)==baseline and delivery_counts(connection)==delivery_baseline,'Final rollback retained SQL rows.')
                            require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==['b40d8f62ac95'],'Applied revision changed.')
            finally:
                # The random namespace contains synthetic fixtures only.
                if sandbox.startswith('police_ref_delivery_') and sandbox!=DATABASE:
                    test.command('dropAllUsersFromDatabase',1);test.command('dropAllRolesFromDatabase',1)
                    bootstrap.drop_database(sandbox)
        require(research_counts()==mongo_before,'Research Mongo counts changed.')
        print('Reference driver recovery checks: PASSED | interruption cases=',cases)
        print('Exact encrypted replay and SQL/Mongo reconciliation verified using real drivers.')
        print('SQL test transactions rolled back; isolated synthetic Mongo database removed.')
        print('Research counts and applied revision unchanged; no production encryption keys used.')
        print('Production adapter uses fresh-connection commit recovery; actual imports remain pending.')
        return 0
    except Exception as error:
        print('Reference driver recovery check stopped:',type(error).__name__)
        if type(error) in (RuntimeError,ValueError):print(str(error))
        print('Stop before reference import; inspect failure without sharing credentials or source values.')
        return 1
    finally:engine.dispose()


if __name__=='__main__':raise SystemExit(main())
