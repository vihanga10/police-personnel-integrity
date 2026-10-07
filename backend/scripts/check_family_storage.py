"""Rollback-only family encryption checks; no Mongo connection or production keys.

Run at e17a5c39df62 before applying f28b6d40ea73. Only opaque existing FK anchors are read;
all newly inserted names, dates and signatures are ephemeral synthetic fixtures.
"""
import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BACKEND))
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import URL, create_engine, inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import SourceAssertion, OfficerFamilyRelation, OfficerFamilyCivilEventVersion, OfficerNextOfKinVersion, SourceAttestation
from app.staging.models import RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from migration_settings import MigrationSettings

REVISION = 'e17a5c39df62'
MIGRATION = 'f28b6d40ea73_encrypt_empty_family_destinations.py'
MODELS = {m.__tablename__:m for m in (OfficerFamilyCivilEventVersion,OfficerNextOfKinVersion,SourceAttestation)}
IDS = {
    'officer_family_civil_event_version':('civil_event_version_id','civil_event_chain_uid','supersedes_civil_event_version_id'),
    'officer_next_of_kin_version':('next_of_kin_version_id','next_of_kin_chain_uid','supersedes_next_of_kin_version_id'),
    'source_attestation':('attestation_version_id','attestation_chain_uid','supersedes_attestation_version_id'),
}


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def counts(connection):
    # Count every registered identity/staging table, without querying any values.
    names = sorted(set(Base.metadata.tables) | set(StagingBase.metadata.tables))
    return {name:connection.execute(text('SELECT count(*) FROM '+name)).scalar_one() for name in names}


def context(table,row):
    primary,chain,_ = IDS[table]
    # Test-only AAD binds routing and opaque identity; no production writer claim.
    return json.dumps(['FAMILY_STORAGE_CHECK_V1',table,str(row[primary]),str(row[chain]),
        str(row['source_assertion_id']),str(row.get('officer_uid')),str(row.get('family_relation_version_id'))],separators=(',',':'))


def fixture(table,owner,assertion,relation,crypto):
    """Prepare synthetic claims solely for the rollback exercise."""
    primary,chain,_ = IDS[table]
    row = {primary:uuid4(),chain:uuid4(), 'source_assertion_id':assertion,
        'version_number':1,'transaction_start':datetime.now(timezone.utc),
        'record_state':'ACTIVE' if table=='source_attestation' else 'ASSERTED'}
    if table=='source_attestation':
        row.update(attestation_type='RECORDED_BY',actor_officer_uid=None,resolution_status='UNRESOLVED')
    else:
        row.update(officer_uid=owner,family_relation_version_id=relation)
    payload = dict(synthetic=True,event_type='MARRIAGE',reported_date='2026-01-02',
        related_person_name='Synthetic Relative',relationship='Reported relative',
        actor_rank='Reported rank',signature_reference='Synthetic signature',
        valid_from=None,valid_to=None,authority_result=None)
    cipher,key = crypto.encrypt_assertion(payload,context=context(table,row))
    row.update(profile_payload_ciphertext=cipher,encryption_key_version=key)
    return row,payload


def main():
    engine = None
    checks = 0
    baseline = None
    try:
        settings = MigrationSettings()
        require((settings.host,settings.port,settings.user,settings.name) ==
            ('127.0.0.1',5432,'police_identity_migrator','police_identity'),'Unexpected migration target.')
        engine = create_engine(URL.create('postgresql+psycopg',username=settings.user,
            password=settings.password.get_secret_value(),host=settings.host,port=settings.port,database=settings.name),
            poolclass=NullPool,hide_parameters=True,connect_args={'connect_timeout':5})
        path = BACKEND/'migrations/versions'/MIGRATION
        spec = importlib.util.spec_from_file_location('family_storage_check_migration',path)
        migration = importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(os.urandom(32)).decode()
            material = dict(active_encryption_key_version='EPHEMERAL',active_lookup_key_version='EPHEMERAL',
                encryption_keys={'EPHEMERAL':key},lookup_keys={'EPHEMERAL':key})
            paths = [Path(directory)/name for name in ('primary.json','backup.json')]
            for path in paths:
                path.write_text(json.dumps(material));path.chmod(0o600)
            crypto,backup = (IdentityCrypto(path) for path in paths)
            with engine.connect() as connection:
                outer = connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text('SELECT pg_advisory_xact_lock(:key)'),{'key':REGISTRATION_LOCK})
                    require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==[REVISION],
                        'Run before the family encryption upgrade.')
                    baseline = counts(connection)
                    for name,expected in {'identity.officer':6596,'identity.officer_identifier_version':23966,
                        'identity.source_assertion':147327,'identity.remaining_source_assertion':36694,
                        'staging.remaining_delivery_preparation':36694,'staging.remaining_delivery_completion':36694,
                        'identity.source_assertion_classification':0,'identity.officer_family_relation':6596}.items():
                        require(baseline[name]==expected,'Unexpected verified import baseline.')
                    for table in MODELS:require(baseline['identity.'+table]==0,'Family encryption requires empty targets.')
                    # Opaque existing anchors only: no personnel decryption or source value reads.
                    assertion,owner = connection.execute(select(SourceAssertion.source_assertion_id,SourceAssertion.officer_uid).limit(1)).one()
                    relation = uuid4()
                    relation_payload = {'synthetic':True,'related_person_name':'Synthetic Spouse'}
                    cipher,version = crypto.encrypt_assertion(relation_payload,context='SYNTHETIC_RELATION_'+str(relation))
                    connection.execute(OfficerFamilyRelation.__table__.insert().values(family_relation_version_id=relation,
                        relation_chain_uid=uuid4(),officer_uid=owner,source_assertion_id=assertion,relationship_type='SPOUSE',
                        version_number=1,profile_payload_ciphertext=cipher,encryption_key_version=version))

                    def rejected(action, state):
                        nonlocal checks
                        savepoint = connection.begin_nested()
                        try:
                            action()
                        except DBAPIError as error:
                            require(getattr(error.orig,'sqlstate',None)==state,'Unexpected database rejection type.')
                            checks += 1
                        else: raise RuntimeError('Invalid family operation was accepted.')
                        finally: savepoint.rollback()

                    def upgrade():
                        with Operations.context(MigrationContext.configure(connection)): migration.upgrade()

                    # Verify refusal for each nonempty OLD destination before conversion.
                    legacy = {
                        'officer_family_civil_event_version':dict(civil_event_version_id=uuid4(),civil_event_chain_uid=uuid4(),
                            officer_uid=owner,family_relation_version_id=relation,source_assertion_id=assertion,
                            event_type='MARRIAGE',event_date='2026-01-02',version_number=1),
                        'officer_next_of_kin_version':dict(next_of_kin_version_id=uuid4(),next_of_kin_chain_uid=uuid4(),
                            officer_uid=owner,source_assertion_id=assertion,related_person_name='Synthetic Relative',
                            relationship_type='OTHER',version_number=1),
                        'source_attestation':dict(attestation_version_id=uuid4(),attestation_chain_uid=uuid4(),
                            source_assertion_id=assertion,attestation_type='RECORDED_BY',actor_rank_asserted='Synthetic rank',version_number=1),
                    }
                    for table,row in legacy.items():
                        def populated_upgrade(table=table,row=row):
                            columns=','.join(row);parameters=','.join(':'+k for k in row)
                            connection.execute(text(f'INSERT INTO identity.{table} ({columns}) VALUES ({parameters})'),row)
                            upgrade()
                        rejected(populated_upgrade,'P0001')
                    upgrade();checks += 1
                    ctx=MigrationContext.configure(connection,opts={'include_schemas':True,'compare_type':True,
                        'include_object':lambda obj,name,kind,reflected,other: kind!='table' or
                            (obj.schema in {'identity','staging'} and name!='alembic_version')})
                    require(not compare_metadata(ctx,[Base.metadata,StagingBase.metadata]),'Schema/model differences detected.');checks += 1
                    inspector=inspect(connection)
                    for table,model in MODELS.items():
                        mapped=model.__table__
                        require({c['name'] for c in inspector.get_columns(table,schema='identity')}==set(mapped.c.keys()),'Family columns differ.');checks += 1
                        expected={connection.dialect.identifier_preparer.format_constraint(c).strip('"') for c in mapped.constraints if c.__class__.__name__=='CheckConstraint'}
                        require({c['name'] for c in inspector.get_check_constraints(table,schema='identity')}==expected,'Family constraints differ.');checks += 1
                        triggers=set(connection.execute(text("""SELECT t.tgname FROM pg_trigger t
                            JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
                            WHERE n.nspname='identity' AND c.relname=:table AND NOT t.tgisinternal"""),{'table':table}).scalars())
                        require({'guard_version_insert','guard_evidence_update','protect_family_delete','protect_family_truncate'}.issubset(triggers),'Family preservation triggers missing.');checks += 1
                        for privilege,allowed in (('SELECT',True),('INSERT',True),('DELETE',False),('TRUNCATE',False)):
                            require(connection.execute(text("SELECT has_table_privilege('police_identity_app',:table,:privilege)"),
                                {'table':'identity.'+table,'privilege':privilege}).scalar_one() is allowed,'Family application permissions differ.');checks += 1
                        require(not connection.execute(text("SELECT has_column_privilege('police_identity_app',:table,'profile_payload_ciphertext','UPDATE')"),
                            {'table':'identity.'+table}).scalar_one(),'Application can overwrite family payload.');checks += 1
                        primary,chain,previous=IDS[table]
                        row,payload=fixture(table,owner,assertion,relation,crypto)
                        # Exercise storage guards as migrator; app permissions are checked above.
                        connection.execute(mapped.insert().values(**row))
                        checks += 1
                        saved=connection.execute(select(mapped).where(mapped.c[primary]==row[primary])).mappings().one()
                        for copy in (crypto,backup):
                            require(copy.decrypt_assertion(saved['profile_payload_ciphertext'],key_version=saved['encryption_key_version'],
                                context=context(table,saved))==payload,'Family encrypted recovery differs.');checks += 1
                        for changes,state in (({'profile_payload_ciphertext':b'x'*28},'23514'),({'encryption_key_version':''},'23514'),
                            ({'profile_payload_ciphertext':None},'23502'),({'version_number':2},'P0001')):
                            changed=dict(row,**changes);changed[primary]=uuid4();changed[chain]=uuid4()
                            rejected(lambda changed=changed:connection.execute(mapped.insert().values(**changed)),state)
                        for statement in (f"UPDATE identity.{table} SET record_state=record_state WHERE {primary}=:id",
                            f"UPDATE identity.{table} SET profile_payload_ciphertext=profile_payload_ciphertext WHERE {primary}=:id",
                            f"DELETE FROM identity.{table} WHERE {primary}=:id",f"TRUNCATE identity.{table}"):
                            rejected(lambda statement=statement:connection.execute(text(statement),{'id':row[primary]}),'P0001')
                        if table!='source_attestation':
                            other=connection.execute(select(OfficerFamilyRelation.family_relation_version_id).where(OfficerFamilyRelation.officer_uid!=owner).limit(1)).scalar_one()
                            changed=dict(row,family_relation_version_id=other);changed[primary]=uuid4();changed[chain]=uuid4()
                            rejected(lambda changed=changed:connection.execute(mapped.insert().values(**changed)),'P0001')
                        if table=='officer_next_of_kin_version':
                            changed=dict(row,valid_from=datetime(2026,1,1).date());changed[primary]=uuid4();changed[chain]=uuid4()
                            rejected(lambda:connection.execute(mapped.insert().values(**changed)),'23514')
                        # Preserve valid one-time closure + immediately following replacement.
                        end=row['transaction_start']+timedelta(seconds=1)
                        connection.execute(mapped.update().where(mapped.c[primary]==row[primary]).values(transaction_end=end,record_state='SUPERSEDED'))
                        checks += 1
                        replacement=dict(row);replacement[primary]=uuid4();replacement[previous]=row[primary]
                        replacement.update(version_number=2,transaction_start=end)
                        replacement['profile_payload_ciphertext'],replacement['encryption_key_version']=crypto.encrypt_assertion(payload,context=context(table,replacement))
                        connection.execute(mapped.insert().values(**replacement));checks += 1
                        rejected(lambda:connection.execute(mapped.update().where(mapped.c[primary]==row[primary]).values(transaction_end=end+timedelta(seconds=1))),'P0001')
                    print('Transactional family storage checks: PASSED | checks=',checks)
                finally:outer.rollback()
            with engine.connect() as connection:
                require(counts(connection)==baseline,'Rollback did not preserve research counts.')
                require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all()==[REVISION],'Applied revision changed.')
                inspector=inspect(connection)
                for table,rule in migration.SPEC.items():
                    columns={c['name'] for c in inspector.get_columns(table,schema='identity')}
                    require(set(rule['columns']).issubset(columns) and 'profile_payload_ciphertext' not in columns,'Original family schema not restored.')
                require(connection.execute(text("SELECT to_regprocedure('identity.guard_family_relation_owner()')")).scalar_one() is None,'Rollback retained family function.')
                print('Rollback verified: original family schema restored; no test rows retained.')
                print('Applied revision remains:',REVISION)
                print('No Mongo connection or personnel values; only ephemeral test keys used.')
                print('Application privileges inspected; fixtures used migrator, not application login.')
                print('Family writer, import and authenticated application access remain pending.')
        return 0
    except Exception as error:
        print('Family storage check stopped:',type(error).__name__)
        if isinstance(error,DBAPIError):
            print('SQL state:',getattr(error.orig,'sqlstate',None))
            print('Constraint:',getattr(getattr(error.orig,'diag',None),'constraint_name',None))
        elif isinstance(error,RuntimeError):print(str(error))
        print('No commit requested. Review before applying the family upgrade.')
        return 1
    finally:
        if engine is not None:engine.dispose()


if __name__=='__main__':raise SystemExit(main())
