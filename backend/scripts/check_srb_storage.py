"""Exercise SRB SQL storage inside one transaction and always roll it back.

Run before applying c95e3a17bd40. No Mongo connection or production keys are used.
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
from sqlalchemy import URL, create_engine, func, insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import (Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem,
    SourceAssertionClassification, ProfileTransformReceipt, ServiceDeliveryPreparation, ServiceDeliveryCompletion,
    HistoryDeliveryPreparation, HistoryDeliveryCompletion, SrbDeliveryPreparation, SrbDeliveryCompletion)
from app.staging.identity_decision import IdentityRegistrationDecision
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.srb_plan import ROUTES, plan_srb, SourceReference, DESTINATIONS
from app.identity.srb_plan_crypto import seal_srb_plan, open_srb_plan
from app.identity.normalization import NORMALIZATION_PROFILE, normalize_identifier
from app.identity.registration_service import REGISTRATION_LOCK, evidence_context
from app.intake.staging_rows import seal_row
from app.security.identity_crypto import IdentityCrypto
from app.storage.srb_mongo_contract import COLLECTION_POLICIES, encryption_context
from migration_settings import MigrationSettings

REVISION = 'b84d2f06ac39'
TABLES = ('staging.srb_delivery_preparation', 'staging.srb_delivery_completion')
BASELINE_MODELS = (Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem, ProfileTransformReceipt,
                   ServiceDeliveryPreparation, ServiceDeliveryCompletion, SourceAssertionClassification, HistoryDeliveryPreparation, HistoryDeliveryCompletion, RawRecord)


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def counts(connection):
    return tuple(connection.execute(select(func.count()).select_from(m.__table__)).scalar_one() for m in BASELINE_MODELS)


def fixture(connection, crypto, backup, filename):
    """Create unrelated source/NIC/officer fixtures entirely inside the rollback."""
    officer, nic_assertion, identifier, file_id, assertion_id, delivery_id = (uuid4() for _ in range(6))
    batch = 'HISTORY-SMOKE-' + uuid4().hex
    row = dict.fromkeys(ROUTES[filename], '')
    row.update(officer_nic_no='ROLLBACK-NIC-' + uuid4().hex)
    collection = DESTINATIONS[filename].split('.', 1)[1]
    if filename == 'officer_police_numbers.csv':
        row.update(police_no='00012', number_type='ROLLBACK-TYPE', valid_from='2020-01-01', valid_to='not a date')
    elif filename == 'officer_restrictions.csv':
        row.update(restriction_id='ROLLBACK-RESTRICTION', restriction_start_date='2020-01-01',
            restriction_record_date='2020-01-02', restriction_verifiable='TRUE', override_recorded='FALSE')
    else:
        row.update(override_id='ROLLBACK-OVERRIDE', restriction_id='ROLLBACK-RESTRICTION', transfer_id='ROLLBACK-TRANSFER',
            override_reference='ROLLBACK-DOC', override_ground='Reported ground', override_reason='Preserve original',
            override_authority_nic='ROLLBACK-ACTOR', override_authority_rank='Assistant Superintendent of Police', override_date='2020-02-01')
    sealed = seal_row(crypto, batch_id=batch, archive_path=filename, source_file_sha256='b'*64,
                      source_row_number=1, columns=list(row), values=list(row.values()))
    connection.execute(insert(IntakeBatch.__table__).values(batch_id=batch, archive_sha256='a'*64, archive_size_bytes=1,
        expected_file_count=1, registration_receipt_id=uuid4(), registration_receipt_sha256='d'*64, schema_version='1.0'))
    connection.execute(insert(IntakeFile.__table__).values(import_file_id=file_id, batch_id=batch, archive_path=filename,
        source_file_sha256='b'*64, size_bytes=1, expected_row_count=1, column_count=len(row), columns=list(row),
        declared_encoding='UTF-8', delimiter=','))
    connection.execute(insert(RawRecord.__table__).values(**asdict(sealed), import_file_id=file_id))
    connection.execute(insert(Officer.__table__).values(officer_uid=officer, registry_state='REGISTERED'))
    source_id = connection.execute(select(SourceSystem.source_system_id).where(SourceSystem.source_system_code == 'SRB')).scalar_one_or_none()
    if source_id is None:
        # Test-only source registration rolls back with every fixture and DDL change.
        source_id = uuid4()
        connection.execute(insert(SourceSystem.__table__).values(source_system_id=source_id,
            source_system_code='SRB', source_name='Rollback-only SRB fixture', is_active=True))
    nic = normalize_identifier(row['officer_nic_no'], identifier_type='NIC')
    claim = dict(schema_version='1.0', source_column='officer_nic_no', reported_value=row['officer_nic_no'],
                 normalized_value=nic.value, identifier_type='NIC', normalization_profile=NORMALIZATION_PROFILE,
                 raw_record_id=sealed.raw_record_id, source_confirmation_sha256='c'*64)
    cipher, version = crypto.encrypt_assertion(claim, context=evidence_context('ASSERTION', nic_assertion))
    provenance = dict(officer_uid=officer, source_system_id=source_id, intake_batch_id=batch, import_file_id=str(file_id),
        raw_record_id=sealed.raw_record_id, source_file_name=filename, source_file_sha256='b'*64,
        source_row_number=1, assertion_state='ACTIVE', independence_status='UNVERIFIED')
    connection.execute(insert(SourceAssertion.__table__).values(**provenance, source_assertion_id=nic_assertion,
        assertion_type='IDENTIFIER_NIC', asserted_value_ciphertext=cipher, encryption_key_version=version))
    cipher, version = crypto.encrypt(nic.value.encode(), context=evidence_context('IDENTIFIER', identifier))
    digest, lookup = crypto.lookup_hmac(nic.value, identifier_type='NIC')
    connection.execute(insert(OfficerIdentifierVersion.__table__).values(identifier_version_id=identifier,
        identifier_chain_uid=uuid4(), officer_uid=officer, source_assertion_id=nic_assertion, identifier_type='NIC',
        identifier_value_ciphertext=cipher, identifier_lookup_hmac=digest, normalization_profile=NORMALIZATION_PROFILE,
        encryption_key_version=version, lookup_key_version=lookup, version_number=1, record_state='ASSERTED'))
    refs = {'restriction_id': (SourceReference('officer_restrictions.csv', 'e' * 64, officer),),
            'transfer_id': (SourceReference('transfer_history.csv', 'f' * 64, officer),)}
    plan = plan_srb(filename, row, officer_uid=officer, station_candidates={},
        actor_candidates={'override_authority_nic': officer}, reference_candidates=refs)
    cipher, version = seal_srb_plan(crypto, plan, raw_record_id=sealed.raw_record_id, reference_evidence={'synthetic': True})
    payload = open_srb_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=officer, raw_record_id=sealed.raw_record_id)
    recorded = datetime.now(timezone.utc)
    recorded = recorded.replace(microsecond=recorded.microsecond // 1000 * 1000)
    doc = dict(_id=str(delivery_id), officer_uid=str(officer), source_assertion_uid=str(assertion_id),
        raw_record_id=sealed.raw_record_id, writer_policy=COLLECTION_POLICIES[collection], schema_version=1,
        classification='UNASSESSED', recorded_at=recorded, payload_key_version=crypto.active_encryption_version)
    cipher, version = crypto.encrypt_assertion(payload, context=encryption_context(collection, doc))
    doc['payload_ciphertext'] = Binary(cipher)
    encoded = bytes(BSON.encode(doc))
    assertion = dict(provenance, source_assertion_id=assertion_id,
        assertion_type={'police_number_intervals': 'SRB_POLICE_NUMBER_EVIDENCE', 'restriction_records': 'SRB_RESTRICTION_EVIDENCE', 'restriction_overrides': 'SRB_OVERRIDE_EVIDENCE'}[collection],
        asserted_value_ciphertext=cipher, encryption_key_version=version, transaction_start=recorded)
    reviews = sum(f.status == 'REVIEW_REQUIRED' for f in plan.fields)
    preparation = dict(delivery_id=delivery_id, raw_record_id=sealed.raw_record_id, officer_uid=officer,
        source_assertion_id=assertion_id, identifier_version_id=identifier, confirmation_sha256='c'*64,
        code_revision='0'*40, source_file_name=filename, mongo_collection=collection, field_review_count=reviews,
        row_review_count=len(plan.review_issues), review_state='STRUCTURAL_REVIEW_REQUIRED' if plan.needs_review else 'NO_STRUCTURAL_REVIEW', writer_policy=doc['writer_policy'],
        linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH', historical_eligibility='UNASSESSED',
        document_bson=encoded, document_sha256=hashlib.sha256(encoded).hexdigest(), recorded_at=recorded)
    return assertion, preparation, payload


def main():
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) == ('127.0.0.1', 5432, 'police_identity_migrator', 'police_identity'),
            'Unexpected migration target.')
    engine = create_engine(URL.create('postgresql+psycopg', username=settings.user, password=settings.password.get_secret_value(),
        host=settings.host, port=settings.port, database=settings.name), poolclass=NullPool, hide_parameters=True,
        connect_args={'connect_timeout': 5})
    path = BACKEND / 'migrations/versions/c95e3a17bd40_add_srb_delivery_storage.py'
    spec = importlib.util.spec_from_file_location('srb_storage_check_migration', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    checks = 0
    try:
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(os.urandom(32)).decode()
            material = dict(active_encryption_key_version='EPHEMERAL', active_lookup_key_version='EPHEMERAL',
                            encryption_keys={'EPHEMERAL': key}, lookup_keys={'EPHEMERAL': key})
            paths = [Path(directory) / n for n in ('primary.json', 'backup.json')]
            for key_path in paths:
                key_path.write_text(json.dumps(material))
                key_path.chmod(0o600)
            crypto, backup = (IdentityCrypto(p) for p in paths)
            with engine.connect() as connection:
                outer = connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': REGISTRATION_LOCK})
                    require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all() == [REVISION], 'Unexpected applied revision.')
                    for table in TABLES:
                        require(connection.execute(text('SELECT to_regclass(:table)'), {'table': table}).scalar_one() is None, 'Run this checker before the SRB upgrade.')
                    baseline = counts(connection)
                    require(baseline[:10] == (6596, 23966, 84448, 2, 6596, 6596, 6596, 0, 47290, 47290), 'Unexpected reconciled research counts.')
                    with Operations.context(MigrationContext.configure(connection)):
                        migration.upgrade()
                    checks += 1
                    context = MigrationContext.configure(connection, opts={'include_schemas': True, 'compare_type': True,
                        'version_table': 'alembic_version', 'version_table_schema': 'identity',
                        'include_object': lambda obj, name, kind, reflected, other: kind != 'table' or obj.schema in {'identity', 'staging'}})
                    require(not compare_metadata(context, [Base.metadata, StagingBase.metadata]), 'Schema/model differences detected.')
                    checks += 1
                    for table in TABLES:
                        for privilege, allowed in (('SELECT', True), ('INSERT', True), ('UPDATE', False), ('DELETE', False), ('TRUNCATE', False), ('REFERENCES', False), ('TRIGGER', False)):
                            actual = connection.execute(text("SELECT has_table_privilege('police_identity_app', :table, :privilege)"), {'table': table, 'privilege': privilege}).scalar_one()
                            require(actual is allowed, 'Unexpected application SRB-storage permissions.')
                            checks += 1
                    def rejected(action, state):
                        nonlocal checks
                        savepoint = connection.begin_nested()
                        try:
                            action()
                        except DBAPIError as error:
                            require(getattr(error.orig, 'sqlstate', None) == state, 'Unexpected SQL rejection type.')
                            checks += 1
                        else:
                            raise RuntimeError('Prohibited SQL operation was accepted.')
                        finally:
                            savepoint.rollback()
                    preparation_table = SrbDeliveryPreparation.__table__
                    completion_table = SrbDeliveryCompletion.__table__
                    for filename in ROUTES:
                        assertion, prep, payload = fixture(connection, crypto, backup, filename)
                        before = counts(connection)
                        def failed_pair():
                            connection.execute(insert(SourceAssertion.__table__).values(**assertion))
                            connection.execute(insert(preparation_table).values(**dict(prep, document_sha256='0'*64)))
                        # Failure after assertion insert must roll back the entire pair.
                        rejected(failed_pair, '23514')
                        require(counts(connection) == before, 'Failed preparation retained its source assertion.')
                        checks += 1
                        connection.execute(insert(SourceAssertion.__table__).values(**assertion))
                        connection.execute(insert(preparation_table).values(**prep))
                        saved = connection.execute(select(preparation_table).where(preparation_table.c.delivery_id == prep['delivery_id'])).mappings().one()
                        require(bytes(saved['document_bson']) == prep['document_bson'], 'Stored exact BSON differs.')
                        document = BSON(bytes(saved['document_bson'])).decode(codec_options=CodecOptions(tz_aware=True))
                        binding = dict(key_version=document['payload_key_version'], context=encryption_context(prep['mongo_collection'], document))
                        for key_copy in (crypto, backup):
                            require(key_copy.decrypt_assertion(bytes(document['payload_ciphertext']), **binding) == payload, 'SRB recovery differs.')
                        checks += 3
                        expected_reviews = 1 if filename == 'officer_police_numbers.csv' else 0
                        require(saved['field_review_count'] == expected_reviews and saved['row_review_count'] == 0, 'Review metadata was lost.')
                        fields = {f['source_column']: f for f in payload['fields']}
                        if expected_reviews:
                            require(fields['police_no']['source_value'] == '00012' and fields['police_no']['value'] == '00012', 'Leading zeros changed.')
                            require(fields['valid_to']['source_value'] == 'not a date' and fields['valid_to']['value'] is None, 'Unsupported end date was changed.')
                        require(payload['authority_result'] is None and payload['authority_assessment'] == 'NOT_RUN' and payload['reconstructed_state'] is None, 'Unassessed state was lost.')
                        checks += 1
                        for changes, state in (({'officer_uid': uuid4()}, 'P0001'),
                            ({'document_bson': prep['document_bson'] + b'x'}, '23514'),
                            ({'mongo_collection': 'service_status_events'}, '23514'),
                            ({'review_state': 'INVALID'}, '23514'), ({'field_review_count': -1}, '23514'),
                            ({'row_review_count': -1}, '23514'), ({'field_review_count': 25}, '23514'), ({}, '23505')):
                            changed = dict(prep, delivery_id=uuid4(), **changes)
                            rejected(lambda changed=changed: connection.execute(insert(preparation_table).values(**changed)), state)
                        receipt = dict(delivery_id=prep['delivery_id'], document_sha256=prep['document_sha256'])
                        rejected(lambda: connection.execute(insert(completion_table).values(**dict(receipt, document_sha256='0'*64))), 'P0001')
                        rejected(lambda: connection.execute(insert(completion_table).values(**dict(receipt, delivery_id=uuid4()))), 'P0001')
                        rejected(lambda: connection.execute(insert(completion_table).values(**receipt, recorded_at=prep['recorded_at']-timedelta(days=1))), 'P0001')
                        connection.execute(insert(completion_table).values(**receipt))
                        require(connection.execute(select(completion_table.c.document_sha256).where(completion_table.c.delivery_id == prep['delivery_id'])).scalar_one() == prep['document_sha256'], 'Receipt digest differs.')
                        checks += 1
                        rejected(lambda: connection.execute(insert(completion_table).values(**receipt)), '23505')
                    for table in TABLES:
                        for statement in (f'UPDATE {table} SET recorded_at=recorded_at', f'DELETE FROM {table}'):
                            rejected(lambda statement=statement: connection.execute(text(statement)), 'P0001')
                    rejected(lambda: connection.execute(text('TRUNCATE staging.srb_delivery_preparation, staging.srb_delivery_completion')), 'P0001')
                    rejected(lambda: connection.execute(text('TRUNCATE staging.srb_delivery_completion')), 'P0001')
                    print('Transactional SRB storage checks: PASSED | checks=', checks)
                finally:
                    # DDL and all fixture rows must disappear, even after any failure.
                    outer.rollback()
            with engine.connect() as connection:
                require(counts(connection) == baseline, 'Research counts changed after rollback.')
                require(connection.execute(text('SELECT version_num FROM identity.alembic_version')).scalars().all() == [REVISION], 'Applied revision changed.')
                for table in TABLES:
                    require(connection.execute(text('SELECT to_regclass(:table)'), {'table': table}).scalar_one() is None, 'SRB table survived rollback.')
                for function in ('guard_srb_preparation_insert', 'guard_srb_completion_insert', 'reject_srb_delivery_mutation'):
                    require(connection.execute(text('SELECT to_regprocedure(:name)'), {'name': 'identity.'+function+'()'}).scalar_one() is None, 'SRB function survived rollback.')
            print('Rollback verified: SRB tables, functions and test rows were not retained.')
            print('Applied revision remains:', REVISION)
            print('No Mongo connection; no personnel values displayed; only ephemeral test keys used.')
        return 0
    except Exception as error:
        print('SRB storage check stopped:', type(error).__name__)
        if isinstance(error, RuntimeError):
            print(str(error))
        if isinstance(error, DBAPIError):
            print('SQL state:', getattr(error.orig, 'sqlstate', None))
            print('Constraint:', getattr(getattr(error.orig, 'diag', None), 'constraint_name', None))
        print('No commit requested. Stop before applying the SRB migration or importing evidence.')
        return 1
    finally:
        engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
