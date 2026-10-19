"""PostgreSQL station reference delivery with independent staged-source recovery.

Completion is internal to the coordinated protocol, after exact Mongo readback.
No officer assignment, human access grant or accepted station mapping is created.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re
from uuid import UUID
from sqlalchemy import Engine, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.identity.reference_delivery import PreparedDelivery, verify_delivery, encryption_context, check_payload, collection_for
from app.identity.reference_plan import ReferenceCandidates, plan_reference
from app.identity.station_vocabulary import HEADERS, MASTER
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.models import SourceSystem
from app.models.reference_delivery_storage import ReferenceSourceAssertion, ReferenceDeliveryPreparation, ReferenceDeliveryCompletion
from app.staging.models import RawRecord, IntakeFile, IntakeBatch

PREP=ReferenceDeliveryPreparation.__table__
DONE=ReferenceDeliveryCompletion.__table__
ASSERTION=ReferenceSourceAssertion.__table__
ASSERTION_TYPES={'station_master.csv':'HR_STATION_REFERENCE_EVIDENCE',
    'sri_lanka_police_stations_sinhala.csv':'HR_STATION_SINHALA_REFERENCE_EVIDENCE'}


@dataclass(frozen=True)
class ReferenceSourceBinding:
    raw_record_id: str
    master_import_file_id: UUID
    master_file_sha256: str
    master_rows: int
    confirmation_sha256: str
    code_revision: str

    def validate(self):
        for value,size in ((self.raw_record_id,64),(self.master_file_sha256,64),
            (self.confirmation_sha256,64),(self.code_revision,40)):
            if not isinstance(value,str) or re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is None:
                raise ValueError('Invalid reference source fingerprint.')
        if not isinstance(self.master_import_file_id,UUID) or type(self.master_rows) is not int or self.master_rows<=0:
            raise ValueError('Invalid registered master snapshot binding.')


def recovered_row(crypto,backup,raw,file,filename):
    """Verify every cell and both encryption-key copies, preserving original text."""
    if tuple(file['columns'])!=HEADERS[filename] or file['column_count']!=len(HEADERS[filename]) or any(raw[f]!=file[f] for f in ('batch_id','archive_path','source_file_sha256','import_file_id')):
        raise ValueError('Reference source header or file binding differs.')
    original=open_row(crypto,stored_row(raw))
    if original['columns']!=file['columns'] or open_row(backup,stored_row(raw))!=original:
        raise ValueError('Reference staged recovery differs.')
    return dict(zip(original['columns'],original['values'],strict=True))


def check_source(connection,crypto,backup,binding,document,expected):
    binding.validate();expected=check_payload(expected)
    plan,evidence=expected['plan'],expected['evidence']
    raw=connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id==binding.raw_record_id)).mappings().one()
    if document['raw_record_id']!=raw['raw_record_id'] or raw['archive_path'].rsplit('/',1)[-1]!=plan['filename']:
        raise ValueError('Wrong station reference source row.')
    file=connection.execute(select(IntakeFile.__table__).where(IntakeFile.import_file_id==raw['import_file_id'])).mappings().one()
    row=recovered_row(crypto,backup,raw,file,plan['filename'])
    if {f['source_column']:f['source_value'] for f in plan['fields']}!=row:
        raise ValueError('Planned original reference values differ from staging.')
    batch=connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id==raw['batch_id'])).mappings().one()
    master=connection.execute(select(IntakeFile.__table__).where(IntakeFile.import_file_id==binding.master_import_file_id)).mappings().one()
    if (master['batch_id'],master['archive_path'].rsplit('/',1)[-1],master['source_file_sha256'],master['expected_row_count'])!=(raw['batch_id'],MASTER,binding.master_file_sha256,binding.master_rows):
        raise ValueError('Registered master snapshot differs.')
    master_raw=connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id==binding.master_import_file_id).order_by(RawRecord.source_row_number)).mappings().all()
    if len(master_raw)!=binding.master_rows or [r['source_row_number'] for r in master_raw]!=list(range(1,binding.master_rows+1)):
        raise ValueError('Recovered master row coverage differs.')
    candidates=ReferenceCandidates([(r['raw_record_id'],recovered_row(crypto,backup,r,master,MASTER)) for r in master_raw])
    if plan['filename']==MASTER and raw['import_file_id']!=binding.master_import_file_id:
        raise ValueError('Master source differs from candidate snapshot.')
    rebuilt=plan_reference(plan['filename'],row,raw_record_id=raw['raw_record_id'],candidates=candidates)
    if rebuilt.payload!=plan:
        raise ValueError('Reference candidate or review evidence differs from recovered master.')
    source=dict(batch_id=raw['batch_id'],archive_sha256=batch['archive_sha256'],confirmation_sha256=binding.confirmation_sha256,
        source_system_code='POLICE_HR_IS',import_file_id=str(raw['import_file_id']),source_file_sha256=raw['source_file_sha256'],
        source_row_number=raw['source_row_number'],master_import_file_id=str(binding.master_import_file_id),
        master_file_sha256=binding.master_file_sha256,master_rows=binding.master_rows)
    if evidence!=source:raise ValueError('Reference source provenance differs.')
    return raw


def assert_saved(connection,saved,crypto,backup,binding,expected):
    prepared=PreparedDelivery(bytes(saved['document_bson']),saved['document_sha256'])
    document=verify_delivery(prepared,crypto,backup,expected)
    plan=expected['plan']
    identity=(saved['delivery_id'],saved['source_assertion_id'],saved['raw_record_id'],saved['writer_policy'],saved['recorded_at'],
        saved['confirmation_sha256'],saved['master_import_file_id'],saved['master_file_sha256'],saved['master_row_count'])
    wanted=(UUID(document['_id']),UUID(document['source_assertion_uid']),document['raw_record_id'],document['writer_policy'],document['recorded_at'],
        binding.confirmation_sha256,binding.master_import_file_id,binding.master_file_sha256,binding.master_rows)
    if identity!=wanted:raise ValueError('Saved reference preparation binding differs.')
    # The winning preparation retains its original code revision on later retries.
    if re.fullmatch('[0-9a-f]{40}',saved['code_revision']) is None:raise ValueError('Saved code revision differs.')
    field_reviews=sum(f['status']=='REVIEW_REQUIRED' for f in plan['fields']);row_reviews=len(plan['review_issues'])
    if (saved['source_file_name'],saved['mongo_collection'],saved['field_review_count'],saved['row_review_count'],saved['review_state'],saved['linkage_method'],saved['historical_eligibility'])!=(
        plan['filename'],collection_for(expected),field_reviews,row_reviews,'STRUCTURAL_REVIEW_REQUIRED' if field_reviews or row_reviews else 'NO_STRUCTURAL_REVIEW',
        'SOURCE_SCOPED_REFERENCE_CANDIDATES_UNASSESSED','UNASSESSED'):
        raise ValueError('Saved reference routing or review metadata differs.')
    raw=check_source(connection,crypto,backup,binding,document,expected)
    assertion=connection.execute(select(ASSERTION).where(ASSERTION.c.source_assertion_id==saved['source_assertion_id'])).mappings().one()
    source=connection.execute(select(SourceSystem.__table__).where(SourceSystem.source_system_id==assertion['source_system_id'])).mappings().one()
    if not source['is_active'] or source['source_system_code']!='POLICE_HR_IS':raise ValueError('Inactive or different reference supplying source.')
    wanted=dict(assertion_type=ASSERTION_TYPES[plan['filename']],raw_record_id=raw['raw_record_id'],intake_batch_id=raw['batch_id'],
        import_file_id=str(raw['import_file_id']),source_file_sha256=raw['source_file_sha256'],source_row_number=raw['source_row_number'],
        asserted_value_ciphertext=bytes(document['payload_ciphertext']),encryption_key_version=document['payload_key_version'],source_file_name=plan['filename'],
        assertion_state='ACTIVE',transaction_start=document['recorded_at'],independence_status='UNVERIFIED',classification='UNASSESSED')
    if any(assertion[k]!=v for k,v in wanted.items()) or any(assertion[f] is not None for f in ('valid_from','valid_to','transaction_end','source_recorded_at','captured_at','source_record_id','source_document_id','source_page')):
        raise ValueError('Saved reference assertion differs.')
    # Exact ciphertext equality above binds assertion recovery to the dual-key
    # authenticated BSON envelope, without a second differently bound payload.
    return prepared


def prepare_on_connection(connection,proposed,*,crypto,backup,binding,expected_payload):
    """Caller must commit the assertion and preparation before writing to Mongo."""
    document=verify_delivery(proposed,crypto,backup,expected_payload);binding.validate()
    lock=int.from_bytes(hashlib.sha256((binding.raw_record_id+document['writer_policy']).encode()).digest()[:8],'big',signed=True)
    connection.execute(text('SELECT pg_advisory_xact_lock(:key)'),{'key':lock})
    raw=check_source(connection,crypto,backup,binding,document,expected_payload)
    saved=connection.execute(select(PREP).where(PREP.c.raw_record_id==binding.raw_record_id,PREP.c.writer_policy==document['writer_policy'])).mappings().one_or_none()
    if saved is not None:return assert_saved(connection,saved,crypto,backup,binding,expected_payload)
    source=connection.execute(select(SourceSystem.__table__).where(SourceSystem.source_system_code=='POLICE_HR_IS')).mappings().one()
    if not source['is_active']:raise ValueError('Inactive reference supplying source.')
    plan=expected_payload['plan']
    connection.execute(insert(ASSERTION).values(source_assertion_id=UUID(document['source_assertion_uid']),source_system_id=source['source_system_id'],
        assertion_type=ASSERTION_TYPES[plan['filename']],asserted_value_ciphertext=bytes(document['payload_ciphertext']),encryption_key_version=document['payload_key_version'],
        intake_batch_id=raw['batch_id'],import_file_id=str(raw['import_file_id']),raw_record_id=raw['raw_record_id'],source_file_name=plan['filename'],
        source_file_sha256=raw['source_file_sha256'],source_row_number=raw['source_row_number'],transaction_start=document['recorded_at'],
        assertion_state='ACTIVE',independence_status='UNVERIFIED',classification='UNASSESSED'))
    connection.execute(insert(PREP).values(delivery_id=UUID(document['_id']),raw_record_id=raw['raw_record_id'],source_assertion_id=UUID(document['source_assertion_uid']),
        master_import_file_id=binding.master_import_file_id,master_file_sha256=binding.master_file_sha256,master_row_count=binding.master_rows,
        confirmation_sha256=binding.confirmation_sha256,code_revision=binding.code_revision,writer_policy=document['writer_policy'],source_file_name=plan['filename'],
        mongo_collection=collection_for(expected_payload),field_review_count=sum(f['status']=='REVIEW_REQUIRED' for f in plan['fields']),row_review_count=len(plan['review_issues']),
        review_state='STRUCTURAL_REVIEW_REQUIRED' if plan['needs_review'] else 'NO_STRUCTURAL_REVIEW',linkage_method='SOURCE_SCOPED_REFERENCE_CANDIDATES_UNASSESSED',
        historical_eligibility='UNASSESSED',document_bson=proposed.document_bson,document_sha256=proposed.document_sha256,recorded_at=document['recorded_at']))
    return assert_saved(connection,connection.execute(select(PREP).where(PREP.c.delivery_id==UUID(document['_id']))).mappings().one(),crypto,backup,binding,expected_payload)


def completion_on_connection(connection, prepared):
    """Append the receipt after protocol-verified Mongo readback; never change it."""
    event_id = UUID(prepared.document()["_id"])
    saved = connection.execute(select(PREP).where(PREP.c.delivery_id == event_id)).mappings().one()
    if bytes(saved["document_bson"]) != prepared.document_bson or saved["document_sha256"] != prepared.document_sha256:
        raise ValueError("Completion preparation differs.")
    connection.execute(pg_insert(DONE).values(delivery_id=event_id, document_sha256=prepared.document_sha256)
                       .on_conflict_do_nothing(index_elements=["delivery_id"]))
    digest = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == event_id)).scalar_one()
    if digest != prepared.document_sha256:
        raise ValueError("Completion digest differs.")
    return digest


class SqlReferenceLedger:
    """Production adapter: each write method returns only after its SQL commit."""

    def __init__(self, engine, *, crypto, backup, binding, expected_payload):
        if not isinstance(engine, Engine) or (engine.url.host, engine.url.port, engine.url.database, engine.url.username) != (
            "127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        binding.validate()
        self.engine, self.crypto, self.backup, self.binding = engine, crypto, backup, binding
        self.expected = check_payload(deepcopy(expected_payload))

    def prepare_once(self, proposed):
        with self.engine.begin() as connection:
            connection.execute(text("SET LOCAL lock_timeout = '5s'"))
            connection.execute(text("SET LOCAL statement_timeout = '30s'"))
            result = prepare_on_connection(connection, proposed, crypto=self.crypto, backup=self.backup,
                                           binding=self.binding, expected_payload=self.expected)
        # A fresh connection must see the committed bytes before Mongo insertion.
        with self.engine.connect() as connection:
            saved = connection.execute(select(PREP).where(PREP.c.delivery_id == UUID(result.document()["_id"]))).mappings().one()
            recovered = assert_saved(connection, saved, self.crypto, self.backup, self.binding, self.expected)
        if recovered != result:
            raise ValueError("Committed station reference preparation recovery differs.")
        return result

    def completion_digest(self, event_id):
        with self.engine.connect() as connection:
            return connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(event_id))).scalar_one_or_none()

    def complete_once(self, prepared):
        # Enforce this adapter's source-plan binding even for direct internal calls.
        verify_delivery(prepared, self.crypto, self.backup, self.expected)
        with self.engine.begin() as connection:
            saved = connection.execute(select(PREP).where(PREP.c.delivery_id == UUID(prepared.document()["_id"]))).mappings().one()
            assert_saved(connection, saved, self.crypto, self.backup, self.binding, self.expected)
            result = completion_on_connection(connection, prepared)
        if self.completion_digest(prepared.document()["_id"]) != result:
            raise ValueError("Committed station reference receipt recovery differs.")
        return result
