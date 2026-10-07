"""Failure injection tests for recovery; these do not simulate real DB permissions."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

import pytest
from pymongo.errors import AutoReconnect, DuplicateKeyError

from app.identity.reference_delivery import deliver, make_delivery, reconcile, collection_for
from app.identity.reference_delivery import ROUTES
from app.identity.reference_plan import plan_reference, ReferenceCandidates
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL
from app.security.identity_crypto import IdentityCrypto


class MemoryLedger:
    """Test-only durable boundary model; production requires real SQL constraints."""

    def __init__(self, fail=None):
        self.prepared = None
        self.receipts = {}
        self.fail = fail

    def interrupt(self, location):
        if self.fail == location:
            self.fail = None
            raise AutoReconnect("Injected uncertain acknowledgment")

    def prepare_once(self, proposed):
        if self.prepared is None:
            self.prepared = proposed
        self.interrupt("after_prepare_commit")
        return self.prepared

    def completion_digest(self, event_id):
        return self.receipts.get(event_id)

    def complete_once(self, prepared):
        self.interrupt("before_receipt_commit")
        event = prepared.document()["_id"]
        self.receipts.setdefault(event, prepared.document_sha256)
        self.interrupt("after_receipt_commit")
        return self.receipts[event]


class MemoryCollection:
    """Test insert/find surface only; there is deliberately no mutation API."""

    def __init__(self, fail=None):
        self.documents = []
        self.name = None
        self.fail = fail
        self.insert_calls = 0

    def find_one(self, query):
        return next((deepcopy(d) for d in self.documents if all(d.get(k) == v for k, v in query.items())), None)

    def insert_one(self, document):
        self.insert_calls += 1
        if self.fail == "before_mongo_insert":
            self.fail = None
            raise AutoReconnect("Injected connection loss")
        if self.documents:
            raise DuplicateKeyError("Injected unique-source conflict")
        self.documents.append(deepcopy(document))
        if self.fail == "after_mongo_insert":
            self.fail = None
            raise AutoReconnect("Injected uncertain acknowledgment")
        return type("Acknowledged", (), {"acknowledged": True})()


@pytest.fixture(params=list(ROUTES))
def evidence(tmp_path,request):
    encoded=base64.b64encode(b'k'*32).decode();paths=[]
    for name in ('primary','backup'):
        path=tmp_path/(name+'.json');path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':encoded},lookup_keys={'TEST':encoded})))
        path.chmod(0o600);paths.append(path)
    crypto,backup=(IdentityCrypto(p) for p in paths)
    master=dict.fromkeys(HEADERS[MASTER],'')
    master.update(station_code='00012',station_name='Example',station_name_si='උදාහරණ',division='Division',province='Province',latitude='6.90',longitude='79.90')
    row=dict.fromkeys(HEADERS[SINHALA],'')
    row.update({LABEL:'Example (උදාහරණ)','Division':'Division (අංශය)','Province ':'Province (පළාත)','Latitude':'not a coordinate'})
    filename=request.param;raw='a'*64 if filename==MASTER else 'b'*64
    plan=plan_reference(filename,master if filename==MASTER else row,raw_record_id=raw,candidates=ReferenceCandidates([('a'*64,master)]))
    payload=dict(plan=plan.payload,evidence=dict(batch_id='ISOLATED-FIXTURE',archive_sha256='c'*64,confirmation_sha256='d'*64,source_system_code='POLICE_HR_IS',
        import_file_id=str(uuid4()),source_file_sha256='e'*64,source_row_number=1,master_import_file_id=str(uuid4()),master_file_sha256='f'*64,master_rows=1))
    def candidate(value=payload):return make_delivery(crypto,backup,value,event_id=uuid4(),assertion_id=uuid4(),recorded_at=datetime.now(timezone.utc))
    return crypto,backup,payload,candidate


def dispatch(ledger, mongo, evidence, proposed=None):
    crypto, backup, payload, candidate = evidence
    if mongo.name is None:
        mongo.name = collection_for(payload)
    return deliver(ledger, mongo, proposed or candidate(), crypto=crypto, backup=backup, expected_payload=payload)


@pytest.mark.parametrize("failure", ["after_prepare_commit", "before_mongo_insert", "after_mongo_insert",
                                     "before_receipt_commit", "after_receipt_commit"])
def test_retry_after_uncertain_outcomes_reuses_exact_ciphertext(evidence, failure):
    ledger = MemoryLedger(failure)
    mongo = MemoryCollection(failure)
    with pytest.raises(AutoReconnect):
        dispatch(ledger, mongo, evidence)
    committed = ledger.prepared
    # Retry has fresh candidate IDs/nonces; the committed SQL winner must prevail.
    dispatch(ledger, mongo, evidence)
    assert ledger.prepared == committed
    assert mongo.documents == [committed.document()]
    assert ledger.receipts == {committed.document()["_id"]: committed.document_sha256}
    assert dispatch(ledger, mongo, evidence) == "VERIFIED_EXISTING"
    assert len(mongo.documents) == len(ledger.receipts) == 1


def test_read_only_reconciliation_never_finishes_pending_import(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    prepared = ledger.prepare_once(candidate())
    mongo.name = collection_for(payload)
    kwargs = dict(crypto=crypto, backup=backup, expected_payload=payload)
    with pytest.raises(ValueError, match="Mongo evidence is missing"):
        reconcile(ledger, mongo, prepared, **kwargs)
    assert not mongo.documents and not ledger.receipts
    mongo.insert_one(prepared.document())
    with pytest.raises(ValueError, match="receipt is missing"):
        reconcile(ledger, mongo, prepared, **kwargs)
    assert not ledger.receipts and mongo.insert_calls == 1
    dispatch(ledger, mongo, evidence, prepared)
    assert reconcile(ledger, mongo, prepared, **kwargs) == "VERIFIED_EXISTING"
    assert mongo.insert_calls == 1


def test_completed_but_missing_mongo_record_is_not_silently_repaired(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    mongo.documents.clear()  # Simulated external tampering, not a production operation.
    with pytest.raises(ValueError, match="integrity review"):
        dispatch(ledger, mongo, evidence)
    assert mongo.insert_calls == 1 and not mongo.documents


def test_conflicting_stored_mongo_evidence_is_never_overwritten(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    mongo.documents[0]["source_assertion_uid"] = str(uuid4())
    corrupted = deepcopy(mongo.documents)
    with pytest.raises(ValueError, match="stop for review"):
        dispatch(ledger, mongo, evidence)
    assert mongo.documents == corrupted and mongo.insert_calls == 1


def test_corrupted_receipt_blocks_retry(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    ledger.receipts[ledger.prepared.document()["_id"]] = "0" * 64
    with pytest.raises(ValueError, match="receipt differs"):
        dispatch(ledger, mongo, evidence)
    assert mongo.insert_calls == 1


def test_source_plan_change_blocks_delivery_of_old_preparation(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    ledger.prepare_once(candidate())
    mongo.name = collection_for(payload)
    changed = deepcopy(payload)
    changed["evidence"]["archive_sha256"] = "0"*64
    with pytest.raises(ValueError, match="differs from source plan"):
        deliver(ledger, mongo, candidate(changed), crypto=crypto, backup=backup, expected_payload=changed)
    assert not mongo.documents and not ledger.receipts


def test_concurrent_identical_insert_is_verified(evidence):
    class RacingCollection(MemoryCollection):
        def insert_one(self, document):
            super().insert_one(document)
            raise DuplicateKeyError("Another worker inserted the prepared winner")
    ledger, mongo = MemoryLedger(), RacingCollection()
    assert dispatch(ledger, mongo, evidence) == "COMPLETED"
    assert len(ledger.receipts) == len(mongo.documents) == 1


def test_duplicate_error_without_identical_readback_cannot_complete(evidence):
    class ConflictingCollection(MemoryCollection):
        def insert_one(self, document):
            raise DuplicateKeyError("Unrelated primary-key collision")
    ledger, mongo = MemoryLedger(), ConflictingCollection()
    with pytest.raises(RuntimeError, match="not recovered"):
        dispatch(ledger, mongo, evidence)
    assert not ledger.receipts


def test_receipt_acknowledgment_without_readback_is_not_success(evidence):
    class BrokenLedger(MemoryLedger):
        def complete_once(self, prepared):
            return prepared.document_sha256
    ledger, mongo = BrokenLedger(), MemoryCollection()
    with pytest.raises(ValueError, match="receipt was not recovered"):
        dispatch(ledger, mongo, evidence)
    assert len(mongo.documents) == 1 and not ledger.receipts


@pytest.mark.parametrize('key,value',[
    ('valid_from','2020-01-01'),('accepted_station_uid','accepted'),('record_classification','ORDINARY'),
    ('authority_result','VALID'),('linkage_accepted',True),('review_issues',[]),('uncertainties',[])])
def test_no_acceptance_or_warning_removal(evidence,key,value):
    _,_,payload,candidate=evidence;changed=deepcopy(payload)
    if changed['plan'].get(key)==value:return
    changed['plan'][key]=value
    with pytest.raises(ValueError):candidate(changed)


@pytest.mark.parametrize('field',['master_file_sha256','confirmation_sha256','master_rows','source_system_code'])
def test_bad_evidence_rejected(evidence,field):
    _,_,payload,candidate=evidence;changed=deepcopy(payload)
    changed['evidence'][field]='invalid'
    with pytest.raises(ValueError):candidate(changed)


def test_wrong_destination_no_preparation(evidence):
    crypto,backup,payload,candidate=evidence;ledger=MemoryLedger();mongo=MemoryCollection();mongo.name='service_status_events'
    with pytest.raises(ValueError):deliver(ledger,mongo,candidate(),crypto=crypto,backup=backup,expected_payload=payload)
    assert ledger.prepared is None and not mongo.documents


def test_original_text_review_and_no_officer_identity(evidence):
    crypto,backup,payload,candidate=evidence;prepared=candidate();doc=prepared.document()
    assert 'officer_uid' not in doc
    assert payload['plan']['accepted_station_uid'] is None and payload['plan']['linkage_accepted'] is False
    fields=payload['plan']['fields']
    if payload['plan']['filename']==MASTER:assert next(f for f in fields if f['source_column']=='station_code')['value']=='00012'
    else:assert payload['plan']['needs_review'] is True and next(f for f in fields if f['source_column']=='Latitude')['value']=='not a coordinate'
    for change in ('parsed_value','source_value','review_flag'):
        altered=deepcopy(payload)
        if change=='review_flag':altered['plan']['needs_review']=not altered['plan']['needs_review']
        else:altered['plan']['fields'][0]['value' if change=='parsed_value' else 'source_value']='altered'
        with pytest.raises(ValueError):candidate(altered)


@pytest.mark.parametrize('username',['police_identity_migrator','postgres'])
def test_production_account_guard(evidence,username):
    from sqlalchemy import URL
    from sqlalchemy.engine import Engine
    from sqlalchemy.engine.default import DefaultDialect
    from sqlalchemy.pool import NullPool
    from app.identity.reference_sql_ledger import ReferenceSourceBinding,SqlReferenceLedger
    def forbidden():raise AssertionError('No connection expected.')
    engine=Engine(NullPool(forbidden),DefaultDialect(),URL.create('postgresql+psycopg',username=username,password='TEST_ONLY',host='127.0.0.1',port=5432,database='police_identity'))
    crypto,backup,payload,_=evidence
    try:
        with pytest.raises(ValueError,match='Unexpected SQL application target'):
            SqlReferenceLedger(engine,crypto=crypto,backup=backup,binding=ReferenceSourceBinding('a'*64,uuid4(),'b'*64,1,'c'*64,'d'*40),expected_payload=payload)
    finally:engine.dispose()


def test_checker_fixture_and_independent_master_verification(tmp_path):
    """Real encryption and verifier; an inert SQL sink models result retrieval only."""
    import importlib.util
    from pathlib import Path
    from sqlalchemy.sql.dml import Insert
    from sqlalchemy.sql.selectable import Select
    from app.identity import reference_sql_ledger as sql
    spec=importlib.util.spec_from_file_location('reference_driver_fixture',Path(__file__).resolve().parents[1]/'scripts/check_reference_delivery.py')
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    key=base64.b64encode(b'x'*32).decode();copies=[]
    for name in ('primary.json','backup.json'):
        p=tmp_path/name;p.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':key},lookup_keys={'TEST':key})));copies.append(IdentityCrypto(p))
    class Result:
        def __init__(self,rows):self.rows=rows
        def mappings(self):return self
        def one(self):assert len(self.rows)==1;return deepcopy(self.rows[0])
        def all(self):return deepcopy(self.rows)
    class Sink:
        def __init__(self):self.rows={}
        def execute(self,statement):
            if isinstance(statement,Insert):
                self.rows.setdefault(statement.table.fullname,[]).append(dict(statement.compile().params));return Result([])
            assert isinstance(statement,Select)
            table=statement.get_final_froms()[0].fullname;params=statement.compile().params
            selected=[r for r in self.rows[table] if all(r.get(k.rsplit('_',1)[0])==v for k,v in params.items())]
            return Result(sorted(selected,key=lambda r:r.get('source_row_number',0)))
    for filename in HEADERS:
        sink=Sink();binding,payload,candidate=checker.fixture(sink,*copies,filename)
        prepared=candidate();sql.check_source(sink,*copies,binding,prepared.document(),payload)
        assert payload['plan']['needs_review'] is (filename==SINHALA)
        altered=deepcopy(payload);altered['evidence']['master_rows']=2
        with pytest.raises(ValueError,match='provenance differs'):
            sql.check_source(sink,*copies,binding,prepared.document(),altered)
        # Well-formed candidate membership still needs the independently recovered snapshot.
        changed=deepcopy(payload)
        if filename==SINHALA:
            for item in changed['plan']['candidate_evidence']:
                for name in ('latin_raw_ids','sinhala_raw_ids','joint_raw_ids'):item[name]=['0'*64]
        else:changed['plan']['source_observations']['repeated_source_code']=True;changed['plan']['review_issues']=['REPEATED_SOURCE_CODE'];changed['plan']['needs_review']=True
        with pytest.raises(ValueError,match='candidate or review evidence'):
            sql.check_source(sink,*copies,binding,prepared.document(),changed)
        # Original-cell changes that are internally consistent cannot replace the staged source.
        changed=deepcopy(payload);changed['plan']['fields'][0]['source_value']=changed['plan']['fields'][0]['value']='changed'
        with pytest.raises(ValueError,match='differ from staging'):
            sql.check_source(sink,*copies,binding,prepared.document(),changed)


def test_sql_transaction_bodies_replay_winner_and_check_saved_metadata(tmp_path):
    """Verify the adapter against an inert result store, not real SQL permissions."""
    import importlib.util
    from pathlib import Path
    from sqlalchemy.sql.dml import Insert
    from sqlalchemy.sql.selectable import Select
    from sqlalchemy.sql.elements import TextClause
    from app.identity import reference_sql_ledger as sql
    spec=importlib.util.spec_from_file_location('reference_driver_transaction_fixture',Path(__file__).resolve().parents[1]/'scripts/check_reference_delivery.py')
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    key=base64.b64encode(b'x'*32).decode();copies=[]
    for name in ('primary','backup'):
        path=tmp_path/(name+'.json');path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':key},lookup_keys={'TEST':key})));copies.append(IdentityCrypto(path))
    class Result:
        def __init__(self,rows,columns=()):self.rows=rows;self.columns=columns
        def mappings(self):return self
        def one(self):assert len(self.rows)==1;return deepcopy(self.rows[0])
        def one_or_none(self):return self.one() if self.rows else None
        def scalar_one(self):return self.one()[self.columns[0].name]
        def all(self):return deepcopy(self.rows)
    class Sink:
        def __init__(self):self.rows={'identity.source_system':[dict(source_system_id=uuid4(),source_system_code='POLICE_HR_IS',is_active=True)]}
        def execute(self,statement,parameters=None):
            if isinstance(statement,TextClause):return Result([])
            if isinstance(statement,Insert):
                row=dict(statement.compile().params);table=statement.table.fullname
                if table=='identity.reference_source_assertion':
                    for key in ('valid_from','valid_to','transaction_end','source_recorded_at','captured_at','source_record_id','source_document_id','source_page'):row.setdefault(key,None)
                target=self.rows.setdefault(table,[])
                if table!='staging.reference_delivery_completion' or not any(r['delivery_id']==row['delivery_id'] for r in target):target.append(row)
                return Result([])
            assert isinstance(statement,Select)
            table=statement.get_final_froms()[0].fullname;params=statement.compile().params
            rows=[r for r in self.rows.get(table,[]) if all(r.get(k.rsplit('_',1)[0])==v for k,v in params.items())]
            return Result(sorted(rows,key=lambda r:r.get('source_row_number',0)),list(statement.selected_columns))
    for filename in HEADERS:
        sink=Sink();binding,payload,candidate=checker.fixture(sink,*copies,filename)
        kwargs=dict(crypto=copies[0],backup=copies[1],binding=binding,expected_payload=payload)
        winner=sql.prepare_on_connection(sink,candidate(),**kwargs)
        replay=sql.prepare_on_connection(sink,candidate(),**kwargs)
        assert winner==replay
        assert len(sink.rows[sql.PREP.fullname])==len(sink.rows[sql.ASSERTION.fullname])==1
        assert sql.completion_on_connection(sink,winner)==winner.document_sha256
        assert sql.completion_on_connection(sink,replay)==winner.document_sha256
        assert len(sink.rows[sql.DONE.fullname])==1
        saved=sink.rows[sql.PREP.fullname][0]
        for key,value in [('master_file_sha256','0'*64),('field_review_count',99),('historical_eligibility','ACCEPTED'),('code_revision','bad')]:
            corrupted=dict(saved,**{key:value})
            with pytest.raises(ValueError):sql.assert_saved(sink,corrupted,*copies,binding,payload)
        assertion=sink.rows[sql.ASSERTION.fullname][0]
        for key,value in [('classification','ORDINARY'),('valid_from','2020-01-01'),('asserted_value_ciphertext',b'wrong')]:
            before=assertion[key];assertion[key]=value
            with pytest.raises(ValueError,match='assertion differs'):sql.assert_saved(sink,saved,*copies,binding,payload)
            assertion[key]=before
        sink.rows['identity.source_system'][0]['is_active']=False
        with pytest.raises(ValueError,match='Inactive'):sql.assert_saved(sink,saved,*copies,binding,payload)


def test_driver_checker_namespace_and_checkpoint():
    from pathlib import Path
    source=(Path(__file__).resolve().parents[1]/'scripts/check_reference_delivery.py').read_text()
    assert "['b40d8f62ac95']" in source
    assert len(('police_ref_delivery_'+'0'*32).encode())<64
    assert 'SET LOCAL ROLE' not in source
    assert 'case.rollback()' in source and 'outer.rollback()' in source
