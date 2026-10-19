"""Isolated generated fixtures; no private accounts, production stores or RPC."""
import base64
import csv
from datetime import datetime,timezone
import io
import json
import sqlite3
from uuid import uuid4
import pytest
from app.intake.promotion_pipeline.core import *
from app.intake.promotion_pipeline.store import IntakeStore
from app.intake.promotion_pipeline.delivery import process

OFFICER='11111111-1111-4111-8111-111111111111'
NOW=datetime(2026,10,15,tzinfo=timezone.utc)
def source(**changes):
    row=dict.fromkeys(COLUMNS,'')
    row.update(promotion_id='TEST-PROMOTION-2026-01',officer_nic_no='880000001V',
        from_rank='Sub Inspector of Police',to_rank='Inspector of Police',
        effective_date='2026-10-01',is_same_unit='TRUE')
    row.update(changes)
    return row

def csv_bytes(rows):
    out=io.StringIO(newline='');writer=csv.writer(out);writer.writerow(COLUMNS)
    for r in rows:writer.writerow([r[k] for k in COLUMNS])
    return out.getvalue().encode()

@pytest.fixture
def store(tmp_path):
    root=tmp_path/'state';root.mkdir(mode=0o700)
    keys=tmp_path/'keys';keys.mkdir(mode=0o700)
    key=keys/'key';backup=keys/'backup'
    key.write_bytes(b'x'*32);backup.write_bytes(b'x'*32);key.chmod(0o600);backup.chmod(0o600)
    return IntakeStore(root,key,backup,repo=tmp_path/'repo',create=True)

def retained(store,rows=None,operation=None):
    rows=rows or [source()]
    validated=validate_rows(rows,lambda n:[OFFICER],store.duplicate,now=NOW)
    return store.create(csv_bytes(rows),{'actor':{'user_id':OFFICER,'username':'research.hq','account_version':1},
        'received_at':NOW.isoformat(),'source_reference':'Controlled fixture order',
        'filename':'promotions-2026.csv','baseline_source_set_sha256':'a'*64,'rows':validated},operation or str(uuid4()))

def queued(store):
    b=retained(store);store.queue(b['batch_id'],{'approved':True});return b

class Destination:
    def __init__(self):self.records={};self.writes=0;self.fail=False;self.after=False
    def put(self,d):
        if self.fail and not self.after:raise RuntimeError('connection failed')
        self.writes+=1
        if d['record_id'] not in self.records:self.records[d['record_id']]=dict(d)
        self.verify(d)
        if self.fail:raise RuntimeError('lost acknowledgement')
    def verify(self,d):check(self.records.get(d['record_id'])==d,'DESTINATION_DIFFERS')

class Chains:
    def __init__(self):self.calls=0;self.pending=False;self.bad=False
    def __call__(self,b,p,boundary):
        boundary();self.calls+=1
        if self.pending:return {'status':'PENDING'}
        pp={k:p[k] for k in ['publication_id','public_sha256','merkle_root']};pp['fabric_transaction_id']='b'*64
        if self.bad:pp['merkle_root']='c'*64
        fabric={'status':'FINAL','payload':p,'transaction_id':'b'*64,'destination':{'chaincode':'promotions-anchor-v1'}}
        pp.update(policy='PROMOTIONS_PUBLIC_ANCHOR_V1',namespace='promotions-anchor-v1',fabric_destination_sha256=digest(fabric['destination']),fabric_receipt_sha256=digest(fabric))
        return {'status':'BOTH_CHAINS_VERIFIED','fabric':fabric,'public':{'status':'FINAL','payload':pp,'transaction_id':'0x'+'d'*64,'destination':{'contract':'0x'+'e'*40}}}

def test_csv_retains_unicode_quotes_multiline_and_original_spacing():
    r=source(promotion_reason='  Sinhala සිංහල, "order"\nsecond line  ')
    assert parse(csv_bytes([r]))==[r]

@pytest.mark.parametrize('data,code',[(b'', 'CSV_SIZE_LIMIT'),(b'bad\n', 'CSV_HEADER_DIFFERS'),
    (b'\xff', 'CSV_UTF8_REQUIRED'),(b'\x00','CSV_NUL_FORBIDDEN'),(b'x'*(MAX_BYTES+1),'CSV_SIZE_LIMIT')])
def test_reject_invalid_file(data,code):
    with pytest.raises(IntakeError,match=code):parse(data)

@pytest.mark.parametrize('changes,issue',[
    ({'effective_date':'31/02/2026'},'effective_date:UNSUPPORTED_DATE_FORMAT'),
    ({'effective_date':'2026-02-30'},'effective_date:INVALID_CALENDAR_DATE'),
    ({'to_rank':'Invented rank'},'to_rank:UNMAPPED_REPORTED_RANK'),
    ({'is_same_unit':'yes'},'is_same_unit:UNMAPPED_BOOLEAN_TEXT'),
    ({'promotion_id':''},'PROMOTION_ID_REQUIRED'),
    ({'officer_nic_no':'name only'},'NIC_FORMAT_UNSUPPORTED'),
    ({'promotion_order_date':'2030-01-01'},'promotion_order_date:FUTURE_ORDER_DATE')])
def test_rows_need_review(changes,issue):
    r=validate_rows([source(**changes)],lambda n:[OFFICER],lambda *a:'ABSENT',now=NOW)[0]
    assert r['status']=='NEEDS_REVIEW'
    assert issue in r['issues']

@pytest.mark.parametrize('candidates', [[],[OFFICER,str(uuid4())]])
def test_identity_must_be_unique(candidates):
    assert validate_rows([source()],lambda n:candidates,lambda *a:'ABSENT',now=NOW)[0]['status']=='NEEDS_REVIEW'

def test_same_promotion_id_twice_blocks_entire_batch(store):
    b=retained(store,[source(),source()])
    with pytest.raises(IntakeError,match='ROWS_REQUIRE_REVIEW'):store.queue(b['batch_id'],{})
    assert store.pending()==[]

def test_unknown_identity_blocks_even_when_other_row_ready(store):
    rows=validate_rows([source(),source(promotion_id='NEXT',officer_nic_no='991111111V')],
        lambda n:[OFFICER] if n=='880000001V' else [],store.duplicate,now=NOW)
    assert [r['status'] for r in rows]==['READY','NEEDS_REVIEW']

def test_file_retry_keeps_original_timestamp_and_actor(store):
    op=str(uuid4());a=retained(store,operation=op);b=retained(store,operation=op)
    assert a==b
    assert retained(store)['batch_id']==a['batch_id']
    with pytest.raises(IntakeError,match='OPERATION_CONFLICT'):
        retained(store,[source(promotion_id='OTHER')],operation=op)

def test_cross_batch_duplicate_and_conflict(store):
    b=queued(store)
    assert store.duplicate('TEST-PROMOTION-2026-01',OFFICER,source())=='IDENTICAL'
    assert store.duplicate('TEST-PROMOTION-2026-01',OFFICER,source(promotion_reason='changed'))=='CONFLICT'
    new=retained(store,[source(),source(promotion_id='OTHER')])
    assert [r['status'] for r in new['rows']]==['DUPLICATE','READY']

def test_concurrent_previews_cannot_reserve_same_source_twice(store):
    a=retained(store);b=retained(store,[source(),source(promotion_id='OTHER')])
    store.queue(a['batch_id'],{})
    with pytest.raises(IntakeError,match='SOURCE_RESERVED_AFTER_PREVIEW_REVIEW_REQUIRED'):store.queue(b['batch_id'],{})
    assert store.duplicate('OTHER',OFFICER,source(promotion_id='OTHER'))=='ABSENT'

def test_no_plaintext_in_store_and_original_cannot_be_modified(store):
    b=retained(store)
    raw=store.path.read_bytes()
    for text in ['880000001V','research.hq','Inspector of Police']:assert text.encode() not in raw
    with sqlite3.connect(store.path) as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM batches')
    assert store.get(b['batch_id'])==b

def test_opaque_publication_contains_no_identifiers(store):
    b=queued(store);p,m=publication(store.key,b)
    assert set(p)=={'policy','namespace','publication_id','public_sha256','merkle_root','publication_commitment'}
    assert '880000001V' not in json.dumps(p) and OFFICER not in json.dumps(p)
    other={**b,'received_at':'2026-10-16T00:00:00+00:00'}
    assert publication(store.key,other)[0]['merkle_root']!=p['merkle_root']

@pytest.mark.parametrize('stage,after',[('sql',False),('sql',True),('mongo',False),('mongo',True)])
def test_delivery_failure_resumes_exact_documents_without_duplicate_evidence(store,stage,after):
    b=queued(store);sql=Destination();mongo=Destination();chains=Chains()
    failed=sql if stage=='sql' else mongo;failed.fail=True;failed.after=after
    with pytest.raises(RuntimeError):process(store,b['batch_id'],sql,mongo,chains,lambda b:None)
    assert chains.calls==0 and store.phase(b['batch_id'],'VISIBLE') is None
    prepared=store.phase(b['batch_id'],'DOCUMENTS_PREPARED')
    failed.fail=False
    assert process(store,b['batch_id'],sql,mongo,chains,lambda b:None)['status']=='BOTH_CHAINS_VERIFIED'
    assert len(sql.records)==len(mongo.records)==1
    assert store.phase(b['batch_id'],'DOCUMENTS_PREPARED')==prepared
    process(store,b['batch_id'],sql,mongo,chains,lambda b:None)
    assert chains.calls==1

def test_finality_pending_never_discloses_records(store):
    b=queued(store);sql=Destination();mongo=Destination();chains=Chains();chains.pending=True
    assert process(store,b['batch_id'],sql,mongo,chains,lambda b:None)['status']=='CHAIN_CONFIRMATION_PENDING'
    assert store.phase(b['batch_id'],'VISIBLE') is None
    chains.pending=False
    process(store,b['batch_id'],sql,mongo,chains,lambda b:None)
    assert store.phase(b['batch_id'],'VISIBLE') is not None

def test_wrong_receipt_cannot_publish_visibility(store):
    b=queued(store);chains=Chains();chains.bad=True
    with pytest.raises(IntakeError,match='PUBLIC_RECEIPT_DIFFERS'):
        process(store,b['batch_id'],Destination(),Destination(),chains,lambda b:None)
    assert store.phase(b['batch_id'],'VISIBLE') is None

def test_storage_tampering_stops_before_chain(store):
    b=queued(store);sql=Destination();mongo=Destination();chains=Chains();chains.pending=True
    process(store,b['batch_id'],sql,mongo,chains,lambda b:None)
    next(iter(sql.records.values()))['ciphertext']='tampered'
    with pytest.raises(IntakeError,match='DESTINATION_DIFFERS'):process(store,b['batch_id'],sql,mongo,chains,lambda b:None)
    assert chains.calls==1

def test_revocation_prevents_storage_or_broadcast(store):
    b=queued(store);sql=Destination();mongo=Destination();chains=Chains()
    def denied(b):raise IntakeError('REVOKED')
    with pytest.raises(IntakeError,match='REVOKED'):process(store,b['batch_id'],sql,mongo,chains,denied)
    assert sql.writes==mongo.writes==chains.calls==0

def test_out_of_order_phase_refused(store):
    b=retained(store)
    with pytest.raises(IntakeError,match='PHASE_OUT_OF_ORDER'):store.phase(b['batch_id'],'VISIBLE',{})


def test_baseline_index_missing_or_modified_cannot_authorize_duplicate_checks(store):
    with pytest.raises(IntakeError,match='BASELINE_INDEX_REQUIRED'):store.verify_baseline('a'*64)
    rows={'b'*64:'c'*64}
    with store.transaction() as c:
        c.execute('INSERT INTO baseline VALUES(?,?)',('b'*64,'c'*64))
        c.execute('INSERT INTO baseline_meta VALUES(1,?)',(store.seal('BASELINE',1,{'source_set_sha256':'a'*64,'promotions':1,'index_sha256':digest(rows)}),))
    assert store.verify_baseline('a'*64)['promotions']==1
    with pytest.raises(IntakeError,match='BASELINE_INDEX_CHANGED'):store.verify_baseline('f'*64)
    with store.transaction() as c:c.execute('INSERT INTO baseline VALUES(?,?)',('d'*64,'e'*64))
    with pytest.raises(IntakeError,match='BASELINE_INDEX_CHANGED'):store.verify_baseline('a'*64)

def test_worker_status_outbox_survives_restart_without_repeated_identical_status(store):
    batch=queued(store);ident=batch['batch_id']
    first=store.record_worker_status(ident,{'status':'CHAIN_CONFIRMATION_PENDING','phase':'STORAGE_VERIFIED'})
    assert store.record_worker_status(ident,{'status':'CHAIN_CONFIRMATION_PENDING','phase':'STORAGE_VERIFIED'})==first
    events=store.pending_worker_audits();assert len(events)==1 and events[0][0]==first[0]
    store.acknowledge_worker_audit(first[0],500)
    assert store.pending_worker_audits()==[]
    with pytest.raises(IntakeError,match='WORKER_AUDIT_ACK_DIFFERS'):store.acknowledge_worker_audit(first[0],501)
    store.record_worker_status(ident,{'status':'BOTH_CHAINS_VERIFIED','phase':'VISIBLE'})
    assert len(store.pending_worker_audits())==1
    assert store.worker_status(ident)['state']['status']=='BOTH_CHAINS_VERIFIED'


def test_reported_demotion_cannot_silently_pass_as_promotion():
    row=source(from_rank='Inspector of Police',to_rank='Sub Inspector of Police')
    result=validate_rows([row],lambda nic:[OFFICER],lambda *a:'ABSENT',now=NOW)[0]
    assert result['status']=='NEEDS_REVIEW' and 'REPORTED_PROMOTION_RANK_ORDER_REQUIRES_REVIEW' in result['issues']


def test_same_file_cannot_silently_receive_a_different_source_reference(store):
    first=retained(store);value={k:v for k,v in first.items() if k not in ('batch_id','file_sha256','original_base64')}
    value['source_reference']='Different claimed order'
    with pytest.raises(IntakeError,match='RETAINED_FILE_SOURCE_REFERENCE_DIFFERS'):
        store.create(csv_bytes([source()]),value,str(uuid4()))
    assert len(store.batches())==1
