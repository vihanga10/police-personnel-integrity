"""Real signed workspace/access fixtures; external storage and chains remain isolated."""
import base64,json,time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from app.access.policy import AccessError
from app.access.api import COOKIE,RequestBoundary,_json_object
from app.access import full_source_profiles as F
from app.access.research_service import ResearchService
from app.intake.promotion_pipeline.store import IntakeStore
from app.intake.promotion_pipeline.service import PromotionService
from app.intake.promotion_pipeline.baseline import index_original
from app.intake.promotion_pipeline.runtime import Runtime
from app.intake.promotion_pipeline.http import register
from app.intake.promotion_pipeline.core import IntakeError,digest
from research_workspace_fixture import initialize,identifier,PASSWORD,sign
from scoped_access_fixture import grant
from test_full_source_profiles import payloads
from test_promotion_pipeline import source,csv_bytes
from test_scoped_access_api import Client

@pytest.fixture
def environment(tmp_path):
    clock=[time.time()];workspace,key,_=initialize(tmp_path,clock=lambda:clock[0]);clock[0]+=2
    workspace.access.put_account(grant(key,'HQ_ADMIN','ALL',None,version=2,now=int(clock[0])))
    profiles,meta,grants=payloads(workspace,key)
    grants=[sign(key,{**g['payload'],'account_version':2}) for g in grants]
    F.publish(workspace,profiles,meta,grants)
    root=tmp_path/'promotion-intake';root.mkdir(mode=0o700)
    files=[]
    for n in ['key','backup']:
        file=tmp_path/n;file.write_bytes(b'k'*32);file.chmod(0o600);files.append(file)
    intake=IntakeStore(root,*files,repo=workspace.repo,create=True)
    baseline=index_original(workspace,intake)
    config={'importer_ids':[identifier(100)],'baseline_source_set_sha256':baseline['source_set_sha256']}
    service=PromotionService(ResearchService(workspace),intake,config)
    token,csrf=workspace.access.login('station.one',PASSWORD,'fixture-peer')
    return SimpleNamespace(workspace=workspace,key=key,store=intake,service=service,token=token,csrf=csrf,clock=clock,config=config)

def upload(**changes):
    return {'operation_id':str(uuid4()),'filename':'promotions-2026.csv','source_reference':'Fixture personnel order',
        'csv_base64':base64.b64encode(csv_bytes([source(officer_nic_no='000000001V')])).decode(),**changes}

def test_signed_hq_preview_idempotence_commit_and_no_original_changes(environment):
    e=environment;before=e.workspace.get_packet(identifier(1));request=upload()
    a=e.service.preview(e.token,e.csrf,request);b=e.service.preview(e.token,e.csrf,request)
    assert a==b and a['status']=='PREVIEW_READY' and a['ready_rows']==1
    result=e.service.commit(e.token,e.csrf,{k:a[k] for k in ['batch_id','file_sha256']})
    assert result['status']=='QUEUED' and e.workspace.get_packet(identifier(1))==before
    assert e.service.officer_rows(e.token,identifier(1))['items']==[]
    assert e.service.commit(e.token,e.csrf,{k:a[k] for k in ['batch_id','file_sha256']})==result

@pytest.mark.parametrize('role,scope,scope_id',[('IGP','ALL',None),('DIG','DIVISION','D1'),('STATION_OIC','STATION','S1')])
def test_non_hq_cannot_upload_even_when_inspection_is_allowed(environment,role,scope,scope_id):
    e=environment;e.workspace.access.put_account(grant(e.key,role,scope,scope_id,version=3,now=int(e.clock[0])))
    token,csrf=e.workspace.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError) as error:e.service.preview(token,csrf,upload())
    assert error.value.code=='PROMOTION_IMPORT_FORBIDDEN' and e.store.batches()==[]

@pytest.mark.parametrize('csrf',['','forged'])
def test_csrf_failure_cannot_retain_or_queue_upload(environment,csrf):
    e=environment
    with pytest.raises(AccessError):e.service.preview(e.token,csrf,upload())
    assert not e.store.batches()

def test_missing_explicit_import_permission_is_denied_before_data_processing(environment):
    e=environment;e.config['importer_ids']=[]
    with pytest.raises(AccessError):e.service.preview(e.token,e.csrf,upload(csv_base64='not-base64'))
    assert not e.store.batches()

def test_unmatched_and_ambiguous_identity_block_confirmation(environment,monkeypatch):
    e=environment
    request=upload(csv_base64=base64.b64encode(csv_bytes([source(officer_nic_no='999999999V')])).decode())
    a=e.service.preview(e.token,e.csrf,request)
    assert a['review_rows']==1 and 'OFFICER_NOT_FOUND' in a['rows'][0]['issues']
    with pytest.raises(IntakeError,match='ROWS_REQUIRE_REVIEW'):e.service.commit(e.token,e.csrf,{k:a[k] for k in ['batch_id','file_sha256']})

def test_revocation_or_new_account_version_blocks_retained_batch(environment):
    e=environment;a=e.service.preview(e.token,e.csrf,upload())
    e.workspace.access.put_account(grant(e.key,'HQ_ADMIN','ALL',None,version=3,now=int(e.clock[0])))
    with pytest.raises(AccessError):e.service.commit(e.token,e.csrf,{k:a[k] for k in ['batch_id','file_sha256']})
    token,csrf=e.workspace.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(IntakeError,match='UPLOADER_ACCOUNT_CHANGED'):e.service.commit(token,csrf,{k:a[k] for k in ['batch_id','file_sha256']})

def test_worker_rechecks_current_signed_importer_and_disclosure(environment):
    e=environment;a=e.service.preview(e.token,e.csrf,upload());batch=e.store.get(a['batch_id'])
    runtime=object.__new__(Runtime);runtime.workspace=e.workspace;runtime.store=e.store;runtime.service=e.service;runtime.config=e.config;runtime.stop=False;runtime.check_pins=lambda:None
    runtime.authorize(batch)
    e.workspace.access.put_account(grant(e.key,'HQ_ADMIN','ALL',None,version=3,now=int(e.clock[0])))
    with pytest.raises(IntakeError,match='IMPORTER_AUTHORIZATION_CHANGED'):runtime.authorize(batch)

def test_http_guards_reject_wrong_origin_oversize_and_duplicate_fields(environment):
    e=environment;app=FastAPI();runtime=SimpleNamespace(service=e.service,check_pins=lambda:None,errors={})
    @app.exception_handler(AccessError)
    async def denied(request,exc):return JSONResponse({'error':exc.code},status_code=exc.status)
    async def body(request,fields):
        try:
            value=json.loads(await request.body(),object_pairs_hook=_json_object)
            if type(value) is not dict or set(value)!=fields:raise ValueError()
            return value
        except Exception:raise AccessError(400,'INVALID_REQUEST')
    register(app,runtime,lambda request:request.cookies.get(COOKIE),body)
    c=Client(RequestBoundary(app,'https://access.test:9443',body_limits={'/api/research/promotions/preview':3*1024*1024}));c.cookie=COOKIE+'='+e.token;c.csrf=e.csrf
    assert c.request('/api/research/promotions/preview','POST',upload(),origin='https://evil.test')[0]==403
    assert c.request('/api/research/promotions/preview','POST',raw=b'x'*(3*1024*1024+1))[0]==413
    assert c.request('/api/research/promotions/preview','POST',raw=b'{"filename":"a","filename":"b"}')[0]==400
    assert c.request('/api/research/promotions/preview','POST',upload())[0]==200
    assert c.request('/api/research/promotions/batches')[2]['items'][0]['ready_rows']==1


def test_importer_identity_alone_does_not_preserve_broad_inspection_after_scope_downgrade(environment):
    e=environment;e.workspace.access.put_account(grant(e.key,'STATION_OIC','STATION','S1',version=3,now=int(e.clock[0])))
    token,csrf=e.workspace.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError,match='PROMOTION_IMPORT_INSPECTION_FORBIDDEN'):e.service.listing(token)

def test_explicit_resume_after_grant_renewal_preserves_original_upload_actor_and_bytes(environment):
    e=environment;a=e.service.preview(e.token,e.csrf,upload());body={k:a[k] for k in ['batch_id','file_sha256']};e.service.commit(e.token,e.csrf,body)
    original=e.store.get(a['batch_id'])
    e.workspace.access.put_account(grant(e.key,'HQ_ADMIN','ALL',None,version=3,now=int(e.clock[0])))
    # Fresh disclosure grants are also needed; account renewal alone is insufficient.
    token,csrf=e.workspace.access.login('station.one',PASSWORD,'fixture-peer')
    with pytest.raises(AccessError):e.service.resume(token,csrf,body)
    from research_workspace_fixture import disclosure
    e.clock[0]+=2
    e.workspace.import_grant(disclosure(e.key,officer=identifier(1),now=int(e.clock[0]),version=3))
    e.service.resume(token,csrf,body)
    assert e.store.current_authorization(a['batch_id'])['account_version']==3
    assert e.store.get(a['batch_id'])==original

def test_both_chain_verified_upload_is_connected_only_to_its_scoped_officer(environment):
    from test_promotion_pipeline import Destination,Chains
    from app.intake.promotion_pipeline.delivery import process
    e=environment;a=e.service.preview(e.token,e.csrf,upload());body={k:a[k] for k in ['batch_id','file_sha256']};e.service.commit(e.token,e.csrf,body)
    old=e.workspace.get_packet(identifier(1));assert e.service.officer_rows(e.token,identifier(1))['items']==[]
    process(e.store,a['batch_id'],Destination(),Destination(),Chains(),lambda batch:None)
    rows=e.service.officer_rows(e.token,identifier(1))['items'];assert len(rows)==1 and rows[0]['fields']['promotion_id']=='TEST-PROMOTION-2026-01'
    assert rows[0]['publication']['status']=='BOTH_CHAINS_VERIFIED'
    assert e.service.officer_rows(e.token,identifier(2))['items']==[] and e.workspace.get_packet(identifier(1))==old
