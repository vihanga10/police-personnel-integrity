from copy import deepcopy
from datetime import datetime,timezone
import json,os
from pathlib import Path
import pytest
from test_accountability import env,events,FILTERS,reader_grant,write
from research_workspace_fixture import identifier
from app.access import accountability_anchor as B
from app.access.policy import AccessError


def test_scoped_client_report_captures_actor_identity_section_and_never_human_read_proof(env):
    _,logs,c,*_=env
    assert c.request('/api/accountability/activity','POST',{'officer_uid':identifier(1),'section':'history','event_id':identifier(701)})[0]==200
    event=events(logs)[-1]
    assert event['action']=='CLIENT_SECTION_DISPLAY' and event['actor']['username']=='station.one'
    assert event['request_details']['section']=='history' and event['officer_identity']['officer_uid']==identifier(1)
    assert 'NOT_PROOF_OF_HUMAN_READING' in event['observation_basis']
    assert c.request('/api/accountability/activity','POST',{'officer_uid':identifier(5),'section':'overview','event_id':identifier(702)})[0]==404
    assert 'officer_identity' not in events(logs)[-1]
    for section in ['bad','<script>']:
        assert c.request('/api/accountability/activity','POST',{'officer_uid':identifier(1),'section':section,'event_id':identifier(703)})[0]==400


def test_client_cannot_supply_actor_or_disable_csrf(env):
    _,logs,c,*_=env
    value={'officer_uid':identifier(1),'section':'overview','event_id':identifier(704)}
    assert c.request('/api/accountability/activity','POST',{**value,'actor':'research.igp'})[0]==400
    assert c.request('/api/accountability/activity','POST',value,csrf='wrong')[0] in (400,403)


def test_filter_account_request_and_inspection_are_logged(env):
    _,logs,c,*_=env
    c.request('/api/officers/search','POST',{'kind':'NIC','query':'000000001V'})
    request_id=events(logs)[-1]['request_id']
    status,_,v=c.request('/api/accountability/logs','POST',{**FILTERS,'account':'station.one','request_id':request_id})
    assert status==200 and v['items'] and all(e['request_id']==request_id for e in v['items'])
    assert events(logs)[-1]['request_details']['account']=='station.one'
    assert c.request('/api/accountability/logs','POST',{**FILTERS,'request_id':'bad'})[0]==400
    logs.grant_files=()
    assert c.request('/api/accountability/anchoring')[0]==403
    assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403


def test_browse_filters_and_exact_terms_are_encrypted(env):
    _,logs,c,*_=env
    body={'kind':'NIC','query':'000000001V','availability':'ALL','level':'ALL','scope_id':'','limit':25,'offset':0}
    c.request('/api/research/browse','POST',body)
    event=events(logs)[-1]
    assert event['request_details']=={**body,'entry_point':'DIRECTORY_BROWSER'}
    assert b'000000001V' not in logs.db.read_bytes()


def configure_anchor(env,tmp_path):
    _,logs,_,_,_,clock,_=env
    root=tmp_path/'anchor';root.mkdir(mode=0o700)
    key=root/'key';key.write_bytes(os.urandom(32));key.chmod(0o600)
    gateway=root/'gateway.json';write(gateway,{'destination':{'chaincode':'accountability-anchor-v1'}})
    source=logs.repo/'blockchain/fabric/client/accountability-worker.js';source.parent.mkdir(parents=True,exist_ok=True);source.write_text('//fixture')
    import hashlib
    cfg={'policy':B.POLICY,'state_directory':str(root),'key_file':str(key),'gateway_config':str(gateway),
      'gateway_sha256':hashlib.sha256(gateway.read_bytes()).hexdigest(),'source_pins':{'blockchain/fabric/client/accountability-worker.js':hashlib.sha256(source.read_bytes()).hexdigest()},'interval_seconds':60,'batch_events':100}
    file=root/'config.json';write(file,cfg);logs.anchor_config=str(file)
    return logs,root,key.read_bytes(),clock


def final(job):return {'status':'FINAL','payload':job['payload'],'transaction_id':'a'*64,'verification':{'validation_code':'VALID','organizations':['Org1MSP','Org2MSP'],'block_sha256':'b'*64}}


def test_timeout_batch_and_newer_event_coverage(env,tmp_path):
    logs,root,key,clock=configure_anchor(env,tmp_path);calls=[]
    worker=lambda *args:(calls.append(args[-1]) or final(args[-1]))
    B.tick(logs,worker);assert not calls
    clock[0]+=61;B.tick(logs,worker);assert len(calls)==1
    v=B.status(logs);assert v['private_chain_verified'] and v['anchored_through_sequence']>0 and not v['public_chain_anchored']
    logs.append({'action':'OTHER_REQUEST','phase':'COMPLETED','outcome':'ALLOWED'})
    assert B.status(logs)['status']=='NEW_EVENTS_PENDING'
    clock[0]+=61;B.tick(logs,worker);assert len(calls)==2
    assert calls[1]['start']==calls[0]['end']+1
    assert b'LOGIN' not in b''.join(p.read_bytes() for p in root.glob('*.encrypted'))


def test_size_trigger_exact_batch_and_recovery_same_payload(env,tmp_path):
    logs,root,key,clock=configure_anchor(env,tmp_path)
    for i in range(100):logs.append({'action':'OTHER_REQUEST','phase':'COMPLETED','outcome':'ALLOWED'})
    calls=[]
    def fail(*args):calls.append(deepcopy(args[-1]));raise TimeoutError()
    B.tick(logs,fail);assert len(calls)==1 and calls[0]['end']-calls[0]['start']==99
    assert B.status(logs)['status']=='FAILED_PENDING_RECOVERY'
    file=next(root.glob('batch-*.encrypted'));job=B.read(file,key,logs.repo);job['next_check_at']=0;B.save(file,job,key)
    def recover(*args):calls.append(deepcopy(args[-1]));return final(args[-1])
    B.tick(logs,recover);assert calls[0]['payload']==calls[1]['payload']
    assert B.status(logs)['private_chain_verified']


@pytest.mark.parametrize('change',['org','payload','validation'])
def test_unverified_receipt_never_marks_anchored(env,tmp_path,change):
    logs,root,key,clock=configure_anchor(env,tmp_path);clock[0]+=61
    def wrong(*args):
        value=final(args[-1])
        if change=='org':value['verification']['organizations']=['Org1MSP']
        elif change=='payload':value['payload']={}
        else:value['verification']['validation_code']='INVALID'
        return value
    B.tick(logs,wrong);assert not B.status(logs)['private_chain_verified']


def test_local_tamper_or_gateway_pin_change_stops_publication(env,tmp_path):
    logs,root,key,clock=configure_anchor(env,tmp_path);clock[0]+=61
    gateway=root/'gateway.json';write(gateway,{'changed':True})
    with pytest.raises(ValueError):B.tick(logs,lambda *_:pytest.fail('Must not call chain'))
    assert B.status(logs)['status']=='VERIFICATION_FAILED'


def test_operator_grants_igp_hq_explicit_read_access_without_changing_accounts(env,tmp_path,monkeypatch):
    import importlib.util,base64
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
    from scoped_access_fixture import grant,sign,PASSWORD
    s,logs,c,key,_,clock,cfg=env
    script=Path(__file__).resolve().parents[1]/'scripts/manage_accountability_upgrade.py'
    spec=importlib.util.spec_from_file_location('upgrade_operator',script);M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
    s.access.keys['research-operator-access']=s.access.keys['test-admin']
    for i,(login,role) in enumerate([('research.igp','IGP'),('research.hq','HQ_ADMIN')],501):
        g=grant(key,role=role,scope_type='ALL',scope_id=None,login=login,now=clock[0]);p={**g['payload'],'user_id':identifier(i)}
        s.access.put_account(sign(key,p),PASSWORD)
    root=tmp_path/'private-app';root.mkdir(mode=0o700);(root/'keys').mkdir(mode=0o700)
    file=root/'keys/research-access-signer.key';file.write_bytes(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()));file.chmod(0o600)
    lc=root/'accountability-config.json';write(lc,{'policy':'ACCOUNTABILITY_CONFIG_V1','state_directory':str(logs.root),'key_file':str(logs.key_path),'reader_grants':[]})
    config=json.loads(cfg.read_bytes());config['accountability_config']=str(lc);write(root/'workspace-config.json',config)
    monkeypatch.setattr(M,'configured_store',lambda _: (s.access,'https://access.test:9443'))
    before={login:M.stored(s.access,login) for login in ('research.igp','research.hq','station.one')}
    assert M.prepare(s.access.repo,root)['status']=='ACCOUNTABILITY_UPGRADE_PREVIEW_PASSED'
    assert not (root/'research-igp-log-reader.json').exists()
    assert M.prepare(s.access.repo,root,True)['readers']==['research.igp','research.hq']
    assert before=={login:M.stored(s.access,login) for login in before}
    logs.grant_files=tuple(json.loads(lc.read_bytes())['reader_grants'])
    for login in ('research.igp','research.hq'):
        status,headers,value=c.request('/api/auth/login','POST',{'username':login,'password':PASSWORD},cookie='',csrf='')
        assert status==200
        cookie=next(v for k,v in headers if k=='set-cookie').split(';')[0]
        assert c.request('/api/accountability/logs','POST',FILTERS,cookie=cookie,csrf=value['csrf_token'])[0]==200
    # Existing ordinary login does not acquire a log-reader grant by role or UI claim.
    c.login();assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403


def test_managed_lifespan_automatically_anchors_without_browser_polling(env,tmp_path,monkeypatch):
    import asyncio
    logs,root,key,clock=configure_anchor(env,tmp_path);boundary=env[2].app;clock[0]+=61
    original=B.tick;monkeypatch.setattr(B,'tick',lambda store:original(store,lambda *args:final(args[-1])))
    async def run():
        queue=asyncio.Queue();started=asyncio.Event()
        async def receive():return await queue.get()
        async def send(event):
            if event['type']=='lifespan.startup.complete':started.set()
        task=asyncio.create_task(boundary({'type':'lifespan','asgi':{'version':'3.0'}},receive,send))
        try:
            await queue.put({'type':'lifespan.startup'});await asyncio.wait_for(started.wait(),3)
            for _ in range(100):
                if B.status(logs)['private_chain_verified']:break
                await asyncio.sleep(.02)
            else:pytest.fail('Managed anchoring worker did not run')
        finally:
            await queue.put({'type':'lifespan.shutdown'});await asyncio.wait_for(task,4)
    asyncio.run(run())


def test_status_remains_available_while_chain_submission_is_slow(env,tmp_path):
    import threading,time
    logs,root,key,clock=configure_anchor(env,tmp_path);clock[0]+=61
    entered=threading.Event();release=threading.Event();errors=[]
    def slow(*args):entered.set();release.wait(3);return final(args[-1])
    def run():
        try:B.tick(logs,slow)
        except Exception as e:errors.append(e)
    thread=threading.Thread(target=run);thread.start()
    try:
        assert entered.wait(2)
        started=time.monotonic();value=B.status(logs)
        assert time.monotonic()-started<.5 and value['status']=='PENDING'
    finally:release.set();thread.join(3)
    assert not errors


def test_real_https_activity_filters_and_anchor_status_use_protected_backend(env):
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request
    from research_workspace_fixture import PASSWORD
    s,logs,_,key,grant,clock,cfg=env
    lc=cfg.parent/'https-accountability.json';write(lc,{'policy':'ACCOUNTABILITY_CONFIG_V1','state_directory':str(logs.root),'key_file':str(logs.key_path),'reader_grants':[str(grant)]})
    value=json.loads(cfg.read_bytes());value['accountability_config']=str(lc);write(cfg,value)
    with server(cfg.parent,prepared=(s,key,cfg)) as (_,_,origin,context,_):
        status,headers,login=request(origin,context,'/api/auth/login',method='POST',body={'username':'station.one','password':PASSWORD})
        assert status==200
        cookie=headers['set-cookie'].split(';')[0]
        def call(path,**kw):return request(origin,context,path,cookie=cookie,csrf=login['csrf_token'],**kw)
        status,headers,value=call('/api/accountability/activity',method='POST',body={'officer_uid':identifier(1),'section':'anchoring','event_id':identifier(901)})
        assert status==200 and value['human_read_confirmed'] is False
        request_id=headers['x-request-id']
        status,_,value=call('/api/accountability/logs',method='POST',body={**FILTERS,'account':'station.one','request_id':request_id})
        assert status==200 and any(v['request_details']['section']=='anchoring' for v in value['items'] if v['phase']=='COMPLETED')
        assert call('/api/accountability/anchoring')[2]['status']=='NOT_CONFIGURED'


@pytest.mark.parametrize('interrupt_at',[1,2])
def test_atomic_write_crash_recovers_exact_pending_or_verified_batch(env,tmp_path,monkeypatch,interrupt_at):
    logs,root,key,clock=configure_anchor(env,tmp_path);clock[0]+=61;calls=[];original=B.os.replace;counter=[0]
    def crash(a,b):
        counter[0]+=1
        if counter[0]==interrupt_at:raise OSError('fixture interruption before atomic replacement')
        return original(a,b)
    monkeypatch.setattr(B.os,'replace',crash)
    with pytest.raises(OSError):B.tick(logs,lambda *args:(calls.append(args[-1]['payload']) or final(args[-1])))
    monkeypatch.setattr(B.os,'replace',original)
    assert B.status(logs)['status']=='INTERRUPTED_WRITE_PENDING_RECOVERY'
    B.tick(logs,lambda *args:(calls.append(args[-1]['payload']) or final(args[-1])))
    assert B.status(logs)['private_chain_verified']
    assert len(calls)==1 # A receipt saved before the crash is recovered, not republished.
