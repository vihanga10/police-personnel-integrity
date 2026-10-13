"""Invented receipts test validation/storage, never establish live anchoring."""
import os,sys,json,sqlite3
from pathlib import Path
import pytest
from test_priority3 import env,saved,requested
from app.access import application_findings_commitments as A,application_anchor_observations as O
from app.access.application_anchor_guard import SourcePins
from app.access.research_service import ResearchService
from app.access.policy import AccessError
from app.access.research_policy import fingerprint
from test_scoped_access_api import Client
from app.access.research_app import create_app

def receipt(selection):
    public=A.generate(selection,os.urandom(32),os.urandom(32),salt=os.urandom(32))
    fabric=dict(status='FINAL',destination=dict(genesis_sha256='1'*64,channel='personnel',chaincode='findings-anchor-v1',namespace='findings-anchor-v1',organizations=['Org1MSP','Org2MSP']),payload=A.fabric_payload(public),transaction_id='2'*64,verification=dict(validation_code='VALID',organizations=['Org1MSP','Org2MSP'],block_sha256='3'*64))
    destination=dict(chain_id=11155111,contract='0x'+'4'*40,runtime_sha256='5'*64,writer='0x'+'6'*40,namespace='findings-anchor-v1',finality='FINALIZED')
    payload=dict(policy='FINDINGS_PUBLIC_ANCHOR_V1',namespace='findings-anchor-v1',publication_id=public['publication_id'],public_sha256=fingerprint(public),merkle_root=public['merkle_root'],fabric_destination_sha256=fingerprint(fabric['destination']),fabric_transaction_id=fabric['transaction_id'],fabric_receipt_sha256=fingerprint(fabric))
    chain=dict(status='FINAL',destination=destination,payload=payload,transaction_id='0x'+'7'*64,verification=dict(execution_status=1,finalized=True,independent_readback=True,block_sha256='8'*64))
    return public,destination,dict(status='BOTH_CHAINS_VERIFIED',fabric=fabric,public=chain,scope='APPLICATION_FINDINGS_PREFIX_ONLY',independent_witness_deployment_verified=False)

def test_observation_is_encrypted_immutable_scoped_and_new_entries_are_not_anchored(env):
    e=env;b,r=saved(e);s=A.select(e['store'],b['officer_uid']);p,d,result=receipt(s);O.record(e['store'],s,p,result,d)
    service=ResearchService(e['store']);status=O.status(service,e['tokens']['hq'][0],b['officer_uid'])
    assert status['both_chains_anchored'] and not status['fresh_chain_verification'] and not status['independent_witness_deployment_verified']
    assert b'BOTH_CHAINS_VERIFIED' not in e['store'].path.read_bytes()
    with e['store'].transaction() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM application_anchor_observations')
    requested(e,b,r);assert O.status(service,e['tokens']['hq'][0],b['officer_uid'])['status']=='NEW_FINDINGS_NOT_ANCHORED'
    with pytest.raises(AccessError):O.status(service,e['tokens']['dig'][0],'00000000-0000-0000-0000-000000000004')
    e['clock'][0]+=1800
    with pytest.raises(AccessError):O.status(service,e['tokens']['hq'][0],b['officer_uid'])

@pytest.mark.parametrize('fault',['payload','fabric','public','destination','simulation'])
def test_partial_simulated_or_mismatched_results_never_recorded(env,fault):
    b,_=saved(env);s=A.select(env['store'],b['officer_uid']);p,d,r=receipt(s)
    if fault=='payload':r['public']['payload']['merkle_root']='0'*64
    if fault=='fabric':r['fabric']['verification']['validation_code']='INVALID'
    if fault=='public':r['public']['verification']['finalized']=False
    if fault=='destination':r['public']['destination']={**d,'contract':'0x'+'9'*40}
    if fault=='simulation':r['scope']='ISOLATED_TEST_ONLY'
    with pytest.raises(ValueError):O.record(env['store'],s,p,r,d)

def test_pending_observation_never_claims_both_chains(env):
    b,_=saved(env);s=A.select(env['store'],b['officer_uid']);p,d,r=receipt(s);r.update(status='PENDING',public=dict(status='PENDING',reason='BOTH_ORIGINAL_RECEIPTS_REQUIRED',transaction_id='0x'+'7'*64))
    O.record(env['store'],s,p,r,d);assert not O.status(ResearchService(env['store']),env['tokens']['igp'][0],b['officer_uid'])['both_chains_anchored']

def test_https_status_has_no_receipt_upload_or_execute_route(env):
    b,_=saved(env);client=Client(create_app(env['store'],origin='https://access.test:9443'));token,csrf=env['tokens']['hq']
    from app.access.api import COOKIE
    url='/api/research/officers/'+b['officer_uid']+'/application-anchoring'
    assert client.request(url,cookie=COOKIE+'='+token)[0]==200
    assert client.request(url,'POST',body={},cookie=COOKIE+'='+token,csrf=csrf)[0] in (400,405)

def test_source_pins_detect_same_length_writes_restore_mtime_replacement_and_addition(tmp_path):
    tmp_path.chmod(0o700);f=tmp_path/'source';f.write_bytes(b'abcd');f.chmod(0o600);pin=SourcePins([tmp_path]);pin.check();st=f.stat();f.write_bytes(b'efgh');os.utime(f,ns=(st.st_atime_ns,st.st_mtime_ns))
    with pytest.raises(ValueError):pin.check()
    pin=SourcePins([tmp_path]);g=tmp_path/'another';g.write_bytes(b'x');g.chmod(0o600)
    with pytest.raises(ValueError):pin.check()

def test_owned_worker_deadline_denial_duplicate_and_missing_result_stop(tmp_path):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
    from anchor_application_findings import run_worker
    request='print('+repr(json.dumps(dict(request='SOURCE_CHECK',id=1,phase='TEST')))+',flush=True)\n'
    good=request+"input()\nprint('{\"result\":{\"status\":\"TEST_ONLY\"}}',flush=True)\n"
    assert run_worker([sys.executable,'-c',good],lambda:None,timeout=2)['status']=='TEST_ONLY'
    with pytest.raises(ValueError):run_worker([sys.executable,'-c',good],lambda:(_ for _ in ()).throw(ValueError('denied')),timeout=2)
    for code in ('import time;time.sleep(10)',request+"input()\n"+request+'input()\n',"print('{}',flush=True)"):
        with pytest.raises(ValueError):run_worker([sys.executable,'-c',code],lambda:None,timeout=.3)

def test_operator_key_recovery_and_encrypted_job_roundtrip(tmp_path):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
    from anchor_application_findings import initialize,keys,save_job,load_job
    tmp_path.chmod(0o700);repo=tmp_path/'repository';repo.mkdir(mode=0o700);app=tmp_path/'app';app.mkdir(mode=0o700)
    f=app/'accounts.json';f.write_text(json.dumps(dict(record_origin='GENERATED_RESEARCH_RECORDS')));f.chmod(0o600)
    root=tmp_path/'findings';assert not initialize(root,repo,app)['chain_submitted'];k=keys(root,repo);assert len(set(k.values()))==4
    job=dict(public=dict(publication_id='d'*64),selection=dict(officer_uid='private-fixture-identity'))
    assert save_job(root,job,k)=='d'*64 and load_job(root,'d'*64,k,repo)==job
    assert b'private-fixture-identity' not in (root/'jobs'/('d'*64)/'job.encrypted.json').read_bytes()
    backup=root/'backup/keys.json';backup.write_text('{}')
    with pytest.raises(ValueError):keys(root,repo)
