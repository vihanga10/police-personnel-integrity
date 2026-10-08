"""Synthetic fixtures only: no live stores, credentials, chains or research permit."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
import subprocess
import sys
import pytest
import app.identity.audit_gate as A
from app.identity.check_audit_gate import publication_hint
from app.identity.anchor_gate import POLICY as LIVE_POLICY, publication_plan
from app.identity.protected_commitment import digest
from test_anchor_gate import public_fixture
from test_protected_commitment import identity_crypto


@pytest.fixture
def verified(monkeypatch):
    p=public_fixture(); monkeypatch.setattr(A,'PUBLIC_SHA',digest(p))  # test-only fixture pin
    now=datetime.now(timezone.utc)
    c=dict(code_revision='a'*40,bundle_attempt_id='fixture-bundle',binding_attempt_id='fixture-binding',commitment_attempt_id='fixture-commitment',binding_artifact_sha256='b'*64)
    l=dict(policy=LIVE_POLICY,status='PASSED',public_payload_sha256=A.PUBLIC_SHA,checked_at=(now-timedelta(seconds=30)).isoformat(),completed_at=(now-timedelta(seconds=1)).isoformat(),scope=A.SCOPE,max_age_seconds=600,historical_claims='UNASSESSED',plan=publication_plan(p),code_revision=c['code_revision'],commitment_attempt_id=c['commitment_attempt_id'],binding_artifact_sha256=c['binding_artifact_sha256'])
    n=dict(channel='personnel',chaincode='officer-evidence-v1',genesis_sha256=A.FABRIC_GENESIS,genesis_identity=dict(policy='FABRIC_GENESIS_HEADER_DATA_V1',header_sha256=A.HEADER,data_sha256=A.DATA))
    f=dict(status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],public_payload_sha256=A.PUBLIC_SHA,fabric_result=dict(status='PASSED',mode='RECONCILE',officers=6596,original_valid_transactions=68,two_organization_readback=True,classification='UNASSESSED',public_payload_sha256=A.PUBLIC_SHA,batch_publication_id=p['batch_publication_id'],merkle_root=p['merkle_root'],network=n))
    i=dict(policy='SEPOLIA_PUBLICATION_TRANSACTION_V1',chain_id=11155111,genesis=A.GENESIS,contract=A.CONTRACT,deployment_transaction=A.DEPLOYMENT_TX,writer=A.WRITER,runtime_sha256=A.RUNTIME,config_sha256=A.CONFIG,batch='0x'+p['batch_publication_id'],public_payload_sha256=A.PUBLIC_SHA,merkle_root='0x'+p['merkle_root'])
    r=dict(status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],public_result=dict(policy='SEPOLIA_RESEARCH_PUBLICATION_V1',status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],identity=i,officers=6596,original_valid_transactions=68,two_rpc_readback=True,finalized=True,research_publication_complete=True,submitted_transactions_this_run=0,classification='UNASSESSED',sealed_block='0x123',sealed_block_hash='0x'+'c'*64,transaction_hashes=['0x'+format(j+1,'064x') for j in range(68)]))
    return p,l,f,r,c,now


def test_complete_fixture_permit_recovers_exactly(verified,tmp_path):
    p,l,f,r,c,now=verified; crypto=identity_crypto(tmp_path)
    permit=A.verify_inputs(p,l,f,r,c,now=now); env=A.seal_permit(crypto,crypto,permit)
    assert A.require_audit_permit(env,crypto,crypto,p,c,now=now)==permit
    assert permit['expires_at']==(datetime.fromisoformat(l['checked_at'])+timedelta(seconds=600)).isoformat()


@pytest.mark.parametrize('path,value',[
 ('l.status','PENDING'),('l.scope.officers',100),('l.max_age_seconds',3600),('l.historical_claims','ACCEPTED'),('l.binding_artifact_sha256','c'*64),('l.code_revision','c'*40),
 ('f.mode','EXECUTE'),('f.fabric_result.officers',100),('f.fabric_result.original_valid_transactions',67),('f.fabric_result.two_organization_readback',False),('f.fabric_result.merkle_root','d'*64),('f.fabric_result.network.chaincode','officer-evidence-test-v1'),('f.fabric_result.network.genesis_identity.header_sha256','e'*64),
 ('r.status','PENDING'),('r.public_result.officers',100),('r.public_result.finalized',False),('r.public_result.two_rpc_readback',False),('r.public_result.research_publication_complete',False),('r.public_result.mode','EXECUTE'),('r.public_result.submitted_transactions_this_run',1),('r.public_result.identity.chain_id',1),('r.public_result.identity.contract','0x'+'0'*40),('r.public_result.identity.runtime_sha256','d'*64),('r.public_result.identity.config_sha256','d'*64),('r.public_result.identity.merkle_root','0x'+'d'*64),('r.public_result.sealed_block','0x0'),('r.public_result.sealed_block_hash','invalid'),('r.public_result.classification','ACCEPTED')])
def test_mismatch_or_partial_batch_refused(verified,path,value):
    p,l,f,r,c,now=deepcopy(verified); target=dict(l=l,f=f,r=r); parts=path.split('.')
    for key in parts[:-1]: target=target[key]
    target[parts[-1]]=value
    with pytest.raises(Exception): A.verify_inputs(p,l,f,r,c,now=now)


@pytest.mark.parametrize('kind',['stale','future','incomplete_receipts','duplicate_receipts','changed_officer','missing_officer','future_completed'])
def test_inventory_and_time_required(verified,kind):
    p,l,f,r,c,now=deepcopy(verified)
    if kind=='stale': l['checked_at']=(now-timedelta(seconds=601)).isoformat()
    if kind=='future': l['checked_at']=(now+timedelta(seconds=1)).isoformat()
    if kind=='future_completed': l['completed_at']=(now+timedelta(seconds=1)).isoformat()
    if kind=='incomplete_receipts': r['public_result']['transaction_hashes'].pop()
    if kind=='duplicate_receipts': r['public_result']['transaction_hashes'][-1]=r['public_result']['transaction_hashes'][0]
    if kind=='changed_officer': p['officers'][0]['commitment']='f'*64
    if kind=='missing_officer': p['officers'].pop()
    with pytest.raises(Exception): A.verify_inputs(p,l,f,r,c,now=now)


@pytest.mark.parametrize('kind',['expired','future','context','ciphertext','plaintext','publication','scope','extended_expiry'])
def test_consumer_rejects_tamper_and_replay(verified,tmp_path,kind):
    p,l,f,r,c,now=verified; crypto=identity_crypto(tmp_path); permit=A.verify_inputs(p,l,f,r,c,now=now)
    if kind=='scope': permit['scope']=dict(A.SCOPE,officers=100)
    if kind=='extended_expiry': permit['expires_at']=(now+timedelta(hours=1)).isoformat()
    env=A.seal_permit(crypto,crypto,permit)
    if kind=='expired': now=datetime.fromisoformat(permit['expires_at'])
    if kind=='future': now=now-timedelta(seconds=60)
    if kind=='context': c=dict(c,binding_attempt_id='other')
    if kind=='ciphertext': env['ciphertext']='AAAA'+env['ciphertext'][4:]
    if kind=='plaintext': env=permit
    if kind=='publication': p=deepcopy(p); p['officers'][0]['commitment']='f'*64
    with pytest.raises(Exception): A.require_audit_permit(env,crypto,crypto,p,c,now=now)


def test_completion_file_is_only_blocking_hint(verified,tmp_path):
    p=verified[0]; tmp_path.chmod(0o700)
    assert publication_hint(tmp_path,p)=='PUBLIC_PUBLICATION_INCOMPLETE'
    journal=tmp_path/'publications'/p['batch_publication_id']; journal.mkdir(parents=True,mode=0o700)
    saved=journal/'PASSED.json'; saved.write_text('{"forged":"PASSED"}'); saved.chmod(0o600)
    assert publication_hint(tmp_path,p) is None  # still requires live reconciliation, never authorizes


def test_cli_has_no_execute_option():
    run=subprocess.run([sys.executable,'-m','app.identity.check_audit_gate','--help'],capture_output=True,text=True)
    assert run.returncode==0 and '--execute' not in run.stdout and '--reconcile' not in run.stdout


def test_partial_cli_returns_blocked_without_database_or_rpc(verified,tmp_path,monkeypatch):
    import app.identity.check_audit_gate as C
    p,l,f,r,c,now=verified
    monkeypatch.setattr(C,'PUBLIC_SHA',A.PUBLIC_SHA)
    monkeypatch.setattr(C,'private_path',lambda p,directory=False: p)
    monkeypatch.setattr(C,'private_output',lambda p,repo: (p.mkdir(parents=True,exist_ok=True) or p))
    monkeypatch.setattr(C.subprocess,'check_output',lambda args,**kw: '' if 'status' in args else c['code_revision'])
    def forbidden(*args,**kwargs): raise AssertionError('Partial batch must not launch any live subprocess')
    monkeypatch.setattr(C.subprocess,'run',forbidden)
    wallet=tmp_path/'wallet'; wallet.mkdir(); commitment=tmp_path/'commitment'; commitment.mkdir()
    import json
    (commitment/'public-commitments.json').write_text(json.dumps(p))
    argv=['check-audit-gate']
    for name in C.INHERITED:
        value=wallet if name=='wallet-root' else commitment if name=='commitment-attempt' else tmp_path/name
        argv.extend(['--'+name,str(value)])
    output=tmp_path/'output'; argv.extend(['--output-root',str(output),'--publication-fee-budget-eth','0.04'])
    monkeypatch.setattr(sys,'argv',argv)
    assert C.main()==2
    children=list(output.iterdir()); assert len(children)==1
    assert (children[0]/'BLOCKED.json').exists() and not (children[0]/'audit-permit.encrypted.json').exists()


def test_ready_runner_only_reconciles_then_refreshes_live_gate(verified,tmp_path,monkeypatch):
    import app.identity.check_audit_gate as C
    import json
    p,l,f,r,c,now=verified; crypto=identity_crypto(tmp_path)
    monkeypatch.setattr(C,'PUBLIC_SHA',A.PUBLIC_SHA)
    monkeypatch.setattr(C,'private_path',lambda p,directory=False: p)
    monkeypatch.setattr(C,'private_output',lambda p,repo: (p.mkdir(parents=True,exist_ok=True) or p))
    monkeypatch.setattr(C.subprocess,'check_output',lambda args,**kw: '' if 'status' in args else c['code_revision'])
    monkeypatch.setattr(C,'private_key_file',lambda path: crypto)
    monkeypatch.setattr(C,'verify_recovery',lambda *args: None)
    monkeypatch.setattr(C,'authenticate_gate',lambda *args,**kwargs: l)
    roots={name:tmp_path/name for name in C.INHERITED}
    roots['bundle-attempt']=tmp_path/c['bundle_attempt_id']; roots['binding-attempt']=tmp_path/c['binding_attempt_id']
    roots['commitment-attempt']=tmp_path/c['commitment_attempt_id']
    roots['commitment-attempt'].mkdir(); (roots['commitment-attempt']/'public-commitments.json').write_text(json.dumps(p))
    journal=roots['wallet-root']/'publications'/p['batch_publication_id']; journal.mkdir(parents=True)
    (journal/'PASSED.json').write_text('{}')
    calls=[]
    def fake_run(command,**kwargs):
        calls.append(command); assert '--execute' not in command
        root=Path(command[command.index('--output-root')+1]); child=root/'fresh'; child.mkdir(parents=True)
        if command[3]=='app.identity.anchor_research_public':
            assert command[-1]=='--reconcile'
            result=dict(r,fabric_attempt_id='fresh-fabric')
            (child/'RESULT.json').write_text(json.dumps(result))
            fabric_child=roots['fabric-output-root']/'fresh-fabric'; fabric_child.mkdir(parents=True)
            (fabric_child/'PASSED.json').write_text(json.dumps(f))
        else:
            assert command[3]=='app.identity.check_live_anchor_gate' and '--reconcile' not in command
            (child/'live-gate.encrypted.json').write_text('{}')
        return subprocess.CompletedProcess(command,0)
    monkeypatch.setattr(C.subprocess,'run',fake_run)
    output=tmp_path/'out'; argv=['check-audit-gate']
    for name,path in roots.items(): argv.extend(['--'+name,str(path)])
    argv.extend(['--output-root',str(output),'--publication-fee-budget-eth','0.04']); monkeypatch.setattr(sys,'argv',argv)
    assert C.main()==0 and len(calls)==2
    attempt=next(output.iterdir()); assert (attempt/'READY.json').exists()
    envelope=json.loads((attempt/'audit-permit.encrypted.json').read_text())
    assert A.require_audit_permit(envelope,crypto,crypto,p,c)['status']=='READY'
