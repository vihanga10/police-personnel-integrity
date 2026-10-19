"""Pipe/service results are doubles; public transport stays unprovisioned."""
from copy import deepcopy
import sys
import os
import pytest
from app.identity import findings_public_backend_service as S
from app.identity.protected_commitment import digest
from test_findings_public_backend_gate import public_fixture,grant,gate_fixture,build,prepared,prepare,recovered,key_data,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys


@pytest.fixture
def service(public_fixture,tmp_path):
    g=public_fixture['gate'];a,k=grant(g)
    worker=g.repo/'blockchain/public/findings/findings-public-backend-worker.js';worker.parent.mkdir(parents=True);worker.write_text('// test-only worker')
    root=tmp_path/'public-retention';root.mkdir(mode=0o700)
    key=tmp_path/'public.key';key.write_bytes(os.urandom(32));key.chmod(0o600)
    kwargs=dict(approval=a,trusted_keys=k,node_binary=sys.executable,network_config_file='fixture',witness_config_file='fixture',
        witness_config_sha256='f'*64,recovery_directory=root,recovery_key_file=key,timeout=10)
    s=g.selection
    result=dict(status='ISOLATED_PUBLIC_VERIFIED',mode=g.mode,operation=digest(dict(policy=S.POLICY,selection=s)),
        recovery_witness_transport='MTLS',recovery_witness_fixture=False,backend_public_runtime='FIXTURE_ONLY',
        live_chain_verification=False,public_transport_enabled=False,both_chains_anchored=False,independent_witness_deployment_verified=False,
        receipt=dict(status='FINAL',destination=s['destination'],payload=s['payload'],transaction_id='0x'+'a'*64,
            verification=dict(execution_status=1,finalized=True,independent_readback=True,block_sha256='b'*64)))
    return public_fixture,g,kwargs,result


def test_public_service_fixes_worker_and_rechecks_fabric_before_return(service,monkeypatch):
    t,g,kw,result=service;before=len(t['calls'])
    def exchange(command,job,guard,timeout):
        assert command[1]==str(g.repo/'blockchain/public/findings/findings-public-backend-worker.js')
        assert kw['recovery_key_file'].read_bytes().hex() not in str(job) and job['selection']==g.selection
        guard('SUBMIT',job['selection'],job['mode']);return result
    monkeypatch.setattr(S,'_exchange',exchange)
    value=S.run_public(g,**kw)
    assert len(t['calls'])==before+3
    assert value['public_finality_simulated'] is True and value['live_research_ready'] is False
    assert value['backend_gate']=='FULL_SOURCE_AND_FRESH_FABRIC'


@pytest.mark.parametrize('fault',['live','both','fixture','runtime','mode','payload','tx','validation','bool-status','operation','independence'])
def test_worker_result_cannot_claim_live_or_change_scope(service,monkeypatch,fault):
    _,g,kw,r=service
    if fault=='live':r['live_chain_verification']=True
    elif fault=='both':r['both_chains_anchored']=True
    elif fault=='fixture':r['recovery_witness_fixture']=True
    elif fault=='runtime':r['backend_public_runtime']='LIVE'
    elif fault=='mode':r['mode']='RECONCILE'
    elif fault=='payload':r['receipt']['payload']={}
    elif fault=='tx':r['receipt']['transaction_id']='invalid'
    elif fault=='validation':r['receipt']['verification']['finalized']=False
    elif fault=='bool-status':r['receipt']['verification']['execution_status']=True
    elif fault=='operation':r['operation']='f'*64
    else:r['independent_witness_deployment_verified']=True
    monkeypatch.setattr(S,'_exchange',lambda *args,**kwargs:r)
    with pytest.raises(ValueError):S.run_public(g,**kw)


def test_pending_is_explicit_and_never_reported_final(service,monkeypatch):
    _,g,kw,r=service;r['status']='PENDING';r['receipt']=dict(status='PENDING',reason='BOTH_ORIGINAL_RECEIPTS_REQUIRED',transaction_id='0x'+'a'*64)
    monkeypatch.setattr(S,'_exchange',lambda *args,**kwargs:r)
    result=S.run_public(g,**kw);assert result['status']=='PENDING' and result['live_research_ready'] is False


@pytest.mark.parametrize('fault',['key','storage','approval'])
def test_public_service_rejects_reused_fabric_key_store_or_wrong_approval_before_worker(service,monkeypatch,fault):
    _,g,kw,r=service
    if fault=='key':kw['recovery_key_file']=g.fabric.options['recovery_key_file']
    elif fault=='storage':kw['recovery_directory']=g.fabric.options['recovery_directory']
    else:kw['approval']['body']['policy']='wrong'
    monkeypatch.setattr(S,'_exchange',lambda *args,**kwargs:pytest.fail('Worker must not start'))
    with pytest.raises(ValueError):S.run_public(g,**kw)
