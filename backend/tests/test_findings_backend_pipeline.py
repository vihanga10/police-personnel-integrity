"""Real signed approvals and protected findings gates; source/chain fixtures.

The original snapshot loader and network services are explicit test substitutes.
This suite never establishes original-batch replay or live/public readiness.
"""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity import findings_backend_pipeline as B
from app.identity.protected_commitment import encoded,digest
from test_findings_public_backend_gate import public_fixture,grant,gate_fixture,build,prepared,prepare,recovered,key_data,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys


@pytest.fixture
def pipeline(public_fixture,monkeypatch):
    t=public_fixture;signer=Ed25519PrivateKey.generate()
    trust={'backend':signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    fopts={k:v for k,v in t['verifier'].options.items() if k in B.FABRIC_FIELDS}
    uopts=dict(node_binary=fopts['node_binary'],network_config_file='fixture-network',witness_config_file='fixture-public-witness',
        witness_config_sha256='d'*64,recovery_directory='fixture-public-recovery',recovery_key_file='fixture-public-key',
        timeout=10,runtime_config_file='fixture-runtime',runtime_config_sha256='e'*64)
    calls=[];fault={'fabric':None,'public':None}
    def fabric(gate,**opts):
        B.G.verify_approval(opts['approval'],opts['trusted_keys'],gate.selection,gate.mode)
        calls.append(('fabric',gate.mode));gate.check('OBSERVE',gate.selection,gate.mode)
        r=deepcopy(t['receipt'])
        if fault['fabric']=='changed':r['transaction_id']='f'*64
        if fault['fabric']=='invalid':r['verification']['validation_code']='MVCC_READ_CONFLICT'
        if fault['fabric']=='outage':raise ValueError('Fabric unavailable')
        return dict(status='FABRIC_COMMIT_VERIFIED',mode=gate.mode,backend_gate='FULL_REPLAY_AND_WITNESSED_FINDINGS',receipt=r)
    def public(gate,**opts):
        B.P.verify_approval(opts['approval'],opts['trusted_keys'],gate.selection,gate.mode)
        calls.append(('public',gate.mode));gate.check('SIGN' if gate.mode=='EXECUTE' else 'OBSERVE',gate.selection,gate.mode)
        if fault['public']=='uncertain':raise ValueError('Uncertain original submission')
        if fault['public']=='source-change':t['original']['s']['snapshot']['catalog']['changed']=True
        return dict(status='PENDING' if fault['public']=='pending' else 'ISOLATED_PUBLIC_VERIFIED',
            mode=gate.mode,backend_gate='FULL_SOURCE_AND_FRESH_FABRIC',receipt={'test-only':True},
            public_finality_simulated=True,provider_independence_verified=False,
            both_chains_anchored=False,live_research_ready=fault['public']=='live')
    monkeypatch.setattr(B.F,'run_fabric',fabric);monkeypatch.setattr(B.U,'run_public',public)
    def make(mode='EXECUTE'):
        source=t['source'] if mode=='EXECUTE' else build(t['original'],'RECONCILE')
        return B.FindingsBackendPipeline(source,t['verifier'].gate,fabric_options=fopts,public_options=uopts,
            fabric_trusted_keys=trust,public_trusted_keys=trust,public_config=t['gate'].config,public_destination=t['gate'].destination)
    def signed(policy,selection,mode='EXECUTE',expired=False):
        now=datetime.now(timezone.utc);fmt=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z')
        body=dict(policy=policy,key_id='backend',mode=mode,selection=deepcopy(selection),issued_at=fmt(now-timedelta(seconds=2)),
            expires_at=fmt(now-timedelta(seconds=1) if expired else now+timedelta(seconds=598)))
        return dict(body=body,signature=base64.b64encode(signer.sign(encoded(body))).decode())
    p=make();fgrant=lambda mode='EXECUTE':signed(B.G.POLICY,p.fabric_selection(),mode)
    def ready(mode='EXECUTE'):
        current=p if mode=='EXECUTE' else make(mode);read=signed(B.G.POLICY,current.fabric_selection(),'RECONCILE')
        selection=current.public_selection(read)
        return current,read,selection,signed(B.P.POLICY,selection,mode)
    return dict(p=p,t=t,make=make,signed=signed,fgrant=fgrant,ready=ready,calls=calls,fault=fault,fopts=fopts,uopts=uopts)


def test_pipeline_connects_findings_fabric_receipt_and_public_approval(pipeline):
    t=pipeline;p=t['p'];f=p.run_fabric(t['fgrant']());p,read,s,grant=t['ready']()
    assert s['fabric_receipt']==f['receipt'] and s['payload']['fabric_receipt_sha256']==digest(f['receipt'])
    result=p.run_public(fabric_read_approval=read,public_approval=grant,expected_selection=s)
    assert result['status']=='ISOLATED_PIPELINE_VERIFIED' and result['live_research_ready'] is False
    assert result['fabric_receipt']==f['receipt'] and result['public_selection']==s
    assert t['calls'].count(('fabric','EXECUTE'))==1 and t['calls'].count(('public','EXECUTE'))==1
    assert t['calls'].count(('fabric','RECONCILE'))>=3


@pytest.mark.parametrize('phase',['fabric','read','public'])
@pytest.mark.parametrize('fault',['signature','expired','mode','selection','policy'])
def test_approval_denial_stops_selected_service(pipeline,phase,fault):
    t=pipeline;p=t['p']
    if phase=='fabric':selection=p.fabric_selection();policy=B.G.POLICY;mode='EXECUTE'
    elif phase=='read':selection=p.fabric_selection();policy=B.G.POLICY;mode='RECONCILE'
    else:p,read,selection,_=t['ready']();policy=B.P.POLICY;mode='EXECUTE'
    g=t['signed']('wrong' if fault=='policy' else policy,
        {} if fault=='selection' else selection,'OTHER' if fault=='mode' else mode,expired=fault=='expired')
    if fault=='signature':g['signature']=base64.b64encode(b'X'*64).decode()
    before=list(t['calls'])
    with pytest.raises(Exception):
        if phase=='fabric':p.run_fabric(g)
        elif phase=='read':p.public_selection(g)
        else:p.run_public(fabric_read_approval=read,public_approval=g,expected_selection=selection)
    if phase in ('fabric','read'):assert t['calls']==before
    else:assert all(c[0]!='public' for c in t['calls'][len(before):])


@pytest.mark.parametrize('field',['fabric_options','public_options','fabric_trusted_keys','public_trusted_keys','public_config','public_destination'])
def test_pipeline_configuration_mutation_has_no_fallback(pipeline,field):
    p=pipeline['p'];getattr(p,field)['unexpected']=True
    with pytest.raises(ValueError,match='configuration changed'):p.fabric_selection()


def test_public_without_fresh_fabric_receipt_stops_before_public_service(pipeline):
    t=pipeline;p,read,s,g=t['ready']();t['fault']['fabric']='outage';before=len(t['calls'])
    with pytest.raises(ValueError):p.run_public(fabric_read_approval=read,public_approval=g,expected_selection=s)
    assert all(c[0]!='public' for c in t['calls'][before:])


def test_original_receipt_change_rejects_signed_public_plan(pipeline):
    t=pipeline;p,read,s,g=t['ready']();t['fault']['fabric']='changed'
    with pytest.raises(ValueError,match='selection differs'):p.run_public(fabric_read_approval=read,public_approval=g,expected_selection=s)


def test_invalid_fabric_cannot_advance_public_phase(pipeline):
    t=pipeline;t['fault']['fabric']='invalid'
    with pytest.raises(ValueError):t['p'].run_fabric(t['fgrant']())
    with pytest.raises(ValueError):t['p'].public_selection(t['fgrant']('RECONCILE'))


@pytest.mark.parametrize('mode',['EXECUTE','RECONCILE'])
def test_explicit_pending_is_not_success_or_automatic_retry(pipeline,mode):
    t=pipeline;p,r,s,g=t['ready'](mode);t['fault']['public']='pending';before=len(t['calls'])
    result=p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s)
    assert result['status']=='PENDING' and result['both_chains_anchored'] is False
    assert t['calls'][before:].count(('public',mode))==1


def test_uncertain_public_operation_never_triggers_execute_retry(pipeline):
    t=pipeline;p,r,s,g=t['ready']();t['fault']['public']='uncertain';before=len(t['calls'])
    with pytest.raises(ValueError,match='Uncertain'):p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s)
    assert t['calls'][before:].count(('public','EXECUTE'))==1


def test_reconstructed_readonly_pipeline_preserves_selection(pipeline):
    t=pipeline;p,r,s,g=t['ready']();original=p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s)
    p,r,s2,g=t['ready']('RECONCILE');before=len(t['calls']);result=p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s2)
    assert s2==s and result['workflow_sha256']==original['workflow_sha256']
    assert all(mode=='RECONCILE' for _,mode in t['calls'][before:])


def test_source_change_after_public_worker_blocks_return(pipeline):
    t=pipeline;p,r,s,g=t['ready']();t['fault']['public']='source-change'
    with pytest.raises(ValueError):p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s)


def test_result_cannot_claim_live_readiness(pipeline):
    t=pipeline;p,r,s,g=t['ready']();t['fault']['public']='live'
    with pytest.raises(ValueError,match='Isolated public'):p.run_public(fabric_read_approval=r,public_approval=g,expected_selection=s)


def test_source_expiry_is_not_refreshed_by_pipeline(pipeline,monkeypatch):
    def expired(*args):raise ValueError('Original audit permit expired')
    monkeypatch.setattr(B.G,'load_verified_snapshot',expired)
    with pytest.raises(ValueError,match='expired'):pipeline['p'].fabric_selection()
