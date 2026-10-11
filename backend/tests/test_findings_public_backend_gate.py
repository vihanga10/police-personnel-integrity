"""Full source gate fixtures; Fabric transport substituted, no live readiness."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import base64
import sys
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity import findings_public_backend_gate as P
from app.identity.protected_commitment import digest,encoded
from test_findings_backend_gate import gate_fixture,build,prepared,prepare,recovered,key_data,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys


@pytest.fixture
def public_fixture(gate_fixture,tmp_path,monkeypatch):
    source=build(gate_fixture);reconcile=build(gate_fixture,'RECONCILE');s=source.selection
    fabric_root=tmp_path/'fabric-retention';fabric_root.mkdir(mode=0o700)
    fabric_key=tmp_path/'fabric.key';fabric_key.write_bytes(os.urandom(32));fabric_key.chmod(0o600)
    receipt=dict(status='FINAL',destination=s['destination'],payload=s['payload'],transaction_id='a'*64,
        verification=dict(validation_code='VALID',organizations=['Org1MSP','Org2MSP'],block_sha256='b'*64))
    calls=[]
    def fabric_double(gate,**opts):
        assert gate is reconcile and gate.mode=='RECONCILE'
        calls.append(deepcopy(opts))
        return dict(status='FABRIC_COMMIT_VERIFIED',mode='RECONCILE',backend_gate='FULL_REPLAY_AND_WITNESSED_FINDINGS',receipt=deepcopy(receipt))
    monkeypatch.setattr(P.S,'run_fabric',fabric_double)
    options=dict(approval={'fixture':True},trusted_keys={},node_binary=sys.executable,gateway_config_file='fixture',
        witness_config_file='fixture',witness_config_sha256='c'*64,recovery_directory=fabric_root,recovery_key_file=fabric_key,timeout=10)
    verifier=P.FabricReceiptVerifier(reconcile,**options)
    config=dict(policy='FINDINGS_PUBLIC_NETWORK_FIXTURE_V1',rpc_urls=['https://one.example.invalid/','https://two.example.invalid/'],
        max_fee_gwei='2',priority_fee_gwei='1',max_total_fee_eth='0.005',confirmations=12)
    destination=dict(chain_id=11155111,contract='0x'+'11'*20,writer='0x'+'22'*20,runtime_sha256='3'*64,
        namespace='findings-anchor-v1',finality='FINALIZED')
    gate=P.FindingsPublicBackendGate(source,verifier,config=config,destination=destination)
    return dict(gate=gate,source=source,verifier=verifier,receipt=receipt,calls=calls,original=gate_fixture)


def grant(gate,mode=None):
    key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    fmt=lambda t:t.isoformat(timespec='milliseconds').replace('+00:00','Z')
    body=dict(policy=P.POLICY,key_id='public',mode=mode or gate.mode,selection=gate.selection,
        issued_at=fmt(now-timedelta(seconds=1)),expires_at=fmt(now+timedelta(seconds=60)))
    return dict(body=body,signature=base64.b64encode(key.sign(encoded(body))).decode()),{'public':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}


def test_public_payload_derived_from_verified_fabric_and_source_rechecked(public_fixture):
    t=public_fixture;g=t['gate'];s=g.selection;p=s['payload']
    assert p['fabric_receipt_sha256']==digest(t['receipt']) and p['fabric_transaction_id']==t['receipt']['transaction_id']
    assert p['fabric_destination_sha256']==digest(t['receipt']['destination'])
    before=len(t['calls']);loaded=len(t['original']['calls'])
    for action in P.ACTIONS:assert g.check(action,s,g.mode)==s
    assert len(t['calls'])==before+len(P.ACTIONS) and len(t['original']['calls'])==loaded+2*len(P.ACTIONS)
    s['fabric_receipt']['transaction_id']='d'*64
    assert g.selection['fabric_receipt']['transaction_id']=='a'*64


@pytest.mark.parametrize('field',['transaction_id','payload','destination','verification'])
def test_changed_fabric_receipt_blocks_public_boundary(public_fixture,field):
    t=public_fixture;r=t['receipt']
    if field=='transaction_id':r[field]='d'*64
    elif field=='verification':r[field]['block_sha256']='d'*64
    else:r[field]['unexpected']='changed'
    with pytest.raises(ValueError):t['gate'].check('SUBMIT',t['gate'].selection,'EXECUTE')


def test_full_source_mutation_blocks_before_fabric_observation(public_fixture):
    t=public_fixture;t['original']['s']['snapshot']['catalog']['unexpected']='changed';before=len(t['calls'])
    with pytest.raises(ValueError):t['gate'].check('SIGN',t['gate'].selection,'EXECUTE')
    assert len(t['calls'])==before


@pytest.mark.parametrize('fault',['live','duplicate','fee','confirmations','boolean','extra'])
def test_network_policy_cannot_enable_live_endpoints_or_loosen_bounds(public_fixture,fault):
    g=public_fixture['gate'];c=g.config
    if fault=='live':c['rpc_urls'][0]='https://provider.example/'
    elif fault=='duplicate':c['rpc_urls'][1]=c['rpc_urls'][0]
    elif fault=='fee':c['max_fee_gwei']='21'
    elif fault=='confirmations':c['confirmations']=11
    elif fault=='boolean':c['confirmations']=True
    else:c['unexpected']='x'
    with pytest.raises(ValueError):g.check('PREFLIGHT',g.selection,'EXECUTE')


def test_configuration_replacement_and_public_recovery_key_reuse_rejected(public_fixture):
    t=public_fixture;g=t['gate'];g.check_recovery_key(os.urandom(32))
    with pytest.raises(ValueError,match='Separate Fabric/public'):
        g.check_recovery_key(t['verifier'].options['recovery_key_file'].read_bytes())
    t['verifier'].options['timeout']=20
    with pytest.raises(ValueError):g.check('OBSERVE',g.selection,'EXECUTE')


@pytest.mark.parametrize('fault',['policy','mode','signature','expiry','selection'])
def test_signed_public_approval_cannot_cross_scope(public_fixture,fault):
    g=public_fixture['gate'];a,k=grant(g)
    P.verify_approval(a,k,g.selection,g.mode)
    if fault=='policy':a['body']['policy']='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1'
    elif fault=='mode':a['body']['mode']='RECONCILE'
    elif fault=='signature':a['signature']=base64.b64encode(b'X'*64).decode()
    elif fault=='expiry':a['body']['expires_at']=a['body']['issued_at']
    else:a['body']['selection']['history_sha256']='f'*64
    with pytest.raises(Exception):P.verify_approval(a,k,g.selection,g.mode)


@pytest.mark.parametrize('seconds',[-10,700])
def test_authentic_signed_approval_still_requires_fresh_bounded_time(public_fixture,seconds):
    g=public_fixture['gate'];a,_=grant(g);key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    fmt=lambda t:t.isoformat(timespec='milliseconds').replace('+00:00','Z')
    a['body']['issued_at']=fmt(now-timedelta(seconds=100))
    a['body']['expires_at']=fmt(now+timedelta(seconds=seconds))
    a['signature']=base64.b64encode(key.sign(encoded(a['body']))).decode()
    trusted={'public':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    with pytest.raises(ValueError,match='Fresh bounded'):P.verify_approval(a,trusted,g.selection,g.mode)


def test_source_change_during_fabric_observation_blocks_approval(public_fixture,monkeypatch):
    t=public_fixture;original=P.S.run_fabric
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        t['original']['s']['snapshot']['catalog']['after-observation']='changed'
        return result
    monkeypatch.setattr(P.S,'run_fabric',changed)
    with pytest.raises(ValueError):t['gate'].check('SUBMIT',t['gate'].selection,'EXECUTE')
