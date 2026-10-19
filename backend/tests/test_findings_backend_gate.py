"""Isolated gate wiring: real AEAD/history/permit; the full-loader call is substituted.

These tests never establish live chain readiness. Existing fixture transport is
explicitly substituted only at its configuration check in the gate fixture.
"""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity import findings_backend_gate as G
from app.identity.protected_commitment import encoded
from test_findings_commitments import prepared,prepare,recovered,key_data
from test_findings_commitments import witnessed_findings,registered,journal,output,witnessed,setup,verified,keys
from test_encrypted_findings_journal import review,advance


@pytest.fixture
def gate_fixture(prepared,monkeypatch):
    t=prepared;r=prepare(t);s=t['s'];f=t['d']['adapter'];repo=s['repo']
    calls=[]
    def loader(*args):calls.append(1);return s['snapshot']
    monkeypatch.setattr(G,'load_verified_snapshot',loader)
    monkeypatch.setattr(G,'committed_repository',lambda root,revision:Path(root))
    monkeypatch.setattr(G,'original_keys',lambda *args:t['original'])
    monkeypatch.setattr(G.C,'load_keys',lambda *args:(t['keys'],t['backup']))
    # The operational constructor rejects this unless this explicit test override
    # is made. Real mTLS transport is tested in the existing transport suites.
    f.fixture_transport=False
    monkeypatch.setattr(f,'_config',lambda: f.registry._config())
    args=SimpleNamespace(commitment_key_file='fixture-only',backup_commitment_key_file='fixture-only-backup')
    options=dict(key_file='fixture-only',backup_key_file='fixture-only-backup',commitment_directory=t['root'],
        private_sha256=r['private_artifact_sha256'],public_sha256=r['public_sha256'],
        gateway_config_sha256='9'*64,destination=dict(genesis_sha256='8'*64,channel='personnel',
            chaincode='findings-anchor-v1',namespace='findings-anchor-v1',organizations=['Org1MSP','Org2MSP']))
    return dict(t=t,f=f,s=s,calls=calls,args=args,options=options,repo=repo)


def build(t,mode='EXECUTE'):
    return G.FindingsBackendGate(t['args'],t['repo'],t['s']['snapshot']['context']['code_revision'],
        t['f'],mode=mode,**t['options'])


def test_gate_derives_payload_and_replays_every_boundary(gate_fixture):
    t=gate_fixture;g=build(t);p=recovered(t['t'])['public']
    assert g.selection['payload']['publication_id']==p['publication_id']
    assert g.selection['payload']['merkle_root']==p['merkle_root']
    initial=len(t['calls'])
    for action in ('ENTRY','ENDORSE','BEFORE_SUBMIT','FINAL','RETURN'):
        assert g.check(action,g.selection,'EXECUTE')==g.selection
    assert len(t['calls'])==initial+5
    text=str(g.selection)
    for secret in ('officer_uid','recorded_at','reason','salt','content_key'):assert secret not in text


@pytest.mark.parametrize('kind',['fixture','public-pin','private-pin','destination'])
def test_bad_backend_setup_stops(gate_fixture,kind):
    t=gate_fixture
    if kind=='fixture':t['f'].fixture_transport=True
    elif kind=='public-pin':t['options']['public_sha256']='f'*64
    elif kind=='private-pin':t['options']['private_sha256']='f'*64
    else:t['options']['destination']['chaincode']='officer-evidence-v1'
    with pytest.raises(ValueError):build(t)


@pytest.mark.parametrize('part',['catalog','bindings','manifest','public'])
def test_source_mutation_blocks_next_boundary(gate_fixture,part):
    t=gate_fixture;g=build(t);t['s']['snapshot'][part]['unexpected']='changed'
    with pytest.raises(ValueError):g.check('BEFORE_SUBMIT',g.selection,'EXECUTE')


def test_fixture_witness_change_cannot_reuse_gate(gate_fixture):
    t=gate_fixture;g=build(t);t['f'].fixture_transport=True
    with pytest.raises(ValueError):g.check('FINAL',g.selection,'EXECUTE')


def test_artifact_tampering_blocks_next_boundary(gate_fixture):
    t=gate_fixture;g=build(t);p=t['t']['root']/G.C.PRIVATE_NAME
    p.write_bytes(p.read_bytes()+b' ')
    with pytest.raises(ValueError):g.check('BEFORE_SUBMIT',g.selection,'EXECUTE')


@pytest.mark.parametrize('change',['action','mode','payload'])
def test_guard_scope_cannot_be_nominated(gate_fixture,change):
    g=build(gate_fixture);s=g.selection;action='ENTRY';mode='EXECUTE'
    if change=='action':action='SKIP_REPLAY'
    elif change=='mode':mode='RECONCILE'
    else:s['payload']['publication_id']='f'*64
    with pytest.raises(ValueError):g.check(action,s,mode)


def test_selection_copy_cannot_modify_gate(gate_fixture):
    g=build(gate_fixture);s=g.selection;s['payload']['merkle_root']='f'*64
    assert g.selection['payload']['merkle_root']!=s['payload']['merkle_root']


def test_execute_rejects_new_review_but_reconcile_preserves_original_prefix(gate_fixture):
    t=gate_fixture;execute=build(t);reconcile=build(t,'RECONCILE')
    d=t['t']['d']['t']['d'];tip=t['f'].select()['journal_tip'];advance(d)
    # Existing test helper issues an explicitly legacy review; the journal
    # preserves it without asserting temporal reviewer authorization.
    t['f'].append_review(intent=review(d,tip))
    with pytest.raises(ValueError,match='Latest witnessed'):execute.check('BEFORE_SUBMIT',execute.selection,'EXECUTE')
    assert reconcile.check('RECONCILE',reconcile.selection,'RECONCILE')==reconcile.selection


def test_replay_loader_failure_stops_before_next_boundary(gate_fixture,monkeypatch):
    g=build(gate_fixture)
    def expired(*args):raise ValueError('Audit permit expired')
    monkeypatch.setattr(G,'load_verified_snapshot',expired)
    with pytest.raises(ValueError,match='expired'):g.check('BEFORE_SUBMIT',g.selection,'EXECUTE')


def test_latest_findings_witness_outage_has_no_fallback(gate_fixture,monkeypatch):
    g=build(gate_fixture)
    def offline():raise ValueError('Witness unavailable')
    monkeypatch.setattr(g.findings.client,'head',offline)
    with pytest.raises(ValueError,match='Witness unavailable'):g.check('FINAL',g.selection,'EXECUTE')


def test_recovery_key_separation(gate_fixture):
    t=gate_fixture;g=build(t)
    g.check_recovery_key(b'R'*32)
    for key in (t['t']['keys'].content,t['t']['original'].publication,
            next(iter(t['s']['crypto'].encryption_keys.values())),b'short'):
        with pytest.raises(ValueError):g.check_recovery_key(key)


@pytest.mark.parametrize('mode',['EXECUTE','RECONCILE'])
def test_approval_matches_node_wire_and_mode(gate_fixture,mode):
    g=build(gate_fixture,mode);key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    fmt=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z')
    body=dict(policy=G.POLICY,key_id='backend',mode=mode,issued_at=fmt(now-timedelta(seconds=1)),
        expires_at=fmt(now+timedelta(seconds=30)),selection=g.selection)
    grant=dict(body=body,signature=base64.b64encode(key.sign(encoded(body))).decode())
    keys={'backend':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    G.verify_approval(grant,keys,g.selection,mode)
    with pytest.raises(ValueError):G.verify_approval(grant,keys,g.selection,'RECONCILE' if mode=='EXECUTE' else 'EXECUTE')
    expired=deepcopy(body);expired['expires_at']=fmt(now-timedelta(milliseconds=1))
    grant=dict(body=expired,signature=base64.b64encode(key.sign(encoded(expired))).decode())
    with pytest.raises(ValueError):G.verify_approval(grant,keys,g.selection,mode)
