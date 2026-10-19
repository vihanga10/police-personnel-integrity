"""Independent encrypted test witness plus actual loopback mutual TLS; no deployment."""
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from uuid import UUID
import base64
import json
import socket
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.identity import findings_tip_witness as A
from app.identity import findings_tip_registry as R
from app.identity import recording_tip_witness as W
from app.identity import witness_secure_transport as T
from app.identity import observed_recording_journal as J
from app.security.identity_crypto import IdentityCrypto
from test_findings_tip_registry import registered,journal,append as local_append,authorization,OP2,REGISTRY
from test_encrypted_findings_journal import add,advance,review,OP,ID,LEDGER
from test_protected_contradiction_runner import output,run,recover,next_checkpoint
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup,OFFICER
from test_protected_recording_review import verified,keys
from test_witness_secure_transport import certs,listener


@pytest.fixture
def witnessed_findings(registered,tmp_path):
    t=registered;r=t['r'];root=tmp_path/'findings-witness';root.mkdir(mode=0o700)
    config=dict(active_encryption_key_version='fw-enc',active_lookup_key_version='fw-lookup',
        encryption_keys={'fw-enc':base64.b64encode(b'V'*32).decode()},
        lookup_keys={'fw-lookup':base64.b64encode(b'Q'*32).decode()})
    copies=[]
    for name in ('fw-primary.json','fw-backup.json'):
        p=tmp_path/name;p.write_text(json.dumps(config));p.chmod(0o600);copies.append(IdentityCrypto(p))
    signer=Ed25519PrivateKey.generate();args=dict(root=root,repo=r.journal.repo,witness_id='fixture-findings-witness',
        registry_id=r.registry_id,journal_anchor=A.findings_scope_anchor(r.registry_id,r.journal.ledger_id),
        crypto=copies[0],backup=copies[1],signer=signer,key_id='findings-witness',
        witness_keys={'findings-witness':J._public(signer)},writer_keys=r.registry_keys)
    server=W.DurableTipWitness(**args);enrollment=server.initialize()
    client_args=dict(witness_id=args['witness_id'],registry_id=r.registry_id,journal_anchor=args['journal_anchor'],
        signer=r.signer,key_id=r.key_id,writer_keys=r.registry_keys,witness_keys=args['witness_keys'])
    client=W.WitnessClient(**client_args,exchange=server.exchange)
    adapter=A.WitnessedFindingsRegistry(r,client,fixture_transport=True)
    return dict(t=t,server=server,args=args,enrollment=enrollment,client=client,client_args=client_args,adapter=adapter)


def append(d,**changes):
    params=dict(operation_id=OP,finding_id=ID,receipt_path=d['t']['d']['output']);params.update(changes)
    return d['adapter'].append_receipt(**params)


def authorize(d,journal_tip,**changes):
    now=J._now();t=d['t'];args=dict(signer=t['recovery'],key_id='tip-recovery',journal_tip=journal_tip,
        operation_id=OP,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=60)).isoformat())
    args.update(changes);return d['adapter'].authorize_recovery(**args)


def inventory(d):
    return {str(p):p.read_bytes() for root in (d['server'].root,d['t']['r'].root,d['t']['d']['ledger'].root) for p in root.iterdir()}


def test_empty_enrolled_selection_is_explicit_not_automatic_enrollment(witnessed_findings):
    d=witnessed_findings;s=d['adapter'].select()
    assert s['registry_tip']==d['t']['r'].empty_tip() and s['entries']==[]
    assert d['client'].head() is None and len(list(d['server'].root.iterdir()))==1


def test_append_restart_and_redacted_summary(witnessed_findings):
    d=witnessed_findings;result=append(d);before=inventory(d)
    server=W.DurableTipWitness(**d['args'],expected_enrollment=d['enrollment'])
    client=W.WitnessClient(**d['client_args'],exchange=server.exchange)
    restarted=R.FindingsTipRegistry(**d['t']['kwargs'])
    adapter=A.WitnessedFindingsRegistry(restarted,client,fixture_transport=True);s=adapter.select()
    assert s['registry_tip']==result['registry_tip'] and s['journal_tip']==result['journal_tip']
    assert s['entries'][0]['entry']['finding']==recover(d['t']['d']['t'],d['t']['d']['output'])
    assert inventory(d)==before and result['status']=='WITNESSED'
    assert OFFICER not in json.dumps(result) and not result['findings_anchored']
    assert all(OFFICER not in p.read_text() for p in d['server'].root.iterdir())


def test_correction_review_and_retry_preserve_original(witnessed_findings):
    d=witnessed_findings;first=append(d);before=inventory(d)
    assert append(d)['status']=='ALREADY_WITNESSED' and inventory(d)==before
    advance(d['t']['d']);second=append(d,operation_id=OP2,supersedes=first['journal_tip']['entry_sha256'],reason='fixture correction')
    advance(d['t']['d']);token=review(d['t']['d'],second['journal_tip'])
    third=d['adapter'].append_review(intent=token)
    assert d['adapter'].append_review(intent=token)['status']=='ALREADY_WITNESSED'
    assert third['registry_tip']['sequence']==3
    assert [e['entry']['kind'] for e in d['adapter'].select()['entries']]==['FINDING','CORRECTION','REVIEW']
    assert all(__import__('pathlib').Path(p).read_bytes()==data for p,data in before.items())


@pytest.mark.parametrize('kind',['journal','registry','both'])
def test_local_rollback_cannot_use_stale_prefix(witnessed_findings,kind):
    d=witnessed_findings;first=append(d);advance(d['t']['d'])
    latest=append(d,operation_id=OP2,finding_id=str(UUID(int=299)))
    if kind in ('journal','both'):(d['t']['d']['ledger'].root/'entry-00000002.encrypted.json').unlink()
    if kind in ('registry','both'):(d['t']['r'].root/'entry-00000002.encrypted.json').unlink()
    assert d['client'].head()['sequence']==latest['registry_tip']['sequence']
    with pytest.raises(ValueError):d['adapter'].select()
    with pytest.raises(ValueError):append(d)


@pytest.mark.parametrize('operation',['select','append','authorize','recover'])
def test_witness_outage_has_no_cached_tip_fallback(witnessed_findings,operation):
    d=witnessed_findings;append(d);before=inventory(d)
    def offline(_):raise OSError('fixture witness unavailable')
    d['client'].exchange=offline
    with pytest.raises(OSError):
        if operation=='select':d['adapter'].select()
        elif operation=='append':append(d)
        elif operation=='authorize':authorize(d,d['t']['d']['ledger'].empty_tip())
        else:d['adapter'].recover({})
    assert inventory(d)==before


def test_journal_only_pending_write_requires_signed_recovery(witnessed_findings):
    d=witnessed_findings;new=add(d['t']['d'])
    with pytest.raises(ValueError):d['adapter'].select()
    result=d['adapter'].recover(authorize(d,new['tip']))
    assert result['status']=='WITNESSED' and d['client'].head()['sequence']==1
    assert len(d['adapter'].select()['entries'])==1
    assert append(d)['status']=='ALREADY_WITNESSED'


def test_registry_published_before_witness_requires_inventory_authorized_reconciliation(witnessed_findings):
    d=witnessed_findings;local=local_append(d['t'])
    assert d['client'].head() is None
    with pytest.raises(ValueError):d['adapter'].select()
    token=authorize(d,local['journal_tip'],pending_registry_tip=local['registry_tip'])
    before=inventory(d);result=d['adapter'].recover(token)
    assert result['registry_tip']==local['registry_tip'] and d['client'].head()['sequence']==1
    assert all(__import__('pathlib').Path(p).read_bytes()==data for p,data in before.items())
    assert len(d['adapter'].select()['entries'])==1
    with pytest.raises(ValueError,match='predecessor'):d['adapter'].recover(token)


def test_lost_witness_response_after_commit_uses_fresh_head_for_retry(witnessed_findings):
    d=witnessed_findings;original=d['client'].exchange
    def lost(receipt):
        result=original(receipt)
        if receipt['payload']['operation']=='CAS':raise OSError('fixture response lost after witness commit')
        return result
    d['client'].exchange=lost
    with pytest.raises(OSError):append(d)
    d['client'].exchange=original;before=inventory(d)
    assert d['client'].head()['sequence']==1 and append(d)['status']=='ALREADY_WITNESSED'
    assert inventory(d)==before and len(d['adapter'].select()['entries'])==1


def test_witness_failure_before_commit_leaves_reconcilable_registry(witnessed_findings):
    d=witnessed_findings;original=d['client'].exchange
    def fail(receipt):
        if receipt['payload']['operation']=='CAS':raise OSError('fixture CAS failed before commit')
        return original(receipt)
    d['client'].exchange=fail
    with pytest.raises(OSError):append(d)
    d['client'].exchange=original
    r=d['t']['r'];j=d['t']['d']['ledger']
    rp=r.root/'entry-00000001.encrypted.json';jp=j.root/'entry-00000001.encrypted.json'
    regtip=r._tip(1,sha256(rp.read_bytes()).hexdigest());jtip=j._tip(1,sha256(jp.read_bytes()).hexdigest())
    result=d['adapter'].recover(authorize(d,jtip,pending_registry_tip=regtip))
    assert result['registry_tip']==regtip and len(d['adapter'].select()['entries'])==1


@pytest.mark.parametrize('kind',['tampered','expired','foreign-key','changed-inventory'])
def test_bad_recovery_never_advances_witness(witnessed_findings,kind):
    d=witnessed_findings;new=add(d['t']['d']);token=authorize(d,new['tip'])
    if kind=='tampered':token['payload']['operation_id']=OP2
    elif kind=='expired':d['t']['d']['t']['s']['clock'][0]+=timedelta(seconds=61)
    elif kind=='foreign-key':token['key_id']='foreign'
    else:(d['t']['r'].root/'unknown').write_text('fixture change')
    with pytest.raises(ValueError):d['adapter'].recover(token)
    assert d['client'].head() is None and not list(d['server'].root.glob('advance-*'))


@pytest.mark.parametrize('kind',['scope','writer','witness-key','transport'])
def test_configuration_domain_refusal(witnessed_findings,kind):
    d=witnessed_findings;r=d['t']['r'];kwargs=dict(d['client_args'])
    if kind=='scope':kwargs['journal_anchor']='f'*64
    if kind=='writer':kwargs.update(signer=Ed25519PrivateKey.generate(),key_id='foreign')
    if kind=='witness-key':kwargs['witness_keys']=r.recovery_keys
    if kind=='writer':
        with pytest.raises(ValueError):W.WitnessClient(**kwargs,exchange=d['server'].exchange)
        return
    client=W.WitnessClient(**kwargs,exchange=d['server'].exchange)
    with pytest.raises(ValueError):A.WitnessedFindingsRegistry(r,client,fixture_transport=kind!='transport')


@pytest.mark.parametrize('kind',['nonce','expired','scope','signature'])
def test_fresh_challenge_verification_rejects_bad_response(witnessed_findings,kind):
    d=witnessed_findings;original=d['client'].exchange
    def bad(receipt):
        result=original(receipt);value=result['payload']
        if kind=='nonce':value['nonce']='a'*64
        elif kind=='scope':value['journal_anchor']='f'*64
        elif kind=='expired':
            now=J._now();value['issued_at']=(now-timedelta(seconds=61)).isoformat();value['expires_at']=(now-timedelta(seconds=1)).isoformat()
        else:result['signature']='invalid';return result
        return J._sign(value,d['args']['signer'],d['args']['key_id'],W.RESPONSE_POLICY)
    d['client'].exchange=bad
    with pytest.raises(ValueError):d['adapter'].select()
    assert not list(d['t']['r'].root.iterdir())


def test_enrollment_missing_on_restart_is_never_reinitialized(witnessed_findings):
    d=witnessed_findings;(d['server'].root/'enrollment.encrypted.json').unlink()
    server=W.DurableTipWitness(**d['args'],expected_enrollment=d['enrollment'])
    client=W.WitnessClient(**d['client_args'],exchange=server.exchange)
    adapter=A.WitnessedFindingsRegistry(d['t']['r'],client,fixture_transport=True)
    with pytest.raises(ValueError):adapter.select()
    assert not list(server.root.iterdir())


def test_read_does_not_accept_witness_change_mid_selection(witnessed_findings,monkeypatch):
    d=witnessed_findings;append(d);original=d['client'].head;calls=[]
    def moving():
        tip=original();calls.append(1)
        return tip if len(calls)==1 else dict(sequence=2,sha256='f'*64)
    monkeypatch.setattr(d['client'],'head',moving)
    with pytest.raises(ValueError,match='advanced during selection'):d['adapter'].select()


def test_recording_and_findings_witness_scopes_cannot_be_interchanged(witnessed_findings):
    d=witnessed_findings;recording=d['t']['d']['t']['client']
    assert recording.scope['journal_anchor']!=d['client'].scope['journal_anchor']
    with pytest.raises(ValueError):A.WitnessedFindingsRegistry(d['t']['r'],recording,fixture_transport=True)


def test_actual_mutual_tls_findings_append_selection_and_witness_restart(witnessed_findings,tmp_path):
    d=witnessed_findings;r=d['t']['r'];pki=certs(tmp_path/'findings-test-pki',J._now())
    control=tmp_path/'findings-test-control';control.mkdir(mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    profile=control/'profile.json';endpoint=f'https://127.0.0.1:{port}'+T.PATH
    pin=T.provision(d['server'],profile_path=profile,endpoint=endpoint,ca_certificate=pki['ca'],
        server_certificate=pki['server'],server_key=pki['server_key'],client_certificates={r.key_id:pki['client']})
    server_args=dict(profile_path=profile,expected_profile_sha256=pin,ca_certificate=pki['ca'],
        server_certificate=pki['server'],server_key=pki['server_key'])
    transport_args=dict(profile_path=profile,expected_profile_sha256=pin,witness_keys=d['args']['witness_keys'],
        repo=r.journal.repo,ca_certificate=pki['ca'],client_certificate=pki['client'],client_key=pki['client_key'])
    listener_args=dict(port=port,t={'server':d['server']},server_args=server_args)
    with listener(listener_args):
        client=W.WitnessClient(**d['client_args'],exchange=T.HTTPSWitnessTransport(**transport_args))
        adapter=A.WitnessedFindingsRegistry(r,client)
        result=adapter.append_receipt(operation_id=OP,finding_id=ID,receipt_path=d['t']['d']['output'])
        assert len(adapter.select()['entries'])==1
    listener_args['t']['server']=W.DurableTipWitness(**d['args'],expected_enrollment=d['enrollment'])
    with listener(listener_args):
        client=W.WitnessClient(**d['client_args'],exchange=T.HTTPSWitnessTransport(**transport_args))
        assert A.WitnessedFindingsRegistry(r,client).select()['registry_tip']==result['registry_tip']


@pytest.mark.parametrize('kind',['scope','key'])
def test_midflight_configuration_change_blocks_new_write(witnessed_findings,kind):
    d=witnessed_findings;before=inventory(d)
    if kind=='scope':d['client'].scope['journal_anchor']='e'*64
    else:d['client'].witness_keys={'changed':J._public(Ed25519PrivateKey.generate())}
    with pytest.raises(ValueError,match='changed'):append(d)
    assert inventory(d)==before


def test_failed_local_durability_flush_cannot_advance_witness(witnessed_findings,monkeypatch):
    d=witnessed_findings;r=d['t']['r'];original=r.append_receipt;original_fsync=A.os.fsync
    def failed_flush(_):raise OSError('fixture local durability flush failure')
    def record(**kwargs):
        result=original(**kwargs);monkeypatch.setattr(A.os,'fsync',failed_flush);return result
    monkeypatch.setattr(r,'append_receipt',record)
    with pytest.raises(OSError):append(d)
    monkeypatch.setattr(A.os,'fsync',original_fsync)
    assert d['client'].head() is None and not list(d['server'].root.glob('advance-*'))
    jp=r.journal.root/'entry-00000001.encrypted.json';rp=r.root/'entry-00000001.encrypted.json'
    result=d['adapter'].recover(authorize(d,r.journal._tip(1,sha256(jp.read_bytes()).hexdigest()),
        pending_registry_tip=r._tip(1,sha256(rp.read_bytes()).hexdigest())))
    assert result['status']=='WITNESSED'


def test_witness_tip_change_during_recovery_issuance_is_refused(witnessed_findings,monkeypatch):
    d=witnessed_findings;new=add(d['t']['d']);original=d['adapter']._head;calls=[]
    def changed():
        calls.append(1)
        return original() if len(calls)==1 else d['t']['r']._tip(1,'f'*64)
    monkeypatch.setattr(d['adapter'],'_head',changed)
    with pytest.raises(ValueError,match='advanced during recovery issuance'):authorize(d,new['tip'])
    assert d['client'].head() is None
