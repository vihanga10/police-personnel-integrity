"""Disposable encrypted registry and findings stores; no deployment or live run."""
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from uuid import UUID
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag
from app.identity import findings_tip_registry as R
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity.evidence_bundle_v2 import canonical,open_artifact,seal_artifact
from app.security.identity_crypto import IdentityCrypto
from test_encrypted_findings_journal import journal,add,review,advance,OP,ID,LEDGER
from test_protected_contradiction_runner import output,run,recover,next_checkpoint
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup,OFFICER
from test_protected_recording_review import verified,keys

REGISTRY=str(UUID(int=201));OP2=str(UUID(int=202))


@pytest.fixture
def registered(journal,tmp_path):
    d=journal;root=tmp_path/'findings-registry';root.mkdir(mode=0o700)
    config=dict(active_encryption_key_version='tip-enc',active_lookup_key_version='tip-lookup',
        encryption_keys={'tip-enc':base64.b64encode(b'T'*32).decode()},
        lookup_keys={'tip-lookup':base64.b64encode(b'U'*32).decode()})
    copies=[]
    for name in ('tip-primary.json','tip-backup.json'):
        p=tmp_path/name;p.write_text(json.dumps(config));p.chmod(0o600);copies.append(IdentityCrypto(p))
    signer=Ed25519PrivateKey.generate();recovery=Ed25519PrivateKey.generate()
    kwargs=dict(root=root,journal=d['ledger'],registry_id=REGISTRY,crypto=copies[0],backup=copies[1],signer=signer,
        key_id='tip-writer',registry_keys={'tip-writer':J._public(signer)},recovery_keys={'tip-recovery':J._public(recovery)})
    return dict(d=d,r=R.FindingsTipRegistry(**kwargs),kwargs=kwargs,recovery=recovery)


def append(t,tip=None,**changes):
    params=dict(expected_registry_tip=tip or t['r'].empty_tip(),operation_id=OP,finding_id=ID,receipt_path=t['d']['output'])
    params.update(changes);return t['r'].append_receipt(**params)


def authorization(t,old_tip,new_journal_tip,**changes):
    now=J._now();args=dict(signer=t['recovery'],key_id='tip-recovery',expected_registry_tip=old_tip,
        journal_tip=new_journal_tip,operation_id=OP,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=60)).isoformat())
    args.update(changes);return t['r'].authorize_recovery(**args)


def inventory(t):
    return {str(p):p.read_bytes() for root in (t['r'].root,t['d']['ledger'].root) for p in root.iterdir()}


def test_first_append_restart_selection_preserves_provenance(registered):
    t=registered;r=t['r'];result=append(t);before=inventory(t)
    restarted=R.FindingsTipRegistry(**dict(t['kwargs'],journal=F.FindingsJournal(**t['d']['kwargs'])))
    selected=restarted.select(result['registry_tip'])
    assert selected['journal_tip']==result['journal_tip']
    assert selected['entries'][0]['entry']['finding']==recover(t['d']['t'],t['d']['output'])
    assert inventory(t)==before
    assert OFFICER not in json.dumps(result) and not result['findings_anchored']
    for p in r.root.iterdir():assert OFFICER not in p.read_text() and p.stat().st_mode&0o777==0o600


def test_correction_review_and_retry_register_once(registered):
    t=registered;r=t['r'];first=append(t)
    assert append(t,first['registry_tip'])['status']=='ALREADY_REGISTERED'
    advance(t['d'])
    second=append(t,first['registry_tip'],operation_id=OP2,supersedes=first['journal_tip']['entry_sha256'],reason='fixture correction')
    advance(t['d']);token=review(t['d'],second['journal_tip'])
    third=r.append_review(expected_registry_tip=second['registry_tip'],intent=token)
    assert r.append_review(expected_registry_tip=third['registry_tip'],intent=token)['status']=='ALREADY_REGISTERED'
    assert [x['entry']['kind'] for x in r.select(third['registry_tip'])['entries']]==['FINDING','CORRECTION','REVIEW']
    assert len(list(r.root.iterdir()))==len(list(t['d']['ledger'].root.iterdir()))==3


@pytest.mark.parametrize('kind',['stale','registry-rollback','journal-rollback','digest','unexpected','permissions','ciphertext'])
def test_invalid_selection_refused(registered,kind):
    t=registered;r=t['r'];result=append(t);tip=deepcopy(result['registry_tip']);p=r.root/'entry-00000001.encrypted.json'
    if kind=='stale':tip=r.empty_tip()
    elif kind=='registry-rollback':p.unlink()
    elif kind=='journal-rollback':(t['d']['ledger'].root/'entry-00000001.encrypted.json').unlink()
    elif kind=='digest':tip['entry_sha256']='a'*64
    elif kind=='unexpected':(r.root/'unknown').write_text('fixture')
    elif kind=='permissions':p.chmod(0o644)
    else:
        data=json.loads(p.read_text());data['ciphertext']='A'*len(data['ciphertext']);p.write_text(json.dumps(data))
    with pytest.raises((ValueError,InvalidTag)):r.select(tip)


def test_unregistered_finding_requires_signed_recovery(registered):
    t=registered;r=t['r'];old=r.empty_tip();new=add(t['d'])
    with pytest.raises(ValueError):r.select(old)
    with pytest.raises(ValueError):append(t,old)
    token=authorization(t,old,new['tip']);result=r.recover(token)
    assert result['status']=='RECOVERED' and result['journal_tip']==new['tip']
    assert len(r.select(result['registry_tip'])['entries'])==1
    assert append(t,result['registry_tip'])['status']=='ALREADY_REGISTERED'
    # Later replay keeps historical authorization valid at original registration time.
    t['d']['t']['s']['clock'][0]+=timedelta(days=1)
    assert len(r.select(result['registry_tip'])['entries'])==1


def test_journal_publication_response_loss_is_recoverable(registered,monkeypatch):
    t=registered;r=t['r'];old=r.empty_tip();original=J._publish
    def loss(*args):original(*args);raise OSError('fixture lost journal response')
    monkeypatch.setattr(J,'_publish',loss)
    with pytest.raises(OSError):append(t)
    p=t['d']['ledger'].root/'entry-00000001.encrypted.json'
    new=t['d']['ledger']._tip(1,sha256(p.read_bytes()).hexdigest())
    token=authorization(t,old,new);result=r.recover(token)
    assert len(r.select(result['registry_tip'])['entries'])==1


def test_registry_publication_response_loss_requires_exact_pending_pin(registered,monkeypatch):
    t=registered;r=t['r'];old=r.empty_tip();original=R._publish
    def loss(*args):original(*args);raise OSError('fixture lost registry response')
    monkeypatch.setattr(R,'_publish',loss)
    with pytest.raises(OSError):append(t)
    jp=t['d']['ledger'].root/'entry-00000001.encrypted.json';rp=r.root/'entry-00000001.encrypted.json'
    jtip=t['d']['ledger']._tip(1,sha256(jp.read_bytes()).hexdigest());rtip=r._tip(1,sha256(rp.read_bytes()).hexdigest())
    with pytest.raises(ValueError):authorization(t,old,jtip)
    token=authorization(t,old,jtip,pending_registry_tip=rtip);before=inventory(t)
    result=r.recover(token)
    assert result['registry_tip']==rtip and inventory(t)==before and len(r.select(rtip)['entries'])==1
    assert r.recover(token)==result  # returning surviving tip is idempotent; no writes


@pytest.mark.parametrize('kind',['tampered','key','scope','operation','expired','future','inventory','pin'])
def test_recovery_authorization_failure_preserves_files(registered,kind):
    t=registered;r=t['r'];old=r.empty_tip();new=add(t['d']);token=authorization(t,old,new['tip'])
    if kind=='tampered':token['payload']['operation_id']=OP2
    if kind=='key':token['key_id']='unknown'
    if kind in ('scope','operation','pin'):
        value=token['payload']
        if kind=='scope':value['registry_id']=str(UUID(int=777))
        elif kind=='operation':value['operation_id']=OP2
        else:value['journal_tip']['entry_sha256']='f'*64
        token=J._sign(value,t['recovery'],'tip-recovery',R.RECOVERY_POLICY)
    if kind=='expired':t['d']['t']['s']['clock'][0]+=timedelta(seconds=61)
    if kind=='future':t['d']['t']['s']['clock'][0]-=timedelta(seconds=1)
    if kind=='inventory':(r.root/'unexpected').write_text('fixture inventory mutation')
    before=inventory(t)
    with pytest.raises(ValueError):r.recover(token)
    assert inventory(t)==before


def test_recovery_refuses_two_pending_findings(registered):
    t=registered;r=t['r'];first=add(t['d']);advance(t['d'])
    second=add(t['d'],first['tip'],operation_id=OP2,finding_id=str(UUID(int=299)))
    with pytest.raises(ValueError):authorization(t,r.empty_tip(),second['tip'],operation_id=OP2)
    assert not list(r.root.iterdir())


def test_recovery_for_newer_interruption_keeps_registered_prefix(registered):
    t=registered;r=t['r'];first=append(t);advance(t['d'])
    new=add(t['d'],first['journal_tip'],operation_id=OP2,finding_id=str(UUID(int=299)))
    prefix=(r.root/'entry-00000001.encrypted.json').read_bytes()
    result=r.recover(authorization(t,first['registry_tip'],new['tip'],operation_id=OP2))
    assert len(r.select(result['registry_tip'])['entries'])==2
    assert (r.root/'entry-00000001.encrypted.json').read_bytes()==prefix


@pytest.mark.parametrize('kind',['same-root','nested','encryption','signer','keys'])
def test_domain_separation_refused(registered,kind):
    t=registered;kwargs=dict(t['kwargs']);l=t['d']['ledger']
    if kind=='same-root':kwargs['root']=l.root
    elif kind=='nested':p=l.root/'nested';p.mkdir(mode=0o700);kwargs['root']=p
    elif kind=='encryption':kwargs.update(crypto=l.crypto,backup=l.backup)
    elif kind=='signer':kwargs['signer']=Ed25519PrivateKey.generate()
    else:kwargs['recovery_keys']=l.reviewer_keys
    with pytest.raises(ValueError):R.FindingsTipRegistry(**kwargs)


def test_concurrent_stale_append_has_one_winner(registered):
    t=registered;r=t['r'];other=R.FindingsTipRegistry(**t['kwargs']);old=r.empty_tip()
    def submit(reg,op):
        try:return reg.append_receipt(expected_registry_tip=old,operation_id=op,finding_id=ID,receipt_path=t['d']['output'])['status']
        except ValueError:return 'REFUSED'
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs=[pool.submit(submit,r,OP),pool.submit(submit,other,OP2)]
        assert sorted(j.result() for j in jobs)==['REFUSED','REGISTERED']
    assert len(list(r.root.iterdir()))==1


def test_registry_signed_payload_tampering_refused_even_with_file_pin(registered):
    t=registered;r=t['r'];result=append(t);p=r.root/'entry-00000001.encrypted.json'
    envelope=json.loads(p.read_text());binding=envelope['binding'];value=open_artifact(r.crypto,envelope,binding)
    value['payload']['operation_id']=OP2
    p.write_text(canonical(seal_artifact(r.crypto,r.backup,value,binding)))
    tip=dict(result['registry_tip'],entry_sha256=sha256(p.read_bytes()).hexdigest())
    with pytest.raises(ValueError,match='signature'):r.select(tip)


def test_key_pin_mutation_refused_before_writes(registered):
    t=registered;r=t['r'];r.recovery_keys={'changed':J._public(Ed25519PrivateKey.generate())}
    with pytest.raises(ValueError,match='pins changed'):append(t)
    assert not list(r.root.iterdir()) and not list(t['d']['ledger'].root.iterdir())


def test_authorization_ttl_bounded_and_empty_pin_strict(registered):
    t=registered;r=t['r'];new=add(t['d']);now=J._now()
    with pytest.raises(ValueError):authorization(t,r.empty_tip(),new['tip'],expires_at=(now+timedelta(seconds=601)).isoformat())
    with pytest.raises(ValueError):r.select(dict(r.empty_tip(),entry_sha256='f'*64))


def test_signed_registry_operation_mismatch_refused_before_append(registered):
    t=registered;r=t['r'];result=append(t);p=r.root/'entry-00000001.encrypted.json'
    envelope=json.loads(p.read_text());binding=envelope['binding'];receipt=open_artifact(r.crypto,envelope,binding)
    receipt['payload']['operation_id']=OP2
    receipt=J._sign(receipt['payload'],r.signer,r.key_id,R.POLICY)
    p.write_text(canonical(seal_artifact(r.crypto,r.backup,receipt,binding)))
    tip=dict(result['registry_tip'],entry_sha256=sha256(p.read_bytes()).hexdigest())
    advance(t['d']);before=inventory(t)
    with pytest.raises(ValueError,match='history differs'):
        append(t,tip,operation_id=str(UUID(int=203)),finding_id=str(UUID(int=204)))
    assert inventory(t)==before


def test_simultaneous_store_rollback_refused_against_independent_newest_pin(registered):
    t=registered;r=t['r'];first=append(t);advance(t['d'])
    second=append(t,first['registry_tip'],operation_id=OP2,finding_id=str(UUID(int=299)))
    (r.root/'entry-00000002.encrypted.json').unlink()
    (t['d']['ledger'].root/'entry-00000002.encrypted.json').unlink()
    with pytest.raises(ValueError):r.select(second['registry_tip'])
    # The old pin would authenticate the old prefix: this proves why independently
    # protected latest-pin retention is required, rather than claiming a local witness.
    assert len(r.select(first['registry_tip'])['entries'])==1


def test_registry_staging_failure_keeps_pending_finding_for_authorized_recovery(registered,monkeypatch):
    t=registered;r=t['r'];old=r.empty_tip();original=R._publish
    def fail(*args):raise OSError('fixture registry staging failure')
    monkeypatch.setattr(R,'_publish',fail)
    with pytest.raises(OSError):append(t)
    assert not list(r.root.iterdir())
    p=t['d']['ledger'].root/'entry-00000001.encrypted.json'
    new=t['d']['ledger']._tip(1,sha256(p.read_bytes()).hexdigest())
    token=authorization(t,old,new)
    monkeypatch.setattr(R,'_publish',original)
    result=r.recover(token);assert len(r.select(result['registry_tip'])['entries'])==1


def test_midflight_inventory_change_blocks_recovery_publication(registered,monkeypatch):
    t=registered;r=t['r'];new=add(t['d']);token=authorization(t,r.empty_tip(),new['tip']);original=R._publish
    def mutate(path,receipt,crypto,backup,binding,check):
        (r.root/'changed').write_text('fixture mutation')
        return original(path,receipt,crypto,backup,binding,check)
    monkeypatch.setattr(R,'_publish',mutate)
    with pytest.raises(ValueError):r.recover(token)
    assert not list(r.root.glob('entry-*.encrypted.json')) and not list(r.root.glob('.registry-*'))


def test_recovery_signer_cannot_reuse_findings_encryption_seed(registered):
    t=registered;r=t['r'];seed=next(iter(t['d']['ledger'].crypto.encryption_keys.values()))
    signer=Ed25519PrivateKey.from_private_bytes(seed)
    kwargs=dict(t['kwargs'],recovery_keys={'tip-recovery':J._public(signer)})
    r2=R.FindingsTipRegistry(**kwargs);new=add(t['d']);now=J._now()
    with pytest.raises(ValueError,match='overlaps'):
        r2.authorize_recovery(signer=signer,key_id='tip-recovery',expected_registry_tip=r2.empty_tip(),
            journal_tip=new['tip'],operation_id=OP,issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=60)).isoformat())
