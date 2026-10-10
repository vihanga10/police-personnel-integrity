"""Real cryptography, separate stores, trusted-pin fixtures and preserved recovery."""
from copy import deepcopy
from hashlib import sha256
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import os
import stat
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import app.identity.observed_recording_journal as J
import app.identity.recording_checkpoint_registry as R
from app.identity.recording_checkpoint_registry import CheckpointRegistry,RECOVERY_POLICY
from app.identity.evidence_bundle_v2 import canonical
from app.security.identity_crypto import IdentityCrypto
from test_observed_recording_journal import setup,baseline,load,authorize,append,numbers
from test_protected_recording_review import verified,keys


def build_registry(s,tmp_path,anchor):
    root=tmp_path/'registry';root.mkdir(mode=0o700)
    config=dict(active_encryption_key_version='enc',active_lookup_key_version='lookup',
        encryption_keys={'enc':base64.b64encode(b'R'*32).decode()},
        lookup_keys={'lookup':base64.b64encode(b'T'*32).decode()})
    copies=[]
    for name in ('registry-primary.json','registry-backup.json'):
        path=tmp_path/name;path.write_text(json.dumps(config));path.chmod(0o600);copies.append(IdentityCrypto(path))
    signer,recovery=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    public=lambda key:key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    args=dict(root=root,journal_root=s['root'],repo=s['repo'],journal_anchor=anchor,registry_id='fixture-registry',
        crypto=copies[0],backup=copies[1],journal_crypto=s['crypto'],journal_backup=s['backup'],signer=signer,
        key_id='registry',registry_keys={'registry':public(signer)},recorder_keys=s['recorder_keys'],
        observation_keys=s['observation_keys'],recovery_keys={'recovery':public(recovery)})
    return CheckpointRegistry(**args),recovery,args


@pytest.fixture
def registered(setup,tmp_path):
    s=setup;pin=baseline(s);registry,recovery,args=build_registry(s,tmp_path,pin['journal_anchor'])
    tip=registry.register(None,checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    return s,pin,registry,tip,recovery,args


def approval(s,registry,tip,recovery,checkpoint_file=None,**changes):
    payload=dict(policy=RECOVERY_POLICY,kind='RECOVERY',registry_id=registry.registry_id,
        journal_anchor=registry.anchor,registry_tip=deepcopy(tip),artifact_inventory=registry._journal_files(),
        registry_artifact_inventory=registry._registry_files(),checkpoint_file=checkpoint_file,
        issued_at=s['clock'][0].isoformat(),expires_at=(s['clock'][0]+timedelta(seconds=600)).isoformat(),
        status='RECOVERY_AUTHORIZED')
    payload.update(changes)
    return dict(key_id='recovery',payload=payload,signature=base64.b64encode(
        recovery.sign(canonical([RECOVERY_POLICY,'recovery',payload]).encode())).decode())


def recover(registry,s,tip,token):
    return registry.recover(tip,token,recorder_signer=s['signer'],recorder_key_id='recorder')


def checkpoint_interruption(s,pin,monkeypatch):
    s['clock'][0]+=timedelta(seconds=1);token=authorize(s,pin);original=J._publish
    def publish(path,*args):
        if path.name.startswith('checkpoint-'):raise OSError('fixture checkpoint interruption')
        return original(path,*args)
    monkeypatch.setattr(J,'_publish',publish)
    with pytest.raises(OSError):append(s,pin,token)
    monkeypatch.setattr(J,'_publish',original)


def test_separate_registry_selects_exact_head_and_is_idempotent(registered):
    s,pin,r,tip,key,args=registered
    assert tip['sequence']==1
    selected=r.select(tip)
    assert selected['checkpoint_sha256']==pin['checkpoint_sha256']
    assert numbers(selected['state'],s['clock'][0])==['fixture-100']
    assert r.register(tip,checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])==tip
    assert len(list(r.root.iterdir()))==1
    for file in r.root.iterdir():
        assert file.stat().st_mode & 0o777==0o600
        assert 'fixture-100' not in file.read_text() and s['root'].name not in file.read_text()


def test_registry_requires_new_pin_after_completed_append(registered):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin))
    with pytest.raises(ValueError,match='Pending'):r.select(tip)
    next_tip=r.register(tip,checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    assert next_tip['sequence']==2
    assert numbers(r.select(next_tip)['state'],s['clock'][0])==['fixture-200']
    with pytest.raises(ValueError,match='stale'):r.select(tip)
    with pytest.raises(ValueError):r.register(next_tip,checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])


def test_pending_event_recovery_preserves_observation_time_and_old_files(registered,monkeypatch):
    s,pin,r,tip,key,args=registered;start=s['clock'][0]
    checkpoint_interruption(s,pin,monkeypatch);observed=s['clock'][0]
    before={p.name:p.read_bytes() for p in s['root'].iterdir()}
    with pytest.raises(ValueError):r.select(tip)
    # Original committed-evidence authorization is now expired; recovery never renews it.
    s['clock'][0]+=timedelta(seconds=1200)
    outcome=recover(r,s,tip,approval(s,r,tip,key))
    selected=r.select(outcome['registry_tip']);history=selected['state']['history']
    assert history.coverage_end==observed and history.versions[-1].recorded_at==observed
    assert numbers(selected['state'],start)==['fixture-100'] and numbers(selected['state'],observed)==['fixture-200']
    with pytest.raises(ValueError):numbers(selected['state'],s['clock'][0])
    assert all((s['root']/name).read_bytes()==data for name,data in before.items())
    assert outcome['observation_times_preserved']


def test_recovery_can_adopt_existing_authenticated_unregistered_checkpoint(registered):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin));files={p.name for p in s['root'].iterdir()}
    outcome=recover(r,s,tip,approval(s,r,tip,key,new['checkpoint_file']))
    assert outcome['checkpoint_file']==new['checkpoint_file']
    assert {p.name for p in s['root'].iterdir()}==files
    assert numbers(r.select(outcome['registry_tip'])['state'],s['clock'][0])==['fixture-200']


@pytest.mark.parametrize('kind',['expired','future','status','anchor','old_tip','inventory','registry_inventory',
    'signature','untrusted','plaintext','changed_event','wrong_recorder'])
def test_invalid_recovery_cannot_publish_or_advance(registered,monkeypatch,kind):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    changes={}
    if kind=='expired':changes.update(issued_at=(s['clock'][0]-timedelta(seconds=600)).isoformat(),expires_at=s['clock'][0].isoformat())
    elif kind=='future':changes.update(issued_at=(s['clock'][0]+timedelta(seconds=1)).isoformat(),expires_at=(s['clock'][0]+timedelta(seconds=601)).isoformat())
    elif kind=='status':changes['status']='UNASSESSED'
    elif kind=='anchor':changes['journal_anchor']='f'*64
    elif kind=='old_tip':changes['registry_tip']=None
    elif kind=='inventory':changes['artifact_inventory']={}
    elif kind=='registry_inventory':changes['registry_artifact_inventory']={}
    token=approval(s,r,tip,key,**changes)
    if kind=='signature':token['signature']='AAAA'
    elif kind=='untrusted':r.recovery_keys={}
    elif kind=='plaintext':token=token['payload']
    elif kind=='changed_event':(s['root']/'event-00000001.encrypted.json').write_text('{}')
    elif kind=='wrong_recorder':s['signer']=Ed25519PrivateKey.generate()
    before={p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}
    with pytest.raises(Exception):recover(r,s,tip,token)
    assert {p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}==before


@pytest.mark.parametrize('kind',['wrong_pin','missing_entry','reformatted_entry','symlink','permissions',
    'journal_rollback','unexpected_stage','wrong_registry_key'])
def test_independent_tip_and_preserved_artifact_checks_detect_rollback(registered,kind):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin));latest=r.register(tip,checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    path=r.root/'entry-00000002.encrypted.json'
    if kind=='wrong_pin':latest['sha256']='f'*64
    elif kind=='missing_entry':path.rename(r.root.parent/'saved-entry')
    elif kind=='reformatted_entry':path.write_text(json.dumps(json.loads(path.read_text()),indent=2)+'\n')
    elif kind=='symlink':saved=r.root.parent/'saved-entry';path.rename(saved);path.symlink_to(saved)
    elif kind=='permissions':path.chmod(0o644)
    elif kind=='journal_rollback':
        (s['root']/new['checkpoint_file']).rename(s['root'].parent/'saved-checkpoint')
        (s['root']/'event-00000001.encrypted.json').rename(s['root'].parent/'saved-event')
    elif kind=='unexpected_stage':(r.root/'.uncertain').write_bytes(b'fixture-stage')
    elif kind=='wrong_registry_key':r.registry_keys={'registry':b'x'*32}
    with pytest.raises(Exception):r.select(latest)


def test_initial_baseline_without_checkpoint_can_be_recovered_with_independent_anchor(setup,tmp_path,monkeypatch):
    s=setup;published={};original=J._publish
    def publish(path,*args):
        if path.name.startswith('checkpoint-'):raise OSError('fixture initial checkpoint failure')
        value=original(path,*args);published['anchor']=value;return value
    monkeypatch.setattr(J,'_publish',publish)
    with pytest.raises(OSError):baseline(s)
    monkeypatch.setattr(J,'_publish',original)
    r,key,args=build_registry(s,tmp_path,published['anchor'])  # pin captured at trusted publication boundary
    outcome=recover(r,s,None,approval(s,r,None,key))
    assert outcome['registry_tip']['sequence']==1
    assert numbers(r.select(outcome['registry_tip'])['state'],s['clock'][0])==['fixture-100']


def test_entry_published_before_tip_acknowledgment_requires_authorized_reconciliation(registered):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin));published=r.register(tip,checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    with pytest.raises(ValueError):r.select(tip)  # external witness still has old prefix after simulated crash
    outcome=r.reconcile_published_tip(tip,approval(s,r,tip,key,new['checkpoint_file']))
    assert outcome['registry_tip']==published
    assert numbers(r.select(outcome['registry_tip'])['state'],s['clock'][0])==['fixture-200']


@pytest.mark.parametrize('kind',['shared_roles','shared_crypto','nested_root','signing_seed','wrong_key'])
def test_registry_storage_and_signing_domains_must_be_separate(registered,kind):
    s,pin,r,tip,key,args=registered;args=dict(args)
    if kind=='shared_roles':args['recovery_keys']=s['observation_keys']
    elif kind=='shared_crypto':args['crypto']=s['crypto'];args['backup']=s['backup']
    elif kind=='nested_root':
        root=s['root']/'nested';root.mkdir(mode=0o700);args['root']=root
    elif kind=='signing_seed':
        signer=Ed25519PrivateKey.from_private_bytes(b'E'*32);args['signer']=signer
        args['registry_keys']={'registry':signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    elif kind=='wrong_key':args['signer']=Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):CheckpointRegistry(**args)


def test_registry_failure_preserves_new_checkpoint_and_can_be_registered_later(registered,monkeypatch):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    original=R._publish
    def publish(path,*args):
        if path.parent==r.root:raise OSError('fixture registry failure')
        return original(path,*args)
    monkeypatch.setattr(R,'_publish',publish)
    with pytest.raises(OSError):recover(r,s,tip,approval(s,r,tip,key))
    monkeypatch.setattr(R,'_publish',original)
    candidates=[p for p in s['root'].glob('checkpoint-*') if p.name!=pin['checkpoint_file']]
    assert len(candidates)==1
    candidate=candidates[0]
    latest=r.register(tip,checkpoint_file=candidate.name,checkpoint_sha256=sha256(candidate.read_bytes()).hexdigest())
    assert numbers(r.select(latest)['state'],s['clock'][0])==['fixture-200']


@pytest.mark.parametrize('phase',['checkpoint','registry'])
def test_recovery_expiration_during_publication_does_not_acknowledge_a_head(registered,monkeypatch,phase):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    token=approval(s,r,tip,key);original=R._publish
    before={p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}
    def publish(path,receipt,crypto,backup,binding,check):
        target=path.parent==(s['root'] if phase=='checkpoint' else r.root)
        def delayed_check(staging):
            if target:s['clock'][0]+=timedelta(seconds=600)
            check(staging)
        return original(path,receipt,crypto,backup,binding,delayed_check)
    monkeypatch.setattr(R,'_publish',publish)
    with pytest.raises(ValueError,match='expired'):recover(r,s,tip,token)
    assert all(path.read_bytes()==data for path,data in before.items())
    assert len(list(r.root.iterdir()))==1
    assert len(list(s['root'].glob('checkpoint-*')))==(1 if phase=='checkpoint' else 2)
    assert not any(p.name.startswith('.') for root in (s['root'],r.root) for p in root.iterdir())


@pytest.mark.parametrize('kind',['chain','authorization','lineage'])
def test_recovery_authorization_cannot_make_invalid_signed_evidence_valid(registered,monkeypatch,kind):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    path=s['root']/'event-00000001.encrypted.json'
    _,receipt=J._read(path,s['crypto'],s['backup'],J._binding('EVENT',r.anchor))
    value=deepcopy(receipt['payload'])
    if kind=='chain':value['previous_receipt_sha256']='f'*64
    elif kind=='authorization':value['claim']['value']='unauthorized alteration'
    else:
        value['supersedes']='missing-predecessor'
        authorized=deepcopy(value['authorization']['payload']);authorized['supersedes']=value['supersedes']
        value['authorization']=J._sign(authorized,s['authority'],'authority',J.AUTH_POLICY)
    envelope=J.seal_artifact(s['crypto'],s['backup'],J._sign(value,s['signer'],'recorder'),J._binding('EVENT',r.anchor))
    path.write_text(canonical(envelope)+'\n')  # deliberate corruption in a synthetic fixture only
    token=approval(s,r,tip,key)  # authority approves exact bytes, but semantic checks still apply
    before={p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}
    with pytest.raises(ValueError):recover(r,s,tip,token)
    assert {p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}==before


def test_concurrent_recovery_accepts_only_one_attempt_from_the_same_tip(registered,monkeypatch):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    token=approval(s,r,tip,key)
    def attempt():
        try:return recover(r,s,tip,token)
        except ValueError:return None
    with ThreadPoolExecutor(max_workers=2) as executor:results=list(executor.map(lambda _:attempt(),range(2)))
    succeeded=[result for result in results if result is not None]
    assert len(succeeded)==1 and len(list(r.root.iterdir()))==2
    assert len(list(s['root'].glob('checkpoint-*')))==2
    assert numbers(r.select(succeeded[0]['registry_tip'])['state'],s['clock'][0])==['fixture-200']


def test_simultaneous_store_rollback_is_detected_by_the_external_latest_tip(registered):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin));latest=r.register(tip,checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    # Restore both stores to their earlier state; the witness retains the latest pin.
    for index,path in enumerate((r.root/'entry-00000002.encrypted.json',s['root']/new['checkpoint_file'],
            s['root']/'event-00000001.encrypted.json')):path.rename(s['repo']/f'fixture-backup-{index}')
    with pytest.raises(ValueError,match='rolled back'):r.select(latest)
    # Supplying an old witness too cannot reveal rollback: this is an explicit trust limit.
    assert numbers(r.select(tip)['state'],load(s,pin)['history'].coverage_start)==['fixture-100']


def test_signed_checkpoint_cannot_extend_coverage_without_an_observation(setup,tmp_path):
    s=setup;pin=baseline(s);r,key,args=build_registry(s,tmp_path,pin['journal_anchor'])
    state=load(s,pin);s['clock'][0]+=timedelta(seconds=1)
    receipt=J._checkpoint(r.anchor,[],s['clock'][0].isoformat(),s['signer'],'recorder')
    path=s['root']/('checkpoint-'+receipt['payload']['checkpoint_id']+'.encrypted.json')
    fingerprint=J._publish(path,receipt,s['crypto'],s['backup'],J._binding('CHECKPOINT',r.anchor),lambda:None)
    with pytest.raises(ValueError,match='last recorded observation'):
        r.register(None,checkpoint_file=path.name,checkpoint_sha256=fingerprint)
    assert not list(r.root.iterdir())


def test_recovery_preserves_alternative_completed_checkpoint(registered):
    s,pin,r,tip,key,args=registered;s['clock'][0]+=timedelta(seconds=1)
    new=append(s,pin,authorize(s,pin));before={p.name:p.read_bytes() for p in s['root'].iterdir()}
    outcome=recover(r,s,tip,approval(s,r,tip,key))
    assert outcome['checkpoint_file']!=new['checkpoint_file']
    assert len(list(s['root'].glob('checkpoint-*')))==3
    assert all((s['root']/name).read_bytes()==data for name,data in before.items())
    assert numbers(r.select(outcome['registry_tip'])['state'],s['clock'][0])==['fixture-200']


def test_registry_directory_flush_failure_is_reconciled_without_republishing(registered,monkeypatch):
    s,pin,r,tip,key,args=registered;checkpoint_interruption(s,pin,monkeypatch)
    before={p:p.read_bytes() for root in (s['root'],r.root) for p in root.iterdir()}
    original=os.fsync;registry_inode=r.root.stat().st_ino
    def flush(fd):
        info=os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_ino==registry_inode:
            raise OSError('fixture failure after registry hard-link publication')
        original(fd)
    monkeypatch.setattr(os,'fsync',flush)
    with pytest.raises(OSError):recover(r,s,tip,approval(s,r,tip,key))
    monkeypatch.setattr(os,'fsync',original)
    assert len(list(r.root.iterdir()))==2
    assert all(path.read_bytes()==data for path,data in before.items())
    new=next(p for p in s['root'].glob('checkpoint-*') if p.name!=pin['checkpoint_file'])
    token=approval(s,r,tip,key,new.name)
    monkeypatch.setattr(os,'fsync',flush)
    with pytest.raises(OSError):r.reconcile_published_tip(tip,token)
    monkeypatch.setattr(os,'fsync',original)
    outcome=r.reconcile_published_tip(tip,token)
    assert numbers(r.select(outcome['registry_tip'])['state'],s['clock'][0])==['fixture-200']
