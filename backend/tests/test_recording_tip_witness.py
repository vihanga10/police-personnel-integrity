"""Real encrypted witness files and signatures; independent in-process test service."""
from copy import deepcopy
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import os
import stat
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.security.identity_crypto import IdentityCrypto
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import recording_checkpoint_registry as R
from test_observed_recording_journal import setup,baseline,authorize,append,numbers
from test_protected_recording_review import verified,keys
from test_recording_checkpoint_registry import build_registry,approval,checkpoint_interruption


@pytest.fixture
def witnessed(setup,tmp_path):
    s=setup;pin=baseline(s);registry,recovery,registry_args=build_registry(s,tmp_path,pin['journal_anchor'])
    root=tmp_path/'witness';root.mkdir(mode=0o700)
    config=dict(active_encryption_key_version='enc',active_lookup_key_version='lookup',
        encryption_keys={'enc':base64.b64encode(b'W'*32).decode()},
        lookup_keys={'lookup':base64.b64encode(b'X'*32).decode()})
    copies=[]
    for name in ('witness-primary.json','witness-backup.json'):
        path=tmp_path/name;path.write_text(json.dumps(config));path.chmod(0o600);copies.append(IdentityCrypto(path))
    signer=Ed25519PrivateKey.generate();public=signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    args=dict(root=root,repo=s['repo'],witness_id='fixture-independent-witness',registry_id=registry.registry_id,
        journal_anchor=registry.anchor,crypto=copies[0],backup=copies[1],signer=signer,key_id='witness',
        witness_keys={'witness':public},writer_keys=registry.registry_keys)
    server=W.DurableTipWitness(**args);enrollment=server.initialize()
    client_args=dict(witness_id=args['witness_id'],registry_id=registry.registry_id,journal_anchor=registry.anchor,
        signer=registry.signer,key_id=registry.key_id,writer_keys=registry.registry_keys,witness_keys=args['witness_keys'])
    client=W.WitnessClient(**client_args,exchange=server.exchange)
    adapter=W.WitnessedCheckpointRegistry(registry,client)
    tip=adapter.register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    return dict(s=s,pin=pin,r=registry,recovery=recovery,server=server,args=args,enrollment=enrollment,
        client=client,client_args=client_args,adapter=adapter,tip=tip,registry_args=registry_args)


def next_checkpoint(t):
    s=t['s'];s['clock'][0]+=timedelta(seconds=1)
    return append(s,t['pin'],authorize(s,t['pin']))


def test_witness_restart_recovers_latest_tip_and_full_reported_history(witnessed):
    t=witnessed;new=next_checkpoint(t)
    tip=t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    restarted=W.DurableTipWitness(**t['args'],expected_enrollment=t['enrollment'])
    client=W.WitnessClient(**t['client_args'],exchange=restarted.exchange)
    registry=R.CheckpointRegistry(**t['registry_args'])
    adapter=W.WitnessedCheckpointRegistry(registry,client)
    assert client.head()==tip and tip['sequence']==2
    assert numbers(adapter.select()['state'],t['s']['clock'][0])==['fixture-200']
    assert len(list(restarted.root.iterdir()))==3
    for path in restarted.root.iterdir():
        assert path.stat().st_mode&0o777==0o600
        assert 'fixture-100' not in path.read_text() and 'fixture-200' not in path.read_text()
    assert adapter.register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])==tip


def test_registry_and_journal_rollback_cannot_override_fresh_witness(witnessed):
    t=witnessed;new=next_checkpoint(t)
    latest=t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    for index,path in enumerate((t['r'].root/'entry-00000002.encrypted.json',t['s']['root']/new['checkpoint_file'],
            t['s']['root']/'event-00000001.encrypted.json')):path.rename(t['s']['repo']/f'fixture-rollback-{index}')
    assert t['client'].head()==latest
    with pytest.raises(ValueError,match='rolled back'):t['adapter'].select()


def test_response_loss_after_commit_is_recovered_by_fresh_read(witnessed):
    t=witnessed;new=next_checkpoint(t);original=t['client'].exchange
    def drop(request):
        response=original(request)
        if request['payload']['operation']=='CAS':raise OSError('fixture response lost after durable witness commit')
        return response
    t['client'].exchange=drop
    with pytest.raises(OSError):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    t['client'].exchange=original
    assert t['client'].head()['sequence']==2
    assert numbers(t['adapter'].select()['state'],t['s']['clock'][0])==['fixture-200']


def test_failure_before_witness_commit_requires_separate_authorized_reconciliation(witnessed):
    t=witnessed;new=next_checkpoint(t);original=t['client'].exchange
    def fail(request):
        if request['payload']['operation']=='CAS':raise OSError('fixture connection lost before witness commit')
        return original(request)
    t['client'].exchange=fail
    with pytest.raises(OSError):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    t['client'].exchange=original
    assert t['client'].head()==t['tip']
    with pytest.raises(ValueError):t['adapter'].select()
    with pytest.raises(ValueError):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    token=approval(t['s'],t['r'],t['tip'],t['recovery'],new['checkpoint_file'])
    outcome=t['adapter'].reconcile(token)
    assert outcome['registry_tip']['sequence']==2
    assert numbers(t['adapter'].select()['state'],t['s']['clock'][0])==['fixture-200']


def test_witnessed_pending_event_recovery_preserves_original_dates(witnessed,monkeypatch):
    t=witnessed;s=t['s'];checkpoint_interruption(s,t['pin'],monkeypatch);observed=s['clock'][0]
    original={p:p.read_bytes() for root in (s['root'],t['r'].root,t['server'].root) for p in root.iterdir()}
    s['clock'][0]+=timedelta(seconds=1200)
    token=approval(s,t['r'],t['tip'],t['recovery'])
    outcome=t['adapter'].recover(token,recorder_signer=s['signer'],recorder_key_id='recorder')
    state=t['adapter'].select()['state']
    assert outcome['registry_tip']['sequence']==2 and state['history'].coverage_end==observed
    assert numbers(state,observed)==['fixture-200']
    assert all(path.read_bytes()==data for path,data in original.items())


@pytest.mark.parametrize('kind',['signature','key','nonce','request_digest','scope','status','future','expired','tip','plaintext','outage'])
def test_bad_witness_response_never_authorizes_a_read(witnessed,kind):
    t=witnessed;original=t['client'].exchange;server=t['server']
    def transport(request):
        if kind=='outage':raise ConnectionError('fixture unavailable witness')
        response=original(request);value=deepcopy(response['payload'])
        if kind=='signature':response['signature']='AAAA';return response
        if kind=='key':return J._sign(value,Ed25519PrivateKey.generate(),'unknown',W.RESPONSE_POLICY)
        if kind=='nonce':value['nonce']='f'*64
        elif kind=='request_digest':value['request_sha256']='e'*64
        elif kind=='scope':value['registry_id']='other-registry'
        elif kind=='status':value['status']='CACHED'
        elif kind=='future':value['issued_at']=(t['s']['clock'][0]+timedelta(seconds=1)).isoformat()
        elif kind=='expired':t['s']['clock'][0]+=timedelta(seconds=60)
        elif kind=='tip':value['tip']={'sequence':True,'sha256':'a'*64}
        elif kind=='plaintext':return value
        return J._sign(value,server.signer,server.key_id,W.RESPONSE_POLICY)
    t['client'].exchange=transport
    before={p:p.read_bytes() for root in (t['s']['root'],t['r'].root,server.root) for p in root.iterdir()}
    with pytest.raises(Exception):t['adapter'].select()
    assert {p:p.read_bytes() for root in (t['s']['root'],t['r'].root,server.root) for p in root.iterdir()}==before


def test_old_signed_head_response_cannot_be_replayed_for_a_new_challenge(witnessed):
    t=witnessed;captured=[];original=t['client'].exchange
    def capture(request):response=original(request);captured.append(response);return response
    t['client'].exchange=capture;assert t['client'].head()==t['tip']
    t['client'].exchange=lambda request:captured[0]
    with pytest.raises(ValueError,match='challenge'):t['adapter'].select()


@pytest.mark.parametrize('kind',['scope','expired','future','gap','boolean','signature','unknown','head_update'])
def test_invalid_signed_requests_cannot_mutate_witness(witnessed,kind):
    t=witnessed;clock=t['s']['clock'][0]
    value=dict(policy=W.REQUEST_POLICY,kind='REQUEST',**t['client'].scope,operation='CAS',nonce='a'*64,
        expected_tip=t['tip'],proposed_tip={'sequence':2,'sha256':'b'*64},issued_at=clock.isoformat(),
        expires_at=(clock+timedelta(seconds=60)).isoformat())
    if kind=='scope':value['journal_anchor']='e'*64
    elif kind=='expired':value['issued_at']=(clock-timedelta(seconds=60)).isoformat();value['expires_at']=clock.isoformat()
    elif kind=='future':value['issued_at']=(clock+timedelta(seconds=1)).isoformat();value['expires_at']=(clock+timedelta(seconds=61)).isoformat()
    elif kind=='gap':value['proposed_tip']['sequence']=3
    elif kind=='boolean':value['expected_tip']={'sequence':True,'sha256':t['tip']['sha256']}
    elif kind=='head_update':value['operation']='HEAD'
    receipt=J._sign(value,t['r'].signer,t['r'].key_id,W.REQUEST_POLICY)
    if kind=='signature':receipt['signature']='AAAA'
    elif kind=='unknown':receipt=J._sign(value,Ed25519PrivateKey.generate(),'unknown',W.REQUEST_POLICY)
    before={p:p.read_bytes() for p in t['server'].root.iterdir()}
    with pytest.raises(Exception):t['server'].exchange(receipt)
    assert {p:p.read_bytes() for p in t['server'].root.iterdir()}==before


def test_compare_and_swap_serializes_concurrent_forks_and_retry_is_idempotent(witnessed):
    t=witnessed;old=t['tip'];proposals=[{'sequence':2,'sha256':c*64} for c in ('b','c')]
    def attempt(proposed):
        try:return t['client'].advance(old,proposed)
        except ValueError:return None
    with ThreadPoolExecutor(max_workers=2) as executor:results=list(executor.map(attempt,proposals))
    successes=[result for result in results if result is not None]
    assert len(successes)==1 and len(list(t['server'].root.iterdir()))==3
    assert t['client'].advance(old,successes[0])==successes[0]
    assert len(list(t['server'].root.iterdir()))==3
    with pytest.raises(ValueError):t['client'].advance(old,proposals[1] if successes[0]==proposals[0] else proposals[0])


@pytest.mark.parametrize('kind',['missing_enrollment','wrong_pin','changed_entry','missing_predecessor','symlink','permissions','unknown_stage','backup','clock'])
def test_witness_store_damage_never_falls_back_to_cached_tip(witnessed,kind):
    t=witnessed;root=t['server'].root
    if kind=='missing_enrollment':(root/'enrollment.encrypted.json').rename(root.parent/'saved-enrollment')
    elif kind=='wrong_pin':t['server'].expected_enrollment='f'*64
    elif kind=='changed_entry':(root/'advance-00000001.encrypted.json').write_text('{}')
    elif kind=='missing_predecessor':
        t['client'].advance(t['tip'],{'sequence':2,'sha256':'b'*64})
        (root/'advance-00000001.encrypted.json').rename(root.parent/'saved-advance')
    elif kind=='symlink':
        path=root/'advance-00000001.encrypted.json';saved=root.parent/'saved-advance';path.rename(saved);path.symlink_to(saved)
    elif kind=='permissions':(root/'advance-00000001.encrypted.json').chmod(0o644)
    elif kind=='unknown_stage':(root/'.uncertain').write_text('fixture preserve')
    elif kind=='backup':t['server'].backup=object()
    elif kind=='clock':t['s']['clock'][0]-=timedelta(seconds=1)
    with pytest.raises(Exception):t['adapter'].select()
    if kind=='unknown_stage':assert (root/'.uncertain').read_text()=='fixture preserve'


def test_enrollment_is_explicit_and_cannot_be_reset_on_restart(witnessed):
    t=witnessed
    with pytest.raises(ValueError):t['server'].initialize()
    reopened=W.DurableTipWitness(**t['args'])
    request=[];original=t['client'].exchange
    def capture(receipt):request.append(receipt);return original(receipt)
    t['client'].exchange=capture;t['client'].head()
    with pytest.raises(ValueError,match='enrollment pin'):reopened.exchange(request[0])
    assert len(list(reopened.root.iterdir()))==2


def test_witness_publication_flush_failure_recovers_without_duplicate_entry(witnessed,monkeypatch):
    t=witnessed;new=next_checkpoint(t);original=os.fsync;inode=t['server'].root.stat().st_ino
    active=[False];transport=t['client'].exchange
    def exchange(receipt):
        if receipt['payload']['operation']=='CAS':active[0]=True
        return transport(receipt)
    t['client'].exchange=exchange
    def flush(fd):
        info=os.fstat(fd)
        if active[0] and stat.S_ISDIR(info.st_mode) and info.st_ino==inode:raise OSError('fixture witness directory flush failure')
        return original(fd)
    monkeypatch.setattr(os,'fsync',flush)
    with pytest.raises(OSError):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    assert len(list(t['server'].root.iterdir()))==3
    with pytest.raises(OSError):t['client'].head()
    monkeypatch.setattr(os,'fsync',original)
    assert t['client'].head()['sequence']==2
    assert numbers(t['adapter'].select()['state'],t['s']['clock'][0])==['fixture-200']


def test_response_expiration_after_commit_preserves_durable_tip(witnessed):
    t=witnessed;new=next_checkpoint(t);original=t['client'].exchange
    def slow(receipt):
        response=original(receipt)
        if receipt['payload']['operation']=='CAS':t['s']['clock'][0]+=timedelta(seconds=60)
        return response
    t['client'].exchange=slow
    with pytest.raises(ValueError,match='expired'):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    t['client'].exchange=original
    assert t['client'].head()['sequence']==2
    state=t['adapter'].select()['state']
    assert state['history'].coverage_end==t['s']['clock'][0]-timedelta(seconds=60)


@pytest.mark.parametrize('kind',['registry_scope','anchor','writer_pins','shared_witness_key','wrong_writer'])
def test_client_registry_configuration_must_be_pinned_and_separate(witnessed,kind):
    t=witnessed;args=dict(t['client_args'])
    if kind=='registry_scope':args['registry_id']='wrong-registry'
    elif kind=='anchor':args['journal_anchor']='e'*64
    elif kind=='writer_pins':args['writer_keys']=dict(args['writer_keys'],extra=b'q'*32)
    elif kind=='shared_witness_key':args['witness_keys']=t['s']['observation_keys']
    elif kind=='wrong_writer':args['signer']=Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        client=W.WitnessClient(**args,exchange=t['server'].exchange)
        W.WitnessedCheckpointRegistry(t['r'],client)


@pytest.mark.parametrize('kind',['shared_roles','signing_seed','public_root','symlink_root','repository_root'])
def test_service_keys_and_storage_require_explicit_private_configuration(witnessed,kind):
    t=witnessed;args=dict(t['args'])
    if kind=='shared_roles':args['writer_keys']=args['witness_keys']
    elif kind=='signing_seed':
        signer=Ed25519PrivateKey.from_private_bytes(b'W'*32);args['signer']=signer
        args['witness_keys']={'witness':signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    elif kind=='public_root':args['root'].chmod(0o755)
    elif kind=='symlink_root':
        link=args['root'].parent/'witness-link';link.symlink_to(args['root'],target_is_directory=True);args['root']=link
    else:args['root']=t['s']['repo'];args['root'].chmod(0o700)
    with pytest.raises(ValueError):W.DurableTipWitness(**args,expected_enrollment=t['enrollment'])


def test_expired_request_before_witness_publication_leaves_registry_for_reconciliation(witnessed,monkeypatch):
    t=witnessed;new=next_checkpoint(t);original=R._publish
    def publish(path,receipt,crypto,backup,binding,check):
        def delayed(staging):
            if path.parent==t['server'].root:t['s']['clock'][0]+=timedelta(seconds=60)
            check(staging)
        return original(path,receipt,crypto,backup,binding,delayed)
    monkeypatch.setattr(R,'_publish',publish)
    with pytest.raises(ValueError,match='expired'):t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    assert len(list(t['r'].root.iterdir()))==2 and len(list(t['server'].root.iterdir()))==2
    assert not any(p.name.startswith('.') for p in t['server'].root.iterdir())
    assert t['client'].head()==t['tip']
    with pytest.raises(ValueError):t['adapter'].select()


def test_head_advancement_between_read_checks_blocks_stale_selection(witnessed):
    t=witnessed;original=t['client'].exchange;reads=[0]
    def advancing(receipt):
        if receipt['payload']['operation']=='HEAD':
            reads[0]+=1
            if reads[0]==2:t['client'].advance(t['tip'],{'sequence':2,'sha256':'c'*64})
        return original(receipt)
    t['client'].exchange=advancing
    with pytest.raises(ValueError,match='advanced during selection'):t['adapter'].select()


def test_authority_store_rollback_requires_independent_operational_protection(witnessed):
    t=witnessed;new=next_checkpoint(t)
    t['adapter'].register(checkpoint_file=new['checkpoint_file'],checkpoint_sha256=new['checkpoint_sha256'])
    for index,path in enumerate((t['server'].root/'advance-00000002.encrypted.json',t['r'].root/'entry-00000002.encrypted.json',
            t['s']['root']/new['checkpoint_file'],t['s']['root']/'event-00000001.encrypted.json')):
        path.rename(t['s']['repo']/f'fixture-all-store-backup-{index}')
    # Explicit trust limit: this prototype cannot detect rollback of its authority too.
    # A fresh signature proves the service answered now, not that its database was never restored.
    assert t['client'].head()==t['tip']
    assert numbers(t['adapter'].select()['state'],t['s']['clock'][0]-timedelta(seconds=1))==['fixture-100']


def test_transport_cannot_replace_the_verifiers_original_challenge_in_place(witnessed):
    t=witnessed;original=t['client'].exchange;captured=[]
    def capture(receipt):
        response=original(receipt);captured.append((deepcopy(receipt),deepcopy(response)));return response
    t['client'].exchange=capture;t['client'].head()
    def substitute(receipt):
        receipt.clear();receipt.update(deepcopy(captured[0][0]));return captured[0][1]
    t['client'].exchange=substitute
    # Identical fixture clock makes the nonce binding, not elapsed time, decisive.
    with pytest.raises(ValueError,match='challenge'):t['client'].head()
