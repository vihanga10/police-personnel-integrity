"""Real permit, signatures, encryption, durable append and query fixtures only."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta,date
from pathlib import Path
from uuid import UUID
from concurrent.futures import ThreadPoolExecutor
import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import app.identity.audit_gate as A
import app.identity.observed_recording_journal as J
from app.identity.evidence_bundle_v2 import canonical,open_artifact
from test_protected_recording_review import verified,keys

OFFICER=str(UUID(int=1))


@pytest.fixture
def setup(verified,keys,tmp_path,monkeypatch):
    public,live,fabric,result,context,now=verified
    crypto,backup=keys
    permit=A.verify_inputs(public,live,fabric,result,context,now=now)
    raw='a'*64;filename='officer_police_numbers.csv'
    row={field:'' for field in J.HEADERS[filename]}
    row.update(police_no='fixture-100',number_type='REGULAR',valid_from='2024-01-01')
    columns=sorted(row)
    catalog={raw:dict(raw_record_id=raw,filename=filename,classification='UNASSESSED',
        delivery={'complete':True},candidate_links=[dict(officer_uid=OFFICER,
        role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')],
        original=dict(columns=columns,values=[row[k] for k in columns]),
        provenance={'fixture':'source-reference'},assertion={'source_assertion_id':str(UUID(int=2))})}
    snapshot=dict(crypto=crypto,backup=backup,public=public,context=context,
        envelope=A.seal_permit(crypto,backup,permit),catalog=catalog,
        bindings={'raw_bindings':{raw:[{'fixture_destination':'a'*64}]}})
    root=tmp_path/'private';root.mkdir(mode=0o700)
    repo=tmp_path/'repo';repo.mkdir()
    signer,authority=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    public_bytes=lambda k:k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    clock=[datetime.now(timezone.utc)]
    monkeypatch.setattr(J,'_now',lambda:clock[0])
    return dict(snapshot=snapshot,root=root,repo=repo,crypto=crypto,backup=backup,
        signer=signer,authority=authority,recorder_keys={'recorder':public_bytes(signer)},
        observation_keys={'authority':public_bytes(authority)},clock=clock)


def baseline(s):
    return J.create_loaded_baseline(s['snapshot'],s['repo'],OFFICER,s['root'],
        s['signer'],'recorder',s['recorder_keys'])


def load(s,pin):
    return J.load_checkpoint(s['root'],s['repo'],s['crypto'],s['backup'],
        s['recorder_keys'],s['observation_keys'],expected_anchor=pin['journal_anchor'],
        checkpoint_file=pin['checkpoint_file'],expected_checkpoint_digest=pin['checkpoint_sha256'])


def authorize(s,pin,claim=None,supersedes=None,withdrawn=False,**changes):
    state=load(s,pin);previous=state['history'].versions[-1]
    if claim is None:
        claim=J._wire(previous.claim)
        if not withdrawn:
            claim['value']=canonical({'police_no':'fixture-200','number_type':'REGULAR'})
            claim['destination_digest']='d'*64;claim['source_reference']='new-committed-fixture-version'
    value=dict(policy=J.AUTH_POLICY,kind='OBSERVATION',journal_anchor=pin['journal_anchor'],
        claim=claim,source_key=previous.source_key,supersedes=supersedes or previous.version_id,
        withdrawn=withdrawn,evidence_epoch_sha256='e'*64,readiness_reference='verified-fixture-epoch',
        issued_at=s['clock'][0].isoformat(),expires_at=(s['clock'][0]+timedelta(seconds=600)).isoformat(),
        status='COMMITTED_VERSION_VERIFIED')
    value.update(changes)
    return dict(key_id='authority',payload=value,signature=base64.b64encode(
        s['authority'].sign(canonical([J.AUTH_POLICY,'authority',value]).encode())).decode())


def append(s,pin,token):
    return J.append_observation(s['root'],s['repo'],s['crypto'],s['backup'],s['signer'],'recorder',
        s['recorder_keys'],s['observation_keys'],token,expected_anchor=pin['journal_anchor'],
        checkpoint_file=pin['checkpoint_file'],expected_checkpoint_digest=pin['checkpoint_sha256'])


def numbers(state,known):
    wrapped=J.query_observed_journal(state,effective_on=date(2024,12,31),known_at=known)
    assert wrapped['coverage_semantics']=='JOURNAL_OBSERVATIONS_ONLY'
    assert not wrapped['source_change_completeness_established'] and wrapped['accepted_state'] is None
    return [json.loads(c.value)['police_no'] for p in wrapped['result'].projections
        if p.dimension=='police_number' for c in p.candidates]


def test_baseline_uses_new_observation_time_preserves_original_claims_and_privacy(setup):
    s=setup;pin=baseline(s);state=load(s,pin)
    start=datetime.fromisoformat(pin['observed_at'])
    assert start==s['clock'][0] and state['history'].coverage_start==start
    assert state['history'].versions[0].claim.start==date(2024,1,1)
    assert numbers(state,start)==['fixture-100']
    with pytest.raises(ValueError):numbers(state,start-timedelta(microseconds=1))
    assert state['baseline']['semantics']=='RECORDER_OBSERVED_ARCHIVED_BASELINE'
    for file in s['root'].iterdir():
        assert file.stat().st_mode & 0o777==0o600
        assert OFFICER not in file.read_text() and 'fixture-100' not in file.read_text()
    assert '2024-01-01' not in pin.values()


def test_corrections_withdrawals_and_old_answers_remain_recoverable(setup):
    s=setup;first=baseline(s);t0=s['clock'][0]
    original=deepcopy(s['snapshot']['catalog'])
    s['clock'][0]+=timedelta(seconds=1)
    second=append(s,first,authorize(s,first));t1=s['clock'][0]
    s['clock'][0]+=timedelta(seconds=1)
    third=append(s,second,authorize(s,second,withdrawn=True));t2=s['clock'][0]
    state=load(s,third)
    assert numbers(state,t0)==['fixture-100'] and numbers(state,t1)==['fixture-200']
    assert numbers(state,t2)==[] and state['history'].versions[-1].withdrawn
    assert s['snapshot']['catalog']==original
    assert numbers(load(s,first),t0)==['fixture-100']
    assert len(list(s['root'].glob('checkpoint-*')))==3


@pytest.mark.parametrize('kind',['scope','source','expired','future','status','epoch','reference',
    'fork','withdrawal_changed','plaintext','signature','untrusted','recorder_self_authority','clock'])
def test_invalid_observation_never_publishes(setup,kind):
    s=setup;pin=baseline(s);s['clock'][0]+=timedelta(seconds=1)
    changes={}
    if kind=='scope':
        claim=J._wire(load(s,pin)['history'].versions[0].claim);claim['officer_uid']=str(UUID(int=3));changes['claim']=claim
    elif kind=='source':changes['source_key']='unknown-source'
    elif kind=='expired':changes.update(issued_at=(s['clock'][0]-timedelta(seconds=600)).isoformat(),expires_at=s['clock'][0].isoformat())
    elif kind=='future':changes.update(issued_at=(s['clock'][0]+timedelta(seconds=1)).isoformat(),expires_at=(s['clock'][0]+timedelta(seconds=601)).isoformat())
    elif kind=='status':changes['status']='PREPARED_NOT_COMMITTED'
    elif kind=='epoch':changes['evidence_epoch_sha256']='unknown'
    elif kind=='reference':changes['readiness_reference']=''
    elif kind=='fork':changes['supersedes']='missing-version'
    elif kind=='withdrawal_changed':changes['withdrawn']=True
    token=authorize(s,pin,**changes)
    if kind=='withdrawal_changed':
        token['payload']['claim']['value']='changed-withdrawal'
        token['signature']=base64.b64encode(s['authority'].sign(canonical([J.AUTH_POLICY,'authority',token['payload']]).encode())).decode()
    elif kind=='plaintext':token=token['payload']
    elif kind=='signature':token['signature']='AAAA'
    elif kind=='untrusted':s['observation_keys']={}
    elif kind=='recorder_self_authority':s['observation_keys']['recorder']=s['recorder_keys']['recorder']
    elif kind=='clock':s['clock'][0]-=timedelta(seconds=2)
    before={p.name:p.read_bytes() for p in s['root'].iterdir()}
    with pytest.raises(Exception):append(s,pin,token)
    assert {p.name:p.read_bytes() for p in s['root'].iterdir()}==before


@pytest.mark.parametrize('kind',['pin','anchor','baseline_bytes','checkpoint_bytes','backup',
    'missing_event','changed_event','wrong_signer','symlink','permissions'])
def test_recovery_requires_exact_private_artifacts_and_independent_pins(setup,kind):
    s=setup;pin=baseline(s);s['clock'][0]+=timedelta(seconds=1)
    pin=append(s,pin,authorize(s,pin))
    if kind=='pin':pin['checkpoint_sha256']='f'*64
    elif kind=='anchor':pin['journal_anchor']='f'*64
    elif kind=='baseline_bytes':(s['root']/'baseline.encrypted.json').write_text('{}')
    elif kind=='checkpoint_bytes':(s['root']/pin['checkpoint_file']).write_text('{}')
    elif kind=='backup':s['backup']=object()
    elif kind=='missing_event':(s['root']/'event-00000001.encrypted.json').unlink()
    elif kind=='changed_event':(s['root']/'event-00000001.encrypted.json').write_text('{}')
    elif kind=='wrong_signer':s['recorder_keys']={'recorder':b'x'*32}
    elif kind=='symlink':
        path=s['root']/'event-00000001.encrypted.json';target=s['root'].parent/'moved';path.rename(target);path.symlink_to(target)
    elif kind=='permissions':(s['root']/pin['checkpoint_file']).chmod(0o644)
    with pytest.raises(Exception):load(s,pin)


def test_stale_append_and_reused_authorization_cannot_replace_new_head(setup):
    s=setup;first=baseline(s);s['clock'][0]+=timedelta(seconds=1)
    token=authorize(s,first);second=append(s,first,token);s['clock'][0]+=timedelta(seconds=1)
    before={p.name:p.read_bytes() for p in s['root'].iterdir()}
    with pytest.raises(ValueError,match='stale'):append(s,first,token)
    with pytest.raises(ValueError):append(s,second,token)
    assert {p.name:p.read_bytes() for p in s['root'].iterdir()}==before


def test_checkpoint_failure_leaves_preserved_uncertain_event_and_blocks_retry(setup,monkeypatch):
    s=setup;first=baseline(s);s['clock'][0]+=timedelta(seconds=1);token=authorize(s,first)
    original=J._publish
    def publish(path,*args):
        if path.name.startswith('checkpoint-'):raise OSError('fixture checkpoint persistence failure')
        return original(path,*args)
    monkeypatch.setattr(J,'_publish',publish)
    with pytest.raises(OSError):append(s,first,token)
    assert (s['root']/'event-00000001.encrypted.json').exists()
    assert len(list(s['root'].glob('checkpoint-*')))==1
    monkeypatch.setattr(J,'_publish',original)
    with pytest.raises(ValueError,match='recovery'):append(s,first,token)


@pytest.mark.parametrize('kind',['not_empty','wrong_signer','permissions','symlink','repository','source','expired'])
def test_baseline_guards_fail_before_publication(setup,kind):
    s=setup
    if kind=='not_empty':(s['root']/'preserved').write_text('keep')
    elif kind=='wrong_signer':s['signer']=Ed25519PrivateKey.generate()
    elif kind=='permissions':s['root'].chmod(0o755)
    elif kind=='symlink':
        link=s['root'].parent/'link';link.symlink_to(s['root'],target_is_directory=True);s['root']=link
    elif kind=='repository':s['root']=s['repo'];s['root'].chmod(0o700)
    elif kind=='source':next(iter(s['snapshot']['catalog'].values()))['classification']='ACCEPTED'
    elif kind=='expired':
        snapshot=s['snapshot'];value=open_artifact(s['crypto'],snapshot['envelope'],A.binding(snapshot['context']))
        value['checked_at']=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat();value['issued_at']=value['checked_at']
        value['expires_at']=(datetime.fromisoformat(value['checked_at'])+timedelta(seconds=600)).isoformat()
        snapshot['envelope']=A.seal_permit(s['crypto'],s['backup'],value)
    before={p.name:p.read_bytes() for p in s['root'].iterdir()}
    with pytest.raises(Exception):baseline(s)
    assert {p.name:p.read_bytes() for p in s['root'].iterdir()}==before


def test_concurrent_append_attempts_publish_only_one_head(setup):
    s=setup;first=baseline(s);s['clock'][0]+=timedelta(seconds=1);token=authorize(s,first)
    def attempt():
        try:return append(s,first,token)
        except ValueError:return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results=list(executor.map(lambda _:attempt(),range(2)))
    assert sum(r is not None for r in results)==1
    assert len(list(s['root'].glob('event-*')))==1
    assert len(load(s,next(r for r in results if r))['history'].versions)==2


def test_authorization_expiry_before_publish_does_not_leave_event(setup,monkeypatch):
    s=setup;first=baseline(s);s['clock'][0]+=timedelta(seconds=1);token=authorize(s,first)
    original=J._publish
    def publish(path,receipt,crypto,backup,binding,check):
        s['clock'][0]+=timedelta(seconds=600)
        return original(path,receipt,crypto,backup,binding,check)
    monkeypatch.setattr(J,'_publish',publish)
    with pytest.raises(ValueError,match='expired'):append(s,first,token)
    assert not list(s['root'].glob('event-*')) and not list(s['root'].glob('.observation-*'))


def test_ciphertext_json_reformatting_cannot_bypass_exact_file_pins(setup):
    s=setup;pin=baseline(s);path=s['root']/pin['checkpoint_file']
    value=json.loads(path.read_text());path.write_text(json.dumps(value,indent=2)+'\n')
    with pytest.raises(ValueError,match='pin'):load(s,pin)


@pytest.mark.parametrize('seed',[b'E'*32,b'L'*32])
def test_signing_key_cannot_reuse_encryption_or_lookup_material(setup,seed):
    s=setup;s['signer']=Ed25519PrivateKey.from_private_bytes(seed)
    s['recorder_keys']={'recorder':s['signer'].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    with pytest.raises(ValueError,match='separate'):baseline(s)
    assert not list(s['root'].iterdir())


def test_public_baseline_entry_uses_full_replay_loader_and_propagates_failure(setup,monkeypatch):
    import app.identity.algorithm_snapshot as S
    s=setup;seen=[]
    def loader(args,repo,revision):
        seen.append((args,repo,revision));return s['snapshot']
    monkeypatch.setattr(S,'load_verified_snapshot',loader)
    J.create_baseline('fixture-args',s['repo'],'c'*40,OFFICER,s['root'],s['signer'],'recorder',s['recorder_keys'])
    assert seen==[('fixture-args',s['repo'],'c'*40)]
    def blocked(*args):raise ValueError('Full replay refused')
    monkeypatch.setattr(S,'load_verified_snapshot',blocked)
    with pytest.raises(ValueError,match='Full replay'):
        J.create_baseline('fixture-args',s['repo'],'c'*40,OFFICER,s['root'],s['signer'],'recorder',s['recorder_keys'])


def test_baseline_permit_expiry_after_staging_leaves_no_completed_artifact(setup,monkeypatch):
    s=setup;original=J.AlgorithmPermit.check;calls=[]
    def check(self,snapshot):
        calls.append(1)
        if len(calls)==2:
            permit=open_artifact(s['crypto'],snapshot['envelope'],A.binding(snapshot['context']))
            return original(self,snapshot,now=datetime.fromisoformat(permit['expires_at']))
        return original(self,snapshot)
    monkeypatch.setattr(J.AlgorithmPermit,'check',check)
    with pytest.raises(ValueError,match='expired'):baseline(s)
    assert not list(s['root'].iterdir())


def test_caller_token_mutation_cannot_change_authenticated_recording(setup,monkeypatch):
    s=setup;pin=baseline(s);s['clock'][0]+=timedelta(seconds=1);token=authorize(s,pin)
    original=J._publish
    def publish(path,*args):
        if path.name.startswith('event-'):
            token['payload']['claim']['value']='caller-mutated-after-authentication'
        return original(path,*args)
    monkeypatch.setattr(J,'_publish',publish)
    new=append(s,pin,token)
    assert numbers(load(s,new),s['clock'][0])==['fixture-200']
