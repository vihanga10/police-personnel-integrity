"""Disposable encrypted fixtures; no production storage or reviewer authority claim."""
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from uuid import UUID
from concurrent.futures import ThreadPoolExecutor
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity.evidence_bundle_v2 import open_artifact,seal_artifact,canonical
from app.identity.protected_commitment import digest
from test_protected_contradiction_runner import output,run,recover,next_checkpoint
from test_recording_tip_witness import witnessed
from test_observed_recording_journal import setup,OFFICER
from test_protected_recording_review import verified,keys

OP=str(UUID(int=101));ID=str(UUID(int=102));LEDGER=str(UUID(int=103))


@pytest.fixture
def journal(witnessed,output,tmp_path):
    t=witnessed;s=t['s'];run(t,output)
    root=tmp_path/'findings';root.mkdir(mode=0o700)
    writer=Ed25519PrivateKey.generate();reviewer=Ed25519PrivateKey.generate()
    kwargs=dict(root=root,repo=s['repo'],ledger_id=LEDGER,officer_uid=OFFICER,crypto=s['crypto'],backup=s['backup'],
        signer=writer,key_id='findings-writer',writer_keys={'findings-writer':J._public(writer)},
        reviewer_keys={'findings-reviewer':J._public(reviewer)})
    ledger=F.FindingsJournal(**kwargs)
    return dict(t=t,ledger=ledger,kwargs=kwargs,reviewer=reviewer,output=output)


def add(d,tip=None,**changes):
    l=d['ledger'];args=dict(expected_tip=tip or l.empty_tip(),operation_id=OP,finding_id=ID,receipt_path=d['output'])
    args.update(changes);return l.append_receipt(**args)


def review(d,tip,**changes):
    now=d['t']['s']['clock'][0]
    args=dict(signer=d['reviewer'],key_id='findings-reviewer',reviewer_keys=d['ledger'].reviewer_keys,crypto=d['ledger'].crypto,backup=d['ledger'].backup,
        ledger_id=LEDGER,officer_uid=OFFICER,finding_id=ID,target_entry_sha256=tip['entry_sha256'],
        operation_id=str(UUID(int=104)),decision='NEEDS_MORE_EVIDENCE',reason='fixture review explanation',
        evidence_references=['fixture source reference'],issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=30)).isoformat())
    args.update(changes);return F.issue_review_intent(**args)


def advance(d):d['t']['s']['clock'][0]+=timedelta(seconds=1)


def test_encrypted_original_preserves_full_receipt_and_private_summary(journal):
    d=journal;l=d['ledger'];expected=recover(d['t'],d['output']);r=add(d);entries=l.read(r['tip'])
    assert entries[0]['entry']['finding']==expected
    assert entries[0]['entry']['receipt_sha256']==sha256(d['output'].read_bytes()).hexdigest()
    data=next(l.root.iterdir()).read_text()
    assert OFFICER not in data and 'fixture-100' not in data and 'source_reference' not in data
    assert 'finding' not in r and OFFICER not in json.dumps(r)
    assert next(l.root.iterdir()).stat().st_mode&0o777==0o600
    assert not r['findings_anchored'] and r['accepted_state'] is None


def test_correction_and_review_preserve_original_and_restart(journal):
    d=journal;l=d['ledger'];first=add(d);original=next(l.root.iterdir()).read_bytes()
    pin=next_checkpoint(d['t']);d['t']['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    newer=d['output'].parent/'newer.json';run(d['t'],newer)
    second=add(d,first['tip'],operation_id=str(UUID(int=105)),receipt_path=newer,
        supersedes=first['tip']['entry_sha256'],reason='fixture updated comparison')
    advance(d);token=review(d,second['tip'])
    third=l.append_review(expected_tip=second['tip'],intent=token)
    assert (l.root/'entry-00000001.encrypted.json').read_bytes()==original
    restarted=F.FindingsJournal(**d['kwargs']);entries=restarted.read(third['tip'])
    assert [e['entry']['kind'] for e in entries]==['FINDING','CORRECTION','REVIEW']
    assert entries[1]['entry']['supersedes']==first['tip']['entry_sha256']
    assert entries[2]['entry']['review']==token
    assert entries[0]['entry']['finding']['comparison']!=entries[1]['entry']['finding']['comparison']


def test_retry_is_idempotent_and_changed_retry_refused(journal):
    d=journal;l=d['ledger'];r=add(d);before=next(l.root.iterdir()).read_bytes()
    assert add(d,r['tip'])['status']=='ALREADY_RECORDED'
    with pytest.raises(ValueError,match='retry content'):add(d,r['tip'],reason='different')
    assert next(l.root.iterdir()).read_bytes()==before and len(l.read(r['tip']))==1


@pytest.mark.parametrize('kind',['stale','rollback','digest','unknown-file','symlink','permission','ciphertext'])
def test_inventory_integrity_blocks_reads(journal,kind):
    d=journal;l=d['ledger'];r=add(d);tip=deepcopy(r['tip']);p=l.root/'entry-00000001.encrypted.json'
    if kind=='stale':tip=l.empty_tip()
    elif kind=='rollback':p.unlink()
    elif kind=='digest':tip['entry_sha256']='f'*64
    elif kind=='unknown-file':(l.root/'unexpected').write_text('fixture')
    elif kind=='symlink':p.rename(l.root/'hidden');p.symlink_to(l.root/'hidden')
    elif kind=='permission':p.chmod(0o644)
    else:
        e=json.loads(p.read_text());e['ciphertext']='A'*len(e['ciphertext']);p.write_text(json.dumps(e))
    with pytest.raises((ValueError,InvalidTag)):l.read(tip)


@pytest.mark.parametrize('kind',['wrong-scope','accepted','digest','binding','symlink','permission'])
def test_receipt_import_rejects_invalid_inputs(journal,kind):
    d=journal;l=d['ledger'];p=d['output']
    if kind in ('wrong-scope','accepted','digest','binding'):
        envelope=json.loads(p.read_text());binding=envelope['binding'];value=open_artifact(l.crypto,envelope,binding)
        if kind=='wrong-scope':value['officer_uid']=str(UUID(int=999))
        elif kind=='accepted':value['accepted_contradiction']=True
        elif kind=='binding':binding['artifact']='OTHER'
        if kind!='digest':binding['result_sha256']=digest(value)
        else:binding['result_sha256']='e'*64
        p.write_text(canonical(seal_artifact(l.crypto,l.backup,value,binding)))
    elif kind=='symlink':target=p.parent/'other';p.rename(target);p.symlink_to(target)
    else:p.chmod(0o644)
    with pytest.raises(ValueError):add(d)
    assert not list(l.root.iterdir())


@pytest.mark.parametrize('kind',['stale-head','tamper','unknown-key','expired','future','scope','decision'])
def test_invalid_reviews_append_nothing(journal,kind):
    d=journal;l=d['ledger'];r=add(d);advance(d)
    changes={}
    if kind=='stale-head':changes['target_entry_sha256']='e'*64
    if kind=='scope':changes['officer_uid']=str(UUID(int=888))
    if kind=='expired':
        now=d['t']['s']['clock'][0];changes=dict(issued_at=(now-timedelta(seconds=30)).isoformat(),expires_at=(now-timedelta(seconds=1)).isoformat())
    if kind=='future':
        now=d['t']['s']['clock'][0];changes=dict(issued_at=(now+timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(seconds=30)).isoformat())
    if kind=='decision':
        with pytest.raises(ValueError):review(d,r['tip'],decision='ACCEPT_PERSONNEL_TRUTH')
        return
    token=review(d,r['tip'],**changes)
    if kind=='tamper':token['payload']['reason']='altered'
    if kind=='unknown-key':token['key_id']='unknown'
    with pytest.raises(ValueError):l.append_review(expected_tip=r['tip'],intent=token)
    assert len(l.read(r['tip']))==1


def test_stale_correction_head_cannot_branch(journal):
    d=journal;r=add(d);advance(d)
    r2=add(d,r['tip'],operation_id=str(UUID(int=105)),supersedes=r['tip']['entry_sha256'],reason='first correction')
    advance(d)
    with pytest.raises(ValueError,match='current finding head'):
        add(d,r2['tip'],operation_id=str(UUID(int=106)),supersedes=r['tip']['entry_sha256'],reason='branch')
    assert len(d['ledger'].read(r2['tip']))==2


def test_review_signature_survives_replay_beyond_expiry(journal):
    d=journal;l=d['ledger'];r=add(d);advance(d);token=review(d,r['tip'])
    r2=l.append_review(expected_tip=r['tip'],intent=token)
    d['t']['s']['clock'][0]+=timedelta(days=1)
    assert len(l.read(r2['tip']))==2  # validate at original recording instant
    assert l.append_review(expected_tip=r2['tip'],intent=token)['status']=='ALREADY_RECORDED'


def test_concurrent_stale_writers_have_one_winner(journal):
    d=journal;l=d['ledger'];other=F.FindingsJournal(**d['kwargs']);tip=l.empty_tip()
    def call(ledger,operation):
        try:return ledger.append_receipt(expected_tip=tip,operation_id=operation,finding_id=ID,receipt_path=d['output'])['status']
        except ValueError:return 'REFUSED'
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs=[pool.submit(call,l,OP),pool.submit(call,other,str(UUID(int=106)))]
        assert sorted(j.result() for j in jobs)==['RECORDED','REFUSED']
    assert len(list(l.root.iterdir()))==1


def test_interrupted_publication_requires_explicit_recovery(journal,monkeypatch):
    d=journal;l=d['ledger'];tip=l.empty_tip();original=J._publish
    def publish(*args):original(*args);raise OSError('fixture response lost after publication')
    monkeypatch.setattr(J,'_publish',publish)
    with pytest.raises(OSError):add(d)
    with pytest.raises(ValueError):l.read(tip)
    p=l.root/'entry-00000001.encrypted.json';sha=sha256(p.read_bytes()).hexdigest()
    with pytest.raises(ValueError):l.recover_pending(expected_tip=tip,operation_id=str(UUID(int=999)),approved_entry_sha256=sha)
    result=l.recover_pending(expected_tip=tip,operation_id=OP,approved_entry_sha256=sha)
    assert result['status']=='RECOVERED' and len(l.read(result['tip']))==1
    assert add(d,result['tip'])['status']=='ALREADY_RECORDED'


@pytest.mark.parametrize('kind',['same-key','wrong-writer','public-root','repo-root'])
def test_configuration_refused(journal,kind):
    kwargs=dict(journal['kwargs'])
    if kind=='same-key':kwargs['reviewer_keys']=kwargs['writer_keys']
    elif kind=='wrong-writer':kwargs['signer']=Ed25519PrivateKey.generate()
    elif kind=='public-root':kwargs['root'].chmod(0o755)
    else:kwargs['root']=kwargs['repo']
    with pytest.raises(ValueError):F.FindingsJournal(**kwargs)


def test_clock_rollback_and_staging_failure_leave_no_entry(journal,monkeypatch):
    d=journal;l=d['ledger'];r=add(d)
    d['t']['s']['clock'][0]-=timedelta(seconds=1)
    with pytest.raises(ValueError):add(d,r['tip'],operation_id=str(UUID(int=106)),finding_id=str(UUID(int=107)))
    advance(d);advance(d)
    def fail(*a):raise OSError('fixture staging failure')
    monkeypatch.setattr(J.os,'fsync',fail)
    with pytest.raises(OSError):add(d,r['tip'],operation_id=str(UUID(int=106)),finding_id=str(UUID(int=107)))
    assert len(l.read(r['tip']))==1 and len(list(l.root.iterdir()))==1


def test_changed_signed_payload_is_rejected_even_with_matching_file_pin(journal):
    d=journal;l=d['ledger'];r=add(d);p=l.root/'entry-00000001.encrypted.json'
    envelope=json.loads(p.read_text());binding=envelope['binding']
    receipt=open_artifact(l.crypto,envelope,binding)
    receipt['payload']['operation_id']=str(UUID(int=777))
    p.write_text(canonical(seal_artifact(l.crypto,l.backup,receipt,binding)))
    tip=dict(r['tip'],entry_sha256=sha256(p.read_bytes()).hexdigest())
    with pytest.raises(ValueError,match='signature'):l.read(tip)


def test_candidate_provenance_and_reasons_survive_storage(hooked,output,tmp_path):
    from app.identity import bitemporal_contradictions as D
    from test_controlled_recording_hook import route,process
    h=hooked;t=h['d']['t'];process(h,route(h,supersedes=None));run(t,output)
    root=tmp_path/'candidate-findings';root.mkdir(mode=0o700)
    writer=Ed25519PrivateKey.generate();reviewer=Ed25519PrivateKey.generate();s=t['s']
    l=F.FindingsJournal(root=root,repo=s['repo'],ledger_id=LEDGER,officer_uid=OFFICER,
        crypto=s['crypto'],backup=s['backup'],signer=writer,key_id='writer',
        writer_keys={'writer':J._public(writer)},reviewer_keys={'reviewer':J._public(reviewer)})
    result=l.append_receipt(expected_tip=l.empty_tip(),operation_id=OP,finding_id=ID,receipt_path=output)
    stored=l.read(result['tip'])[0]['entry']['finding']
    assert stored==recover(t,output)
    pair=stored['comparison']['comparisons'][0]
    assert pair['status']==D.CANDIDATE and len(pair['source_references'])==2
    assert pair['reasons'] and not pair['accepted_contradiction']
    assert all(reference not in next(root.iterdir()).read_text() for reference in pair['source_references'])


from test_controlled_recording_hook import hooked
from test_committed_evidence_capture import committed


def test_reviewer_signing_seed_cannot_reuse_encryption_key(journal):
    d=journal;l=d['ledger'];r=add(d)
    seed=next(iter(l.crypto.encryption_keys.values()));signer=Ed25519PrivateKey.from_private_bytes(seed)
    with pytest.raises(ValueError,match='separate'):
        review(d,r['tip'],signer=signer,reviewer_keys={'findings-reviewer':J._public(signer)})
