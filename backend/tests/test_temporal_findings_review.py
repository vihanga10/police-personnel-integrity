"""Invented independently signed assessments; no police-law or deployment claim."""
from copy import deepcopy
from dataclasses import asdict,replace
from datetime import date,timedelta
from hashlib import sha256
from uuid import UUID
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.identity import temporal_findings_review as M,encrypted_findings_journal as F
from app.identity import findings_tip_registry as R,findings_tip_witness as W,observed_recording_journal as J
from app.identity.action_authority_integration import AuthorityAssessment,StateAssessment
from app.identity.temporal_authority import Fact,ActorState,Rule,Delegation
from app.identity.protected_commitment import digest
from app.identity.run_research_algorithms import json_value
from test_findings_tip_witness import witnessed_findings,registered,journal,output,witnessed,setup,verified,keys,OP,ID,OFFICER,advance,authorize,inventory

REF='fixture-instrument-and-assessed-state';SCOPE='fixture-subject-scope'
REVIEW_OP=str(UUID(int=902));ISSUER=str(UUID(int=903))


def fact(value,assessment='ASSESSED'):return Fact(value,assessment,(REF,))


@pytest.fixture
def authorized(witnessed_findings):
    d=witnessed_findings;j=d['t']['d']['ledger'];s=d['t']['d']['t']['s'];assessor=Ed25519PrivateKey.generate()
    config=dict(authority_keys={'assessor':J._public(assessor)},reviewer_identities={'findings-reviewer':OFFICER},
        authority_scopes={'assessor':(SCOPE,)})
    j=F.FindingsJournal(**d['t']['d']['kwargs'],**config)
    kwargs=dict(d['t']['kwargs']);kwargs['journal']=j;r=R.FindingsTipRegistry(**kwargs)
    d['t']['d']['ledger']=j;d['t']['r']=r;d['t']['kwargs']=kwargs
    d['adapter']=W.WitnessedFindingsRegistry(r,d['client'],fixture_transport=True)
    s['snapshot']['manifest']={'bundles':[{'officer_uid':OFFICER},{'officer_uid':ISSUER}]}
    s['snapshot']['captured_at']=s['clock'][0]
    first=d['adapter'].append_receipt(operation_id=OP,finding_id=ID,receipt_path=d['t']['d']['output'])
    advance(d['t']['d'])
    return dict(d=d,j=j,s=s,assessor=assessor,first=first)


def request(t,**changes):
    args=dict(finding_id=ID,target_entry_sha256=t['first']['journal_tip']['entry_sha256'],operation_id=REVIEW_OP,
        reviewer_uid=OFFICER,reviewer_key_id='findings-reviewer',decision='NEEDS_MORE_EVIDENCE',reason='fixture review reason',
        evidence_references=[REF],reviewed_at=t['s']['clock'][0].isoformat(),target_scope=SCOPE,
        finding_receipt_sha256=sha256(t['d']['t']['d']['output'].read_bytes()).hexdigest())
    args.update(changes);return M.review_request(t['s']['snapshot'],t['j'],**args)


def state(t,uid=OFFICER,on=None,**changes):
    on=on or M._review_day(t['s']['clock'][0]);identifier,_=M._history(t['s']['snapshot']).project(uid,on)
    args=dict(actor_uid=uid,on=on,identity=fact(True),rank=fact('fixture-rank'),role=fact('fixture-review-role'),
        active=fact(True),scope=fact('fixture-actor-scope'));args.update(changes)
    return StateAssessment(identifier,ActorState(**args))


def packet(t,r,**changes):
    on=M._action(r).reported_date
    rule=Rule('fixture-review-rule',('REVIEW_FINDING:'+r['decision'],),('fixture-rank',),('fixture-review-role',),
        ('fixture-actor-scope',),(SCOPE,),date(2020,1,1),None,True,'ASSESSED',(REF,))
    args=dict(public_payload_sha256=r['public_payload_sha256'],original_action_digest=digest(json_value(asdict(M._action(r)))),
        destination_digest=r['target_entry_sha256'],actor_uid=r['reviewer_uid'],target_scope=r['target_scope'],
        identity=fact(True),date_semantics=fact(True),coverage=fact(True),states=(state(t,on=date.fromisoformat(on)),),
        rules=(rule,),delegations=(),evidence_digests=((REF,sha256(b'fixture-assessed-evidence').hexdigest()),))
    args.update(changes);return AuthorityAssessment(**args)


def authority(t,r=None,p=None,**changes):
    r=r or request(t);p=p or packet(t,r)
    args=dict(request=r,assessment=p,target_membership=fact(True),evidence={REF:b'fixture-assessed-evidence'},
        signer=t['assessor'],key_id='assessor',expires_at=(M.F._time(r['reviewed_at'])+timedelta(seconds=60)).isoformat())
    args.update(changes)
    return M.issue_authority_assessment(t['s']['snapshot'],t['j'],**args)


def intent(t,a=None):
    return M.issue_authorized_review_intent(t['j'],authority=a or authority(t),signer=t['d']['t']['d']['reviewer'],key_id='findings-reviewer')


def record(t,i,**changes):
    args=dict(intent=i,expected_authority_sha256=digest(i['payload']['authority']),finding_receipt_path=t['d']['t']['d']['output'])
    args.update(changes)
    return M.record_loaded_review(t['s']['snapshot'],t['s']['repo'],t['d']['adapter'],**args)


def test_valid_review_is_encrypted_witnessed_replayable_and_idempotent(authorized):
    t=authorized;i=intent(t)
    assert record(t,i)['status']=='REVIEWED'
    before=inventory(t['d']);selected=t['d']['adapter'].select()
    assert selected['entries'][-1]['entry']['review']==i and selected['registry_tip']['sequence']==2
    assert record(t,i)['status']=='ALREADY_REVIEWED' and inventory(t['d'])==before
    assert OFFICER not in str(record(t,i))
    advance(t['d']['t']['d']);t['s']['clock'][0]+=timedelta(seconds=120)
    assert t['d']['adapter'].select()['entries'][-1]['entry']['review']==i


@pytest.mark.parametrize('kind',['inactive','rank','role','scope','identity','date','coverage','unassessed-rule','expired-rule','wrong-power'])
def test_invalid_or_unverifiable_authority_cannot_issue_review(authorized,kind):
    t=authorized;r=request(t);p=packet(t,r)
    if kind in ('inactive','rank','role','scope'):
        values=dict(inactive=('active',fact(False)),rank=('rank',fact('other')),role=('role',fact('other')),scope=('scope',fact('other')))
        key,value=values[kind];p=replace(p,states=(state(t,**{key:value}),))
    elif kind=='identity':p=replace(p,identity=fact(None,'UNASSESSED'))
    elif kind=='date':p=replace(p,date_semantics=fact(None,'UNASSESSED'))
    elif kind=='coverage':p=replace(p,rules=(),coverage=fact(None,'UNASSESSED'))
    elif kind=='unassessed-rule':p=replace(p,rules=(replace(p.rules[0],assessment='UNASSESSED'),))
    elif kind=='expired-rule':p=replace(p,rules=(replace(p.rules[0],end=M._review_day(t['s']['clock'][0])),))
    else:p=replace(p,rules=(replace(p.rules[0],powers=('OTHER_ACTION',)),))
    a=authority(t,r,p);before=inventory(t['d'])
    with pytest.raises(ValueError):intent(t,a)
    assert inventory(t['d'])==before


@pytest.mark.parametrize('kind',['evidence','membership','scope','key','state-version'])
def test_assessment_requires_evidence_custody_and_exact_histories(authorized,kind):
    t=authorized;r=request(t);p=packet(t,r);changes={}
    if kind=='evidence':changes['evidence']={REF:b'changed evidence bytes'}
    if kind=='membership':changes['target_membership']=fact(None,'UNASSESSED')
    if kind=='scope':r=request(t,target_scope='unapproved-scope');p=packet(t,r)
    if kind=='key':changes['signer']=Ed25519PrivateKey.generate()
    if kind=='state-version':p=replace(p,states=(replace(p.states[0],state_id='f'*64),))
    with pytest.raises(ValueError):authority(t,r,p,**changes)
    assert len(t['d']['adapter'].select()['entries'])==1


@pytest.mark.parametrize('kind',['assessor-signature','reviewer-signature','approved-pin','receipt','target-head','backdated','future'])
def test_review_publication_rejects_changed_request_and_artifacts(authorized,kind):
    t=authorized;i=intent(t);changes={}
    if kind=='assessor-signature':i['payload']['authority']['signature']='bad'
    if kind=='reviewer-signature':i['signature']='bad'
    if kind=='approved-pin':changes['expected_authority_sha256']='f'*64
    if kind=='receipt':t['d']['t']['d']['output'].write_text('{}')
    if kind=='target-head':
        t['d']['adapter'].append_receipt(operation_id=str(UUID(int=920)),finding_id=ID,receipt_path=t['d']['t']['d']['output'],
            supersedes=t['first']['journal_tip']['entry_sha256'],reason='fixture correction');advance(t['d']['t']['d'])
    if kind in ('backdated','future'):
        r=request(t,reviewed_at=(t['s']['clock'][0]+timedelta(days=-1 if kind=='backdated' else 1)).isoformat())
        before=inventory(t['d'])
        with pytest.raises(ValueError):intent(t,authority(t,r))
        assert inventory(t['d'])==before
        return
    before=inventory(t['d'])
    with pytest.raises(Exception):record(t,i,**changes)
    assert inventory(t['d'])==before


def delegated(t,change=None):
    r=request(t);p=packet(t,r);on=M._review_day(t['s']['clock'][0]);issued=on-timedelta(days=2)
    grant=Delegation('fixture-review-grant','fixture-review-rule',ISSUER,OFFICER,
        p.rules[0].powers,(SCOPE,),issued,issued,None,False,None,'ASSESSED',(REF,))
    issuer_on=state(t,ISSUER,on=on);issuer_issued=state(t,ISSUER,on=issued)
    if change=='issuer-inactive':issuer_on=state(t,ISSUER,on=on,active=fact(False))
    if change=='revoked':grant=replace(grant,revoked_from=on)
    if change=='missing-issuer':issuer_on=state(t,ISSUER,on=on,identity=fact(None,'UNASSESSED'))
    rule=p.rules[0]
    if change=='no-delegation':rule=replace(rule,may_delegate=False)
    if change=='scope-expansion':grant=replace(grant,target_scopes=(SCOPE,'other-scope'))
    p=replace(p,states=(state(t,rank=fact('recipient-rank')),issuer_issued,issuer_on),rules=(rule,),delegations=(grant,))
    return authority(t,r,p)


def test_delegation_reconstructs_issuer_both_dates_and_records_explanation(authorized):
    t=authorized;i=intent(t,delegated(t));assert record(t,i)['status']=='REVIEWED'
    proof=i['payload']['authority']['payload']
    links=proof['actor_state_links']
    assert len([l for l in links if l['officer_uid']==ISSUER])==2
    assert i['payload']['authority_decision']['successful_paths']==['fixture-review-grant']
    assert t['d']['adapter'].select()['entries'][-1]['entry']['review']==i


@pytest.mark.parametrize('change',['issuer-inactive','revoked','missing-issuer','no-delegation','scope-expansion'])
def test_delegation_cannot_bypass_temporal_constraints(authorized,change):
    t=authorized;a=delegated(t,change)
    with pytest.raises(ValueError):intent(t,a)
    assert len(t['d']['adapter'].select()['entries'])==1


@pytest.mark.parametrize('kind',['source','permit','receipt','witness','trust-config'])
def test_final_staging_guard_blocks_changed_authorization(authorized,monkeypatch,kind):
    t=authorized;i=intent(t);original=J._publish
    def intercept(path,*args,**kwargs):
        if path.parent==t['j'].root and path.name=='entry-00000002.encrypted.json':
            if kind=='source':t['s']['snapshot']['catalog']['changed']={}
            elif kind=='permit':t['s']['snapshot']['envelope']['binding']['changed']=True
            elif kind=='receipt':t['d']['t']['d']['output'].write_text('{}')
            elif kind=='trust-config':t['j'].reviewer_identities['findings-reviewer']=ISSUER
            else:t['d']['client'].exchange=lambda *a,**k:(_ for _ in ()).throw(ConnectionError('offline'))
        return original(path,*args,**kwargs)
    monkeypatch.setattr(J,'_publish',intercept)
    with pytest.raises(Exception):record(t,i)
    assert not (t['j'].root/'entry-00000002.encrypted.json').exists()


@pytest.mark.parametrize('kind',['identity','scope','assessor','domain'])
def test_authority_config_drift_or_overlapping_keys_refused(authorized,kind):
    t=authorized;i=intent(t);j=t['j']
    if kind=='identity':j.reviewer_identities['findings-reviewer']=ISSUER
    if kind=='scope':j.authority_scopes['assessor']=('unapproved-scope',)
    if kind=='assessor':j.authority_keys['assessor']=J._public(Ed25519PrivateKey.generate())
    if kind=='domain':j.authority_keys['assessor']=next(iter(j.reviewer_keys.values()))
    with pytest.raises(ValueError):record(t,i)
    assert not (j.root/'entry-00000002.encrypted.json').exists()


def test_reported_legacy_intent_cannot_enter_protected_review_adapter(authorized):
    from test_encrypted_findings_journal import review
    t=authorized;i=review(t['d']['t']['d'],t['first']['journal_tip'])
    with pytest.raises(ValueError):M.record_loaded_review(t['s']['snapshot'],t['s']['repo'],t['d']['adapter'],intent=i,
        expected_authority_sha256='f'*64,finding_receipt_path=t['d']['t']['d']['output'])
    assert len(t['d']['adapter'].select()['entries'])==1


@pytest.mark.parametrize('lost_after_commit',[True,False])
def test_review_witness_interruption_and_signed_recovery(authorized,lost_after_commit):
    t=authorized;d=t['d'];i=intent(t);original=d['client'].exchange
    def fail(receipt):
        if receipt['payload']['operation']=='CAS':
            if lost_after_commit:original(receipt)
            raise OSError('fixture witness acknowledgement failure')
        return original(receipt)
    d['client'].exchange=fail
    with pytest.raises(OSError):record(t,i)
    d['client'].exchange=original
    if not lost_after_commit:
        with pytest.raises(ValueError):record(t,i)
        r=d['t']['r'];j=t['j']
        rt=r._tip(2,sha256((r.root/'entry-00000002.encrypted.json').read_bytes()).hexdigest())
        jt=j._tip(2,sha256((j.root/'entry-00000002.encrypted.json').read_bytes()).hexdigest())
        d['adapter'].recover(authorize(d,jt,pending_registry_tip=rt,operation_id=REVIEW_OP))
    before=inventory(d)
    assert record(t,i)['status']=='ALREADY_REVIEWED' and inventory(d)==before


def test_public_entry_requires_mutual_tls_not_fixture(authorized):
    t=authorized;i=intent(t)
    with pytest.raises(ValueError):M.record_review(None,t['s']['repo'],'fixture',t['d']['adapter'],intent=i,
        expected_authority_sha256=digest(i['payload']['authority']),finding_receipt_path=t['d']['t']['d']['output'])
    assert len(t['d']['adapter'].select()['entries'])==1


def test_configured_ledger_refuses_new_legacy_or_unguarded_reviews(authorized):
    from test_encrypted_findings_journal import review
    t=authorized;legacy=review(t['d']['t']['d'],t['first']['journal_tip'])
    for i in (legacy,intent(t)):
        with pytest.raises(ValueError):t['d']['adapter'].append_review(intent=i)
    assert len(t['d']['adapter'].select()['entries'])==1


def test_authority_explanation_tampering_rejected_even_when_reviewer_resigns(authorized):
    t=authorized;i=intent(t);i['payload']['authority_decision']['reasons']=[]
    forged=J._sign(i['payload'],t['d']['t']['d']['reviewer'],'findings-reviewer',F.AUTHORIZED_REVIEW_POLICY)
    with pytest.raises(ValueError):record(t,forged)
    assert len(t['d']['adapter'].select()['entries'])==1


def test_expired_token_cannot_create_new_review_but_completed_retry_remains_audit(authorized):
    t=authorized;i=intent(t);t['s']['clock'][0]+=timedelta(seconds=61)
    with pytest.raises(ValueError):record(t,i)
    assert len(t['d']['adapter'].select()['entries'])==1


from test_witness_secure_transport import certs,listener

def test_public_entry_full_loader_and_actual_mutual_tls_review(authorized,tmp_path,monkeypatch):
    import socket
    from app.identity import recording_tip_witness as Q,witness_secure_transport as T,algorithm_snapshot
    t=authorized;d=t['d'];r=d['t']['r'];i=intent(t);pki=certs(tmp_path/'review-pki',J._now())
    control=tmp_path/'review-control';control.mkdir(mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    profile=control/'profile.json'
    pin=T.provision(d['server'],profile_path=profile,endpoint=f'https://127.0.0.1:{port}'+T.PATH,
        ca_certificate=pki['ca'],server_certificate=pki['server'],server_key=pki['server_key'],
        client_certificates={r.key_id:pki['client']})
    server_args=dict(profile_path=profile,expected_profile_sha256=pin,ca_certificate=pki['ca'],
        server_certificate=pki['server'],server_key=pki['server_key'])
    transport_args=dict(profile_path=profile,expected_profile_sha256=pin,witness_keys=d['args']['witness_keys'],
        repo=t['s']['repo'],ca_certificate=pki['ca'],client_certificate=pki['client'],client_key=pki['client_key'])
    calls=[]
    def loader(*args):calls.append(args);return t['s']['snapshot']
    monkeypatch.setattr(algorithm_snapshot,'load_verified_snapshot',loader)
    with listener(dict(port=port,t={'server':d['server']},server_args=server_args)):
        adapter=W.WitnessedFindingsRegistry(r,Q.WitnessClient(**d['client_args'],exchange=T.HTTPSWitnessTransport(**transport_args)))
        result=M.record_review('fixture',t['s']['repo'],'fixture-revision',adapter,intent=i,
            expected_authority_sha256=digest(i['payload']['authority']),finding_receipt_path=d['t']['d']['output'])
        assert result['status']=='REVIEWED' and len(calls)==1
        assert adapter.select()['registry_tip']['sequence']==2


def test_review_date_uses_explicit_sri_lanka_calendar():
    from datetime import datetime,timezone
    assert M._review_day(datetime(2026,10,10,18,29,tzinfo=timezone.utc))==date(2026,10,10)
    assert M._review_day(datetime(2026,10,10,18,30,tzinfo=timezone.utc))==date(2026,10,11)


def test_authorized_review_survives_restart_with_pinned_trust(authorized):
    t=authorized;i=intent(t);record(t,i);d=t['d'];j=t['j']
    fresh=F.FindingsJournal(**d['t']['d']['kwargs'],authority_keys=j.authority_keys,
        reviewer_identities=j.reviewer_identities,authority_scopes=j.authority_scopes)
    kwargs=dict(d['t']['kwargs']);kwargs['journal']=fresh
    registry=R.FindingsTipRegistry(**kwargs)
    adapter=W.WitnessedFindingsRegistry(registry,d['client'],fixture_transport=True)
    before=inventory(d)
    assert adapter.select()['entries'][-1]['entry']['review']==i and inventory(d)==before


def test_assessment_system_time_is_actual_issuance_not_request_time(authorized):
    t=authorized;r=request(t);t['s']['clock'][0]+=timedelta(seconds=2)
    a=authority(t,r)
    assert a['payload']['issued_at']==t['s']['clock'][0].isoformat()
    assert a['payload']['issued_at']!=r['reviewed_at']
    i=intent(t,a);assert record(t,i)['status']=='REVIEWED'
