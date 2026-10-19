"""Authenticated assessed authority for finding reviews; trusted backend only.

No law is inferred from rank, key possession or reported CSV text. Configured
assessment signers are an explicit trust root, not self-issued reviewer powers.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import date,datetime,timedelta,timezone
import base64
import hashlib
from pathlib import Path
from zoneinfo import ZoneInfo
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity import findings_tip_witness as W
from app.identity import protected_findings_capture as C
from app.identity.action_actor_history import ActorHistory
from app.identity.action_authority_integration import AuthorityAssessment,StateAssessment,ActionAuthority
from app.identity.reported_authority_actions import ActionReview
from app.identity.temporal_authority import Fact,ActorState,Rule,Delegation,Action,evaluate
from app.identity.reconstruct_history import subject_index
from app.identity.run_research_algorithms import json_value
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require

POLICY='PROTECTED_TEMPORAL_FINDINGS_REVIEW_V1'
REVIEW_TIMEZONE='Asia/Colombo'
ASSESSMENT_POLICY='AUTHENTICATED_FINDINGS_REVIEW_ASSESSMENT_V1'
ASSESSMENT_FIELDS={'policy','kind','request','assessment','target_membership','evidence',
    'actor_state_links','issued_at','expires_at'}
REQUEST_FIELDS=F.REVIEW_FIELDS-{'policy','kind','issued_at','expires_at'}|{
    'reviewer_uid','reviewer_key_id','reviewed_at','target_scope','source_context',
    'public_payload_sha256','source_sha256','finding_receipt_sha256','actor_inputs_sha256','review_timezone'}


def _fact(v):
    require(type(v) is dict and set(v)=={'value','assessment','evidence'},'Authority fact shape differs.')
    require(type(v['evidence']) is list,'Authority fact evidence list required.')
    return Fact(v['value'],v['assessment'],tuple(v['evidence']))


def _day(v):
    require(type(v) is str,'Canonical authority date required.')
    d=date.fromisoformat(v);require(d.isoformat()==v,'Canonical authority date required.');return d


def _assessment(v):
    require(type(v) is dict and set(v)==set(AuthorityAssessment.__dataclass_fields__),
        'Authority assessment schema differs.')
    p=deepcopy(v)
    for k in ('identity','date_semantics','coverage'):p[k]=_fact(p[k])
    states=[]
    require(type(p['states']) is list and len(p['states'])<=4096,'Bounded actor assessment list required.')
    for item in p['states']:
        require(type(item) is dict and set(item)=={'state_id','state'},'State assessment shape differs.')
        state=deepcopy(item['state']);state['on']=_day(state['on'])
        for k in ('identity','rank','role','active','scope'):state[k]=_fact(state[k])
        states.append(StateAssessment(item['state_id'],ActorState(**state)))
    p['states']=tuple(states)
    for name,cls in (('rules',Rule),('delegations',Delegation)):
        values=[];require(type(p[name]) is list and len(p[name])<=256,'Bounded authority instrument list required.')
        for item in p[name]:
            row=deepcopy(item)
            for key in ('start','end','issued_on','revoked_from'):
                if key in row and row[key] is not None:row[key]=_day(row[key])
            for key in ('powers','ranks','roles','actor_scopes','target_scopes','evidence'):
                if key in row:
                    require(type(row[key]) is list,'Authority instrument labels must be lists.')
                    row[key]=tuple(row[key])
            values.append(cls(**row))
        p[name]=tuple(values)
    p['evidence_digests']=tuple(tuple(x) for x in p['evidence_digests'])
    return AuthorityAssessment(**p)


def review_request(snapshot,journal,*,finding_id,target_entry_sha256,operation_id,reviewer_uid,
        reviewer_key_id,decision,reason,evidence_references,reviewed_at,target_scope,finding_receipt_sha256):
    """Build exact action metadata for an independent trusted assessment workflow."""
    for uid in (finding_id,operation_id,reviewer_uid):F._uuid(uid)
    F._sha(target_entry_sha256);F._sha(finding_receipt_sha256);F._text(reason);F._text(target_scope)
    require(decision in F.DECISIONS,'Supported reported review decision required.')
    require(type(evidence_references) is list and all(type(x) is str and x.strip() for x in evidence_references),
        'Explicit review evidence references required.')
    when=F._time(reviewed_at)
    require(datetime.fromisoformat(reviewed_at).utcoffset()==timedelta(0),'UTC review time required.')
    return dict(ledger_id=journal.ledger_id,officer_uid=journal.officer_uid,finding_id=finding_id,
        target_entry_sha256=target_entry_sha256,operation_id=operation_id,reviewer_uid=reviewer_uid,
        reviewer_key_id=reviewer_key_id,decision=decision,reason=reason,evidence_references=deepcopy(evidence_references),
        reviewed_at=reviewed_at,review_timezone=REVIEW_TIMEZONE,target_scope=target_scope,source_context=deepcopy(snapshot['context']),
        public_payload_sha256=digest(snapshot['public']),source_sha256=C._source(snapshot),finding_receipt_sha256=finding_receipt_sha256,actor_inputs_sha256=_actor_inputs(snapshot))


def _review_day(instant):
    return instant.astimezone(ZoneInfo(REVIEW_TIMEZONE)).date()


def _action(request):
    require(type(request) is dict and set(request)==REQUEST_FIELDS,'Exact review request schema required.')
    for key in ('ledger_id','officer_uid','finding_id','operation_id','reviewer_uid'):F._uuid(request[key])
    for key in ('target_entry_sha256','public_payload_sha256','source_sha256','finding_receipt_sha256','actor_inputs_sha256'):F._sha(request[key])
    F._text(request['reviewer_key_id']);F._text(request['target_scope']);F._text(request['reason'])
    require(request['decision'] in F.DECISIONS and request['review_timezone']==REVIEW_TIMEZONE,'Supported review action and date semantics required.')
    when=F._time(request['reviewed_at']);require(datetime.fromisoformat(request['reviewed_at']).utcoffset()==timedelta(0),'UTC review time required.')
    require(type(request['evidence_references']) is list and
        all(type(x) is str and x.strip() for x in request['evidence_references']),'Review references differ.')
    return ActionReview('REVIEW_FINDING:'+request['decision'],'CANNOT_VERIFY',(),digest(request),
        (request['reviewer_uid'],),_review_day(when).isoformat(),_review_day(when).isoformat(),
        J.canonical(request),request['target_entry_sha256'])


def _actor_inputs(snapshot):
    return digest(json_value(dict(manifest=snapshot['manifest'],captured_at=snapshot['captured_at'])))


def _history(snapshot):
    return ActorHistory(subject_index(snapshot['manifest'],snapshot['catalog']),
        snapshot['bindings']['raw_bindings'],snapshot['captured_at'],digest(snapshot['public']))


def _evidence(packet,membership,evidence,request):
    require(type(evidence) is dict and 0<len(evidence)<=128,'Bounded assessment evidence bytes required.')
    fingerprints={};total=0
    for ref,encoded in evidence.items():
        F._text(ref);require(type(encoded) is str and len(encoded)<=1400000,'Bounded evidence encoding required.')
        data=base64.b64decode(encoded,validate=True);total+=len(data)
        require(data and total<=8*1024*1024,'Bounded nonempty authority evidence required.')
        fingerprints[ref]=hashlib.sha256(data).hexdigest()
    require(fingerprints==dict(packet.evidence_digests),'Authority evidence bytes or inventory differs.')
    require(membership.assessment=='ASSESSED' and membership.value is True and
        membership.evidence and set(membership.evidence)<=set(fingerprints),
        'Assessed finding-subject target-scope membership required.')
    require(set(request['evidence_references'])<=set(fingerprints),'Review cites absent authority evidence.')


def _bound_packet(request,packet):
    action=_action(request)
    require(packet.actor_uid==request['reviewer_uid'] and packet.target_scope==request['target_scope'] and
        packet.public_payload_sha256==request['public_payload_sha256'] and
        packet.original_action_digest==digest(json_value(asdict(action))) and
        packet.destination_digest==request['target_entry_sha256'],'Authority assessment names different review action.')
    return action


def issue_authority_assessment(snapshot,journal,*,request,assessment,target_membership,evidence,
        signer,key_id,expires_at):
    """Trusted assessment signer only; caller must verify instruments and custody.

    A signature authenticates the configured assessor's statement, not police law.
    The signer must independently assess state facts, governing instruments,
    resolved memberships and coverage before calling this helper.
    """
    journal._authority_config();require(key_id in journal.authority_keys and
        request['target_scope'] in journal.authority_scopes[key_id],'Assessment signer scope differs.')
    J._recorder(signer,key_id,journal.authority_keys,journal.crypto,journal.backup)
    request=deepcopy(request);_bound_packet(request,assessment)
    encoded={k:base64.b64encode(v).decode() for k,v in evidence.items()}
    _evidence(assessment,target_membership,encoded,request)
    result=ActionAuthority(_history(snapshot)).review(_action(request),assessment)
    reviewed=F._time(request['reviewed_at']);issued=J._now().astimezone(timezone.utc);expiry=F._time(expires_at)
    require(reviewed<=issued<expiry<=reviewed+timedelta(seconds=600) and _review_day(issued)==_review_day(reviewed),
        'Contemporaneous actual assessment issuance and bounded review window required.')
    require(request['source_context']==snapshot['context'] and request['source_sha256']==C._source(snapshot) and
        request['public_payload_sha256']==digest(snapshot['public']) and request['actor_inputs_sha256']==_actor_inputs(snapshot),'Assessment source differs.')
    value=dict(policy=ASSESSMENT_POLICY,kind='REVIEW_AUTHORITY',request=request,
        assessment=json_value(asdict(assessment)),target_membership=json_value(asdict(target_membership)),
        evidence=encoded,actor_state_links=result['actor_state_links'],issued_at=issued.isoformat(),expires_at=expires_at)
    # INVALID and CANNOT_VERIFY assessments may be signed for investigation, but
    # the review-intent issuer and recorder will never accept them as permission.
    return J._sign(value,signer,key_id,ASSESSMENT_POLICY)


def validate_stored_authority(review,reviewer_key_id,journal,*,building=False):
    """Replay signed authority and embedded evidence without refreshing old expiry."""
    journal._authority_config()
    require(journal.reviewer_identities.get(reviewer_key_id)==review['reviewer_uid'],
        'Review signing key is not bound to that officer.')
    receipt=review['authority'];proof=J._verify(receipt,journal.authority_keys,ASSESSMENT_FIELDS,
        'REVIEW_AUTHORITY',ASSESSMENT_POLICY)
    request=proof['request'];_action(request)
    require(request['target_scope'] in journal.authority_scopes[receipt['key_id']],
        'Assessment signer cannot attest that target scope.')
    require(request['reviewer_key_id']==reviewer_key_id and
        all(request[k]==review[k] for k in F.REVIEW_FIELDS-{'policy','kind','issued_at','expires_at'}) and
        all(request[k]==review[k] for k in ('reviewer_uid','reviewed_at','target_scope','review_timezone')),
        'Assessment belongs to a different signed review.')
    require(review['issued_at']==proof['issued_at'] and review['expires_at']==proof['expires_at'] and
        F._time(review['reviewed_at'])<=F._time(review['issued_at'])<F._time(review['expires_at'])<=
        F._time(review['reviewed_at'])+timedelta(seconds=600) and
        _review_day(F._time(review['issued_at']))==_review_day(F._time(review['reviewed_at'])),
        'Review and authority authorization windows differ.')
    packet=_assessment(proof['assessment']);_bound_packet(request,packet)
    _evidence(packet,_fact(proof['target_membership']),proof['evidence'],request)
    links=proof['actor_state_links'];require(type(links) is list and len(links)<=4096,'Bounded actor links required.')
    seen=set()
    for link in links:
        require(type(link) is dict and set(link)=={'officer_uid','on','state_id','assessment_supplied'},
            'Reconstruction link shape differs.')
        F._uuid(link['officer_uid']);_day(link['on']);F._sha(link['state_id'])
        key=(link['officer_uid'],link['on']);require(key not in seen,'Duplicate actor reconstruction link.')
        seen.add(key)
    indexed={(l['officer_uid'],l['on']):l for l in links}
    for s in packet.states:
        link=indexed.get((s.state.actor_uid,s.state.on.isoformat()))
        require(link is not None and link['assessment_supplied'] is True and link['state_id']==s.state_id,
            'Assessed actor state differs from retained reconstruction link.')
    action=Action(request['reviewer_uid'],_review_day(F._time(request['reviewed_at'])),
        'REVIEW_FINDING:'+request['decision'],request['target_scope'],packet.identity,packet.date_semantics,
        (_action(request).source_reference,))
    decision=evaluate(action,tuple(s.state for s in packet.states),packet.rules,packet.delegations,coverage=packet.coverage)
    require(decision.status=='VALID','Review authority is not VALID; no review may be recorded.')
    if not building:
        require(review['authority_decision']==json_value(asdict(decision)),'Retained review authority explanation differs.')
    return proof,packet,decision


def issue_authorized_review_intent(journal,*,authority,signer,key_id):
    """Trusted reviewer signer; signed packet is frozen into the review record."""
    proof=J._verify(authority,journal.authority_keys,ASSESSMENT_FIELDS,'REVIEW_AUTHORITY',ASSESSMENT_POLICY)
    request=proof['request']
    value={k:deepcopy(request[k]) for k in F.REVIEW_FIELDS-{'policy','kind','issued_at','expires_at'}}
    value.update(policy=F.AUTHORIZED_REVIEW_POLICY,kind='REVIEW',reviewer_uid=request['reviewer_uid'],
        reviewed_at=request['reviewed_at'],review_timezone=REVIEW_TIMEZONE,target_scope=request['target_scope'],authority=deepcopy(authority),
        issued_at=proof['issued_at'],expires_at=proof['expires_at'])
    J._recorder(signer,key_id,journal.reviewer_keys,journal.crypto,journal.backup)
    _,_,decision=validate_stored_authority(value,key_id,journal,building=True)
    value['authority_decision']=json_value(asdict(decision))
    now=J._now().astimezone(timezone.utc)
    require(F._time(value['issued_at'])<=now<=F._time(value['expires_at']) and
        _review_day(now)==_review_day(F._time(value['reviewed_at'])),'Review signature requires a current authority window.')
    return J._sign(value,signer,key_id,F.AUTHORIZED_REVIEW_POLICY)


def record_review(args,repo,revision,findings,*,intent,expected_authority_sha256,finding_receipt_path):
    """Operational entry: mTLS witness, fresh readiness and full original replay."""
    require(type(findings) is W.WitnessedFindingsRegistry and findings.fixture_transport is False,
        'Operational findings mutual-TLS witness required.')
    findings._config()
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot=load_verified_snapshot(args,repo,revision)
    return record_loaded_review(snapshot,repo,findings,intent=intent,expected_authority_sha256=expected_authority_sha256,finding_receipt_path=finding_receipt_path)


def record_loaded_review(snapshot,repo,findings,*,intent,expected_authority_sha256,finding_receipt_path):
    """Internal trusted full-loader boundary; no user-supplied snapshot/configuration."""
    require(type(findings) is W.WitnessedFindingsRegistry,'Configured findings witness required.')
    journal=findings.registry.journal;require(journal.repo==Path(repo).expanduser().resolve(),'Review repository differs.')
    intent=deepcopy(intent);F._sha(expected_authority_sha256)
    value=journal._review(intent)
    require(value['policy']==F.AUTHORIZED_REVIEW_POLICY and digest(value['authority'])==expected_authority_sha256,
        'Exact independently approved authority packet pin required.')
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    source_sha=C._source(snapshot);actor_inputs_sha=_actor_inputs(snapshot);context=deepcopy(snapshot['context']);public_sha=digest(snapshot['public'])
    pins=deepcopy(findings.registry.key_pins);scope=deepcopy(findings.scope)
    def verify():
        permit.check(snapshot);findings._config()
        require(C._source(snapshot)==source_sha and snapshot['context']==context and digest(snapshot['public'])==public_sha and
            findings.registry.key_pins==pins and findings.scope==scope and _actor_inputs(snapshot)==actor_inputs_sha,'Review evidence or trust configuration changed.')
        proof,packet,decision=validate_stored_authority(value,intent['key_id'],journal)
        request=proof['request']
        require(request['source_context']==context and request['source_sha256']==source_sha and
            request['public_payload_sha256']==public_sha and request['actor_inputs_sha256']==actor_inputs_sha,'Review assessment differs from original replay.')
        result=ActionAuthority(_history(snapshot)).review(_action(request),packet)
        require(result['status']=='VALID' and result['actor_state_links']==proof['actor_state_links'] and
            tuple(result['successful_paths'])==decision.successful_paths,
            'Review actor histories or authority evaluation differ.')
        permit.check(snapshot)
    verify();selected=findings.select()
    request=value['authority']['payload']['request']
    require(value['ledger_id']==journal.ledger_id and value['officer_uid']==journal.officer_uid,
        'Review names a different findings ledger.')
    matches=[e for e in selected['entries'] if e['entry']['operation_id']==value['operation_id']]
    if matches:
        require(len(matches)==1 and matches[0]['entry']['kind']=='REVIEW' and matches[0]['entry']['review']==intent,
            'Review retry content differs.')
        verify();return dict(policy=POLICY,status='ALREADY_REVIEWED',accepted_state=None,findings_anchored=False)
    heads=[e for e in selected['entries'] if e['entry']['finding_id']==value['finding_id'] and
        e['entry']['kind'] in ('FINDING','CORRECTION')]
    require(heads and heads[-1]['entry_sha256']==value['target_entry_sha256'],
        'Review must target the exact current finding head.')
    head=heads[-1]['entry'];finding=head['finding']
    require(head['receipt_sha256']==request['finding_receipt_sha256'],'Assessment names different finding receipt bytes.')
    def receipt_check():
        sha,result=F.read_comparison_receipt(finding_receipt_path,repo,journal.crypto,journal.backup,journal.officer_uid)
        envelope=F._json(Path(finding_receipt_path).read_bytes());binding=envelope['binding']
        original=deepcopy(binding['source_context']);current=deepcopy(context)
        original.pop('code_revision',None);current.pop('code_revision',None)
        require(sha==request['finding_receipt_sha256'] and result==finding and original==current and
            binding['original_publication_sha256']==public_sha,
            'Reviewed finding receipt differs from original verified evidence publication.')
    receipt_check()
    def before_publish():
        verify();receipt_check();now=J._now().astimezone(timezone.utc)
        require(F._time(value['issued_at'])<=now<=F._time(value['expires_at']) and
            _review_day(now)==_review_day(F._time(value['reviewed_at'])),'Review is expired, future-dated or backdated.')
        require(findings._head()==selected['registry_tip'],'Findings witness advanced before review publication.')
    before_publish()
    findings.append_review(intent=intent,before_publish=before_publish)
    verify()
    return dict(policy=POLICY,status='REVIEWED',accepted_state=None,findings_anchored=False)
