"""UI request -> actual protected temporal review with invented assessment fixtures.

The production review entry is substituted only to exercise the existing loaded
runner with a disposable in-process witness. No operational waiver is shipped.
"""
from copy import deepcopy
from datetime import date
from dataclasses import replace
from hashlib import sha256
import time
import pytest
from app.access import research_bridge as B
from app.access.research_service import ResearchService
from app.identity import temporal_findings_review as M
from app.identity.protected_commitment import digest
from research_workspace_fixture import initialize,presentation,disclosure,sign,review_body,identifier,PASSWORD
from scoped_access_fixture import catalog
from test_temporal_findings_review import (
    authorized,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys,
    request,authority,intent,inventory,packet,REF)

def web_authority(t,r):
    head=r['target_entry_sha256'];data=(t['j'].root/'entry-00000001.encrypted.json').read_bytes()
    assert sha256(data).hexdigest()==head
    assessed=packet(t,r)
    assessed=replace(assessed,evidence_digests=(*assessed.evidence_digests,(head,head)))
    return authority(t,r,assessed,evidence={REF:b'fixture-assessed-evidence',head:data})

def connect(t,tmp_path):
    now=int(time.time())+2;s,k,_=initialize(tmp_path/'web-review',clock=lambda:now)
    public=digest(t['s']['snapshot']['public']);directory=catalog(k,now=now,generation=2);directory['payload']['source_public_sha256']=public
    from scoped_access_fixture import sign as access_sign
    s.access.put_directory(access_sign(k,directory['payload']))
    p=presentation(k,now=now,generation=2);p['payload']['source_public_sha256']=public
    f=p['payload']['findings'][0];f['finding_id']=t['first']['finding_id'] if 'finding_id' in t['first'] else __import__('test_temporal_findings_review').ID
    f['head_sha256']=t['first']['journal_tip']['entry_sha256'];f['versions'][0]['entry_sha256']=f['head_sha256']
    s.import_packet(sign(k,p['payload']))
    g=disclosure(k,now=now+1);g['payload']['issued_at']=now;g['payload']['source_public_sha256']=public;s.import_grant(sign(k,g['payload']))
    token,csrf=s.access.login('station.one',PASSWORD,'fixture-bridge')
    body=review_body(generation=2,finding_id=f['finding_id'],target_head_sha256=f['head_sha256'],evidence_references=[f['head_sha256']])
    result=ResearchService(s).request_review(token,csrf,body);assert result['status']=='PENDING_AUTHORITY'
    return s,body

def test_requested_review_authenticates_actor_authority_and_retains_result(authorized,tmp_path,monkeypatch):
    t=authorized;s,body=connect(t,tmp_path)
    r=request(t,operation_id=body['operation_id'],decision=body['decision'],reason=body['reason'],evidence_references=body['evidence_references'])
    signed_intent=intent(t,web_authority(t,r));calls=[]
    def fixture_entry(args,repo,revision,findings,**kw):
        calls.append(kw);return M.record_loaded_review(t['s']['snapshot'],repo,findings,**kw)
    monkeypatch.setattr(M,'record_review',fixture_entry)
    result=B.record_requested_review(s,body['operation_id'],None,t['s']['repo'],'fixture-revision',t['d']['adapter'],
        intent=signed_intent,expected_authority_sha256=digest(signed_intent['payload']['authority']),finding_receipt_path=t['d']['t']['d']['output'])
    assert result['status']=='REVIEW_RECORDED' and len(calls)==1
    assert t['d']['adapter'].select()['entries'][-1]['entry']['review']==signed_intent
    before=inventory(t['d'])
    B.record_requested_review(s,body['operation_id'],None,t['s']['repo'],'fixture-revision',t['d']['adapter'],
        intent=signed_intent,expected_authority_sha256=digest(signed_intent['payload']['authority']),finding_receipt_path=t['d']['t']['d']['output'])
    assert inventory(t['d'])==before
    summaries,assessments=B._findings(t['s']['snapshot'],t['d']['adapter'].select()['entries'],t['j'])
    assert [v['kind'] for v in summaries[0]['versions']]==['FINDING','REVIEW']
    assert assessments[0]['status']=='VALID' and assessments[0]['assessment_receipt_sha256']==digest(signed_intent['payload']['authority'])
    assert summaries[0]['head_sha256']==t['first']['journal_tip']['entry_sha256']
    assert summaries[0]['versions'][-1]['supersedes'] is None

@pytest.mark.parametrize('change',['reason','source','actor'])
def test_request_binding_cannot_replace_review_intent(authorized,tmp_path,monkeypatch,change):
    t=authorized;s,body=connect(t,tmp_path)
    changes={}
    if change=='reason':changes['reason']='Different independently signed intent.'
    if change=='actor':
        # Mutation cannot be made valid by a browser; reject signature/actor
        # binding at the journal boundary before the protected runner.
        i=intent(t);i['payload']['reviewer_uid']=identifier(999)
    else:
        r=request(t,operation_id=body['operation_id'],decision=body['decision'],reason=changes.get('reason',body['reason']),evidence_references=body['evidence_references'])
        i=intent(t,web_authority(t,r))
    if change=='source':
        # An unsigned source change fails the journal intent verification.
        i['payload']['authority']['payload']['request']['public_payload_sha256']='f'*64
    monkeypatch.setattr(M,'record_review',lambda *a,**kw:pytest.fail('Unmatched intent reached protected recorder'))
    with pytest.raises(Exception):B.record_requested_review(s,body['operation_id'],None,t['s']['repo'],'revision',t['d']['adapter'],intent=i,
        expected_authority_sha256=digest(i['payload']['authority']),finding_receipt_path=t['d']['t']['d']['output'])

def test_requested_correction_calls_protected_capture_and_keeps_original(authorized,tmp_path,monkeypatch):
    from app.identity import protected_findings_capture as C
    import app.identity.algorithm_snapshot as S
    from test_protected_contradiction_runner import next_checkpoint
    t=authorized;s,body=connect(t,tmp_path);operation=identifier(302)
    record=s.get_request(body['operation_id'])['request'];record.update(kind='CORRECTION',operation_id=operation)
    s.append_request(record)
    recording=t['d']['t']['d']['t'];pin=next_checkpoint(recording)
    recording['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    monkeypatch.setattr(S,'load_verified_snapshot',lambda *args:t['s']['snapshot'])
    calls=[]
    def fixture_capture(args,repo,revision,r,f,**kwargs):
        calls.append(kwargs);return C.capture_loaded(t['s']['snapshot'],repo,r,f,**kwargs)
    monkeypatch.setattr(C,'capture_contradictions',fixture_capture)
    # Witness/checkpoint heads advance; original encrypted journal entries must
    # keep their exact bytes when a correction is appended.
    before={p:p.read_bytes() for p in t['j'].root.glob('entry-*.encrypted.json')}
    assert before
    destination=tmp_path/'correction-output';destination.mkdir(mode=0o700)
    result=B.capture_requested_correction(s,operation,None,t['s']['repo'],'fixture-revision',recording['adapter'],t['d']['adapter'],
        effective_on=date(2024,12,31),known_at=t['s']['clock'][0],destination=destination/'intent.encrypted.json')
    assert result['status']=='CORRECTION_RECORDED' and len(calls)==1
    assert all(path.read_bytes()==data for path,data in before.items())
    selected=t['d']['adapter'].select();assert selected['entries'][-1]['entry']['kind']=='CORRECTION'
