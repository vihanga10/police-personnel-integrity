import json
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import os
import sqlite3
import time
import pytest
from app.access.research_app import create_app, configured
from app.access.research_store import ResearchStore
from app.access.research_service import ResearchService
from app.access import research_policy as P
from app.access.policy import AccessError
from research_workspace_fixture import initialize,presentation,disclosure,sign,review_body,identifier,PASSWORD
from scoped_access_fixture import grant as account_grant
from test_scoped_access_api import Client

@pytest.fixture(scope='module')
def environment(tmp_path_factory):
    root=tmp_path_factory.mktemp('research-web');clock=[time.time()]
    s,k,config=initialize(root,clock=lambda:clock[0]);c=Client(create_app(s,origin='https://access.test:9443'));c.login()
    return s,k,c,root,clock

def query_body(s,at=None):
    p=s.get_packet(identifier(1));return dict(officer_uid=identifier(1),effective_on='2024-12-31',known_at=at or p['history']['coverage_end'])

def test_workspace_semantics_and_no_whole_personal_rows(environment):
    s,k,c,*_=environment;status,headers,b=c.request('/api/research/officers/'+identifier(1))
    assert status==200 and b['evidence_view']=='SIGNED_OBSERVED_COPY'
    assert b['accepted_state'] is None and b['fresh_live_verification'] is False and b['public_finality_verified'] is False
    assert b['coverage_semantics']=='JOURNAL_OBSERVATIONS_ONLY'
    assert ('content-security-policy',"default-src 'none'; frame-ancestors 'none'") in headers
    assert 'history' not in b and 'actor_uid' not in json.dumps(b)

@pytest.mark.parametrize('officer',[identifier(2),identifier(5),identifier(999)])
def test_direct_api_out_of_scope_precedes_presentation_lookup(environment,officer,monkeypatch):
    s,k,c,*_=environment
    monkeypatch.setattr(s,'get_packet',lambda _:pytest.fail('Sensitive packet lookup before scope check'))
    assert c.request('/api/research/officers/'+officer)[0]==404
    assert c.request('/api/research/history','POST',{**query_body_without_store(),'officer_uid':officer})[0]==404

def query_body_without_store():return dict(officer_uid=identifier(1),effective_on='2024-12-31',known_at='2026-10-11T00:00:00+00:00')

def test_actual_algorithms_correction_boundary_and_earlier_digest(environment):
    s,k,c,*_=environment;p=s.get_packet(identifier(1));start=p['history']['coverage_start'];later=p['history']['versions'][-1]['recorded_at']
    early=c.request('/api/research/history','POST',query_body(s,start));after=c.request('/api/research/history','POST',query_body(s,later))
    assert early[0]==after[0]==200
    assert early[2]['comparisons'][0]['status']=='REPORTED_CONTRADICTION_CANDIDATE'
    assert after[2]['comparisons'][0]['status']=='REPORTED_AGREEMENT'
    assert early[2]['query_digest']!=after[2]['query_digest']
    assert c.request('/api/research/history','POST',query_body(s,start))[2]['query_digest']==early[2]['query_digest']
    assert all(not p['accepted_contradiction'] for p in after[2]['comparisons'])
    assert 'source_reference' not in json.dumps(early[2]) and 'source_key' not in json.dumps(early[2])

@pytest.mark.parametrize('at',['1900-01-01T00:00:00Z','2999-01-01T00:00:00Z'])
def test_no_invented_coverage(environment,at):
    s,k,c,*_=environment;assert c.request('/api/research/history','POST',query_body(s,at))[0]==422

@pytest.mark.parametrize('change',[{'known_at':'2024-12-31T12:00:00'},{'effective_on':'2024-02-30'},{'effective_on':'20241231'}, {'role':'IGP'}, {'snapshot':{}}, {'classification':'ORDINARY'}])
def test_http_inputs_never_supply_trust(environment,change):
    s,k,c,*_=environment;assert c.request('/api/research/history','POST',{**query_body(s),**change})[0]==400

@pytest.mark.parametrize('csrf',['','forged'])
def test_csrf_blocks_query_and_review(environment,csrf):
    s,k,c,*_=environment
    assert c.request('/api/research/history','POST',query_body(s),csrf=csrf)[0]==403
    assert c.request('/api/research/requests','POST',review_body(),csrf=csrf)[0]==403

@pytest.mark.parametrize('assignment,classification,clearance,expected',[
    ('UNRESOLVED','ORDINARY',False,403),('ORDINARY','UNASSESSED',True,403),
    ('CID_CCIB','ORDINARY',False,403),('ORDINARY','CID_CCIB_RESTRICTED',False,403),
    ('CID_CCIB','CID_CCIB_RESTRICTED',True,200),('ORDINARY','ORDINARY',False,200)])
def test_disclosure_boundary_is_independent_of_role(tmp_path,assignment,classification,clearance,expected):
    s,k,_=initialize(tmp_path);g=disclosure(k,assignment=assignment,classification=classification,clearance=clearance)
    s.clock=lambda:g['payload']['issued_at']+1
    with s.transaction() as db:db.execute('DELETE FROM disclosures')
    s.import_grant(g);t,csrf=s.access.login('station.one',PASSWORD,'fixture')
    c=Client(create_app(s,origin='https://access.test:9443'));c.cookie='__Host-ppi-session='+t;c.csrf=csrf
    assert c.request('/api/officers/'+identifier(1))[0]==200
    assert c.request('/api/research/officers/'+identifier(1))[0]==expected

def test_review_request_exact_retry_append_only_and_conflict(environment):
    s,k,c,*_=environment;b=review_body()
    first=c.request('/api/research/requests','POST',b)
    assert first[0]==200 and first[2]['status']=='PENDING_AUTHORITY' and not first[2]['decision_recorded'] and not first[2]['chain_submitted']
    before=s.path.read_bytes();again=c.request('/api/research/requests','POST',b)
    assert again[2]==first[2] and s.path.read_bytes()==before
    assert c.request('/api/research/requests','POST',{**b,'reason':'A changed reason.'})[0]==409
    assert c.request('/api/research/requests/'+b['operation_id'])[2]==first[2]
    raw=s.path.read_bytes();assert b['reason'].encode() not in raw and identifier(1).encode() not in raw
    with sqlite3.connect(s.path) as db:
        with pytest.raises(sqlite3.IntegrityError):db.execute('DELETE FROM requests')
        with pytest.raises(sqlite3.IntegrityError):db.execute('UPDATE events SET digest=?',('0'*64,))

@pytest.mark.parametrize('change,expected',[
    ({'target_head_sha256':'f'*64},409),({'generation':2},409),({'decision':'ACCEPT_TRUE'},400),
    ({'evidence_references':['f'*64]},400),({'reviewer_uid':identifier(2)},400),
    ({'reason':'x'*1201},400),({'evidence_references':['b'*64,'b'*64]},400),({'kind':'SUBMIT_CHAIN'},400)])
def test_review_schema_head_and_evidence_pins(environment,change,expected):
    s,k,c,*_=environment
    assert c.request('/api/research/requests','POST',{**review_body(operation_id=identifier(302)),**change})[0]==expected

def test_correction_request_preserves_original_evidence_and_no_automatic_run(environment):
    s,k,c,*_=environment;before=s.get_packet(identifier(1))
    result=c.request('/api/research/requests','POST',review_body(operation_id=identifier(303),kind='CORRECTION'))
    assert result[0]==200 and result[2]['status']=='PENDING_AUTHORITY'
    assert s.get_packet(identifier(1))==before

def test_expiry_signature_scope_and_source_fail_closed(tmp_path):
    clock=[time.time()];s,k,_=initialize(tmp_path,clock=lambda:clock[0]);t,csrf=s.access.login('station.one',PASSWORD,'fixture')
    service=ResearchService(s);s.import_packet(presentation(k,generation=2))
    clock[0]+=1801
    t,csrf=s.access.login('station.one',PASSWORD,'fixture-new-session')
    with pytest.raises(AccessError,match='DETAILS_WITHHELD'):service.workspace(t,identifier(1))
    for mutation in ('signature','officer','policy','history-gap','unknown-field'):
        p=presentation(k,now=clock[0]);v=p['payload']
        if mutation=='signature':p['signature']='A'*88
        if mutation=='officer':v['history']['versions'][0]['claim']['officer_uid']=identifier(2)
        if mutation=='policy':v['policy']='OTHER_DOMAIN'
        if mutation=='history-gap':v['history']['versions'][-1]['supersedes']='missing'
        if mutation=='unknown-field':v['nic']='LEAK'
        if mutation!='signature':p=sign(k,v)
        with pytest.raises(Exception):s.import_packet(p)

def test_monotone_import_and_encrypted_restart(tmp_path):
    s,k,cfg=initialize(tmp_path);before=s.path.read_bytes()
    altered=presentation(k,generation=1);altered['payload']['findings'][0]['versions'][0]['reason']='Different same-generation content.'
    with pytest.raises(ValueError):s.import_packet(sign(k,altered['payload']))
    s.import_packet(presentation(k,generation=2));s.append_request({**review_body(), 'user_id':identifier(100),'account_version':1,'reviewer_uid':identifier(1),'source_public_sha256':'a'*64})
    reopened=ResearchStore(s.root,tmp_path/'workspace.key',s.keys,access=s.access)
    assert reopened.get_packet(identifier(1))['generation']==2
    assert reopened.get_request(identifier(301))['status']=='PENDING_AUTHORITY'

def test_private_configuration_and_separate_key(tmp_path):
    s,k,cfg=initialize(tmp_path)
    store,origin=configured(cfg);assert store.get_packet(identifier(1))['generation']==1
    with pytest.raises(ValueError):ResearchStore(s.root,s.access.key_path,s.keys,access=s.access)
    cfg.chmod(0o644)
    with pytest.raises(ValueError):configured(cfg)

def test_query_rechecks_revocation_before_return(tmp_path,monkeypatch):
    s,k,_=initialize(tmp_path);t,csrf=s.access.login('station.one',PASSWORD,'fixture')
    import app.access.research_service as R
    original=R.compare_history
    def revoke(*args,**kwargs):
        result=original(*args,**kwargs);s.access.put_account(account_grant(k,version=2,active=False));return result
    monkeypatch.setattr(R,'compare_history',revoke)
    with pytest.raises(AccessError):ResearchService(s).history(t,csrf,identifier(1),'2024-12-31',s.get_packet(identifier(1))['history']['coverage_end'])

def test_empty_findings_do_not_imply_no_contradiction(tmp_path):
    s,k,_=initialize(tmp_path);p=presentation(k,generation=2);p['payload']['findings']=[];s.import_packet(sign(k,p['payload']))
    t,csrf=s.access.login('station.one',PASSWORD,'fixture');assert ResearchService(s).workspace(t,identifier(1))['findings']==[]

def test_no_web_execution_or_approval_route(environment):
    s,k,c,*_=environment
    for path in ('/api/research/execute','/api/research/approve','/api/research/anchor','/api/research/import','/api/admin/keys'):
        assert c.request(path,'POST',{})[0]==404

def test_reported_provenance_is_bounded_and_never_discloses_whole_source_rows(environment):
    s,k,c,*_=environment
    result=c.request('/api/research/history','POST',query_body(s,s.get_packet(identifier(1))['history']['coverage_start']))
    assert result[0]==200
    claims=[v['claim'] for v in result[2]['versions']]
    assert {v['reported_dataset'] for v in claims}=={'promotion_history.csv','transfer_history.csv'}
    assert all(len(v['provenance_sha256'])==64 and not v['source_independence_verified'] for v in claims)
    assert result[2]['comparisons'][0]['evidence']
    assert all('original' not in v and 'source_reference' not in v for v in claims)

@pytest.mark.parametrize('filename',['/private/other-person.csv','<img src=x>','unknown.csv',None])
def test_unknown_provenance_filename_is_withheld(filename):
    from app.identity.historical_reconstruction import Claim
    claim=Claim('reported-id',identifier(1),'rank',json.dumps({'to_rank':'SP','other_officer_nic':'private'}),
        json.dumps({'filename':filename,'original':{'values':['private-linked-person']}}),'a'*64)
    projection=P.claim_projection(claim)
    assert projection['reported_dataset'] is None and len(projection['provenance_sha256'])==64
    assert 'private' not in json.dumps(projection) and projection['fields']=={'to_rank':'SP'}

def test_current_hr_posting_and_demoted_floor_remain_visible_as_reported_fields():
    from app.identity.historical_reconstruction import Claim
    posting=Claim('posting',identifier(1),'posting',json.dumps({'current_station':'Reported station',
        'current_station_code':'S1','current_unit_name':'Reported Crime Branch','other_person_name':'private'}),
        json.dumps({'filename':'officer_service_information.csv'}),'a'*64)
    assert P.claim_projection(posting)['fields']=={'current_station':'Reported station','current_station_code':'S1','current_unit_name':'Reported Crime Branch'}
    floor=Claim('floor',identifier(1),'rank',json.dumps({'floor_rank':'Reported floor'}),'{}','a'*64)
    assert P.claim_projection(floor)['fields']=={'floor_rank':'Reported floor'}

def test_read_only_disclosure_forbids_review_even_for_an_in_scope_officer(tmp_path):
    s,k,_=initialize(tmp_path);g=disclosure(k,now=int(s.clock())+2,reviews=False)
    g['payload']['issued_at']=int(s.clock());s.import_grant(sign(k,g['payload']))
    token,csrf=s.access.login('station.one',PASSWORD,'fixture')
    service=ResearchService(s)
    assert not service.workspace(token,identifier(1))['can_request_review']
    with pytest.raises(AccessError,match='REVIEW_REQUEST_FORBIDDEN'):service.request_review(token,csrf,review_body())

def test_recent_requests_recover_current_actors_queue_without_private_narrative(tmp_path):
    s,k,_=initialize(tmp_path);token,csrf=s.access.login('station.one',PASSWORD,'fixture');service=ResearchService(s)
    first=service.request_review(token,csrf,review_body());records=service.recent_requests(token,identifier(1))
    assert records['items']==[first] and records['limit']==20
    assert 'Invented fixture review needs evidence.' not in json.dumps(records)
    assert 'reviewer_uid' not in json.dumps(records)
    for officer in (identifier(5),identifier(999)):
        with pytest.raises(AccessError):service.recent_requests(token,officer)

@pytest.mark.parametrize('change',['other-user','other-officer','old-version','other-source'])
def test_recent_request_list_cannot_leak_other_contexts(tmp_path,change):
    s,k,_=initialize(tmp_path);token,csrf=s.access.login('station.one',PASSWORD,'fixture')
    request={**review_body(),'user_id':identifier(100),'account_version':1,'reviewer_uid':identifier(1),'source_public_sha256':'a'*64}
    if change=='other-user':request['user_id']=identifier(999)
    if change=='other-officer':request['officer_uid']=identifier(5)
    if change=='old-version':request['account_version']=2
    if change=='other-source':request['source_public_sha256']='f'*64
    s.append_request(request)
    assert ResearchService(s).recent_requests(token,identifier(1))['items']==[]
