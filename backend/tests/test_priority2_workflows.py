"""End-to-end generated assessment fixtures, not independent police ground truth."""
from copy import deepcopy
from dataclasses import asdict,replace
from datetime import date,datetime,timedelta,timezone
import hashlib
import json
import time
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.access import research_policy as P,operational_authority as A,authority_case_store as S
from app.access.workflow_service import WorkflowService
from app.access.research_service import ResearchService
from app.access.policy import AccessError
from app.identity.action_authority_integration import AuthorityAssessment,StateAssessment
from app.identity.temporal_authority import Fact,ActorState,Rule,Delegation
from app.identity.run_research_algorithms import json_value
from app.access.generated_connection import signed,public
from research_workspace_fixture import initialize,sign,presentation,identifier,PASSWORD,disclosure
from scoped_access_fixture import grant

REF='reviewed-fixture-document';DATA=b'Developer annotated scenario; not police law.'
DAY=date(2024,1,1);ISSUED=date(2023,12,20)

@pytest.fixture
def env(tmp_path):
    clock=[time.time()];store,key,_=initialize(tmp_path,clock=lambda:clock[0])
    assessor=Ed25519PrivateKey.generate();store.workflow_keys={'fixture-assessor':public(assessor)}
    def install(officer=identifier(1),actor_nic='000000001V',generation=2,action_date='2024-01-01'):
        envelope=presentation(key,officer=officer,generation=generation,now=int(clock[0]));p=envelope['payload']
        row={k:'' for k in A.HEADERS['promotion_history.csv']}
        row.update(officer_nic_no='000000001V',to_rank='Reported DIG',effective_date='2024-01-01',
            promotion_authority=actor_nic,promotion_authority_signed_date=action_date)
        p.update(policy=P.RETAINED_POLICY,record_origin='GENERATED_RESEARCH_RECORDS',expires_at=None,
            full_records=[dict(dataset='promotion_history.csv',raw_record_id='f'*64,fields=row)])
        store.import_packet(sign(key,p));return p
    packet=install()
    service=ResearchService(store);workflow=WorkflowService(service);token,csrf=store.access.login('station.one',PASSWORD,'priority2-fixture')
    with store.access.transaction() as database:directory=store.access._directory(database)
    return dict(clock=clock,store=store,key=key,assessor=assessor,packet=packet,install=install,service=service,workflow=workflow,
        token=token,csrf=csrf,directory=directory,root=tmp_path)

def auth_body(**changes):return dict(officer_uid=identifier(1),known_at=None,action_on=None,status='ALL',limit=25,offset=0,**changes)
def authority(e,**changes):
    body=auth_body();body.update(changes);return e['workflow'].authority(e['token'],e['csrf'],body)
def context(e,extra=()):
    packet=e['store'].get_packet(identifier(1));actions=A.inventory(packet,e['directory']);known=datetime.fromtimestamp(e['clock'][0],timezone.utc)
    history,pins,missing=A.actor_history(e['store'],packet,e['directory'],actions.values(),known,extra)
    assert not missing
    ref,action=next(iter(actions.items()));return packet,history,pins,ref,action
def fact(value,assessment='ASSESSED'):return Fact(value,assessment,(REF,))
def state(h,uid=identifier(1),on=DAY,rank='SP',role='ASSESSOR_ROLE',active=True):
    state_id,_=h.project(uid,on)
    return StateAssessment(state_id,ActorState(uid,on,fact(True),fact(rank),fact(role),fact(active),fact('EXPLICIT_SCOPE')))
def typed(e,**changes):
    packet,h,pins,ref,action=context(e)
    r=Rule('explicit-fixture-rule',(action.action_kind,),('SP',),('ASSESSOR_ROLE',),('EXPLICIT_SCOPE',),('EXPLICIT_TARGET',),
        date(2010,1,1),None,True,'ASSESSED',(REF,))
    value=AuthorityAssessment(packet['source_public_sha256'],A.digest(json_value(asdict(action))),action.destination_digest,
        identifier(1),'EXPLICIT_TARGET',fact(True),fact(True),fact(True),(state(h),),(r,),(),((REF,hashlib.sha256(DATA).hexdigest()),))
    return replace(value,**changes)
def record(e,value,*,supersedes=None,at=None,operation=None):
    packet,h,pins,ref,action=context(e,A.assessment_actors(value));prior=S.rows(e['store'],identifier(1))
    head=next((row for row in reversed(prior) if row['payload']['action_reference']==ref),None)
    p=dict(policy=S.POLICY,kind='AUTHORITY_ASSESSMENT',record_origin='GENERATED_RESEARCH_RECORDS',officer_uid=identifier(1),
        action_reference=ref,workspace_sha256=P.fingerprint(packet),source_public_sha256=packet['source_public_sha256'],
        assessment=json_value(asdict(value)),actor_packets=pins,recorded_at=at or datetime.fromtimestamp(e['clock'][0]-0.5,timezone.utc).isoformat(),
        version=head['payload']['version']+1 if head else 1,supersedes=P.fingerprint(head) if head and supersedes is None else supersedes,
        operation_id=operation or str(uuid4()),review_reference='EXPLICIT_DEVELOPER_ANNOTATION')
    envelope=signed(e['assessor'],'fixture-assessor',p)
    receipt=S.append(e['store'],envelope,lambda database=None:None,evidence={REF:DATA})
    return receipt,envelope

def test_reported_rank_and_login_never_create_valid_authority(env):
    e=env;answer=authority(e);item=answer['items'][0]
    assert item['status']=='CANNOT_VERIFY' and item['mode']=='REPORTED_INPUTS_ONLY' and not item['police_action_authorized']
    assert item['actors'][0]['identity']['officer_uid']==identifier(1) and not item['rules'] and not item['delegations']
    assert answer['source_change_completeness_established'] is False

@pytest.mark.parametrize('scenario,expected',[('valid','VALID'),('wrong_rank','INVALID'),('wrong_role','INVALID'),
    ('wrong_scope','INVALID'),('inactive','INVALID'),('identity_unknown','CANNOT_VERIFY'),('coverage_unknown','CANNOT_VERIFY'),
    ('date_unknown','CANNOT_VERIFY'),('expired_rule','INVALID')])
def test_authority_outcomes_through_same_operational_facade(env,scenario,expected):
    e=env;p=typed(e)
    if scenario in ('wrong_rank','wrong_role','wrong_scope','inactive'):
        field={'wrong_rank':'rank','wrong_role':'role','wrong_scope':'scope','inactive':'active'}[scenario]
        p=replace(p,states=(replace(p.states[0],state=replace(p.states[0].state,**{field:fact(False if field=='active' else 'OTHER')})),))
    elif scenario=='identity_unknown':p=replace(p,identity=fact(None,'UNASSESSED'))
    elif scenario=='coverage_unknown':p=replace(p,coverage=fact(None,'UNASSESSED'),
        states=(replace(p.states[0],state=replace(p.states[0].state,active=fact(False))),))
    elif scenario=='date_unknown':p=replace(p,date_semantics=fact(None,'UNASSESSED'))
    elif scenario=='expired_rule':p=replace(p,rules=(replace(p.rules[0],end=DAY),))
    receipt,_=record(e,p);answer=authority(e);item=answer['items'][0]
    assert item['status']==expected and item['assessment_reference']==receipt and item['mode']=='EXPLICIT_ASSESSED_INPUTS'
    assert not item['accepted_authority_claim'] and not item['police_action_authorized']
    filtered=authority(e,status=expected);assert filtered['total']==1
    filtered=authority(e,status='INVALID' if expected!='INVALID' else 'VALID');assert filtered['total']==0

@pytest.mark.parametrize('scenario,expected',[('valid','VALID'),('revoked','INVALID'),('expired','INVALID'),
    ('wrong_power','INVALID'),('wrong_target','INVALID'),('unassessed','CANNOT_VERIFY'),('parent_missing','CANNOT_VERIFY'),('cycle','CANNOT_VERIFY')])
def test_delegation_issuer_issuance_action_date_and_scope_cases(env,scenario,expected):
    e=env;e['install'](identifier(2),generation=1)
    packet,h,pins,ref,action=context(e,[identifier(2)])
    states=(state(h,role='RECIPIENT',rank='PC'),state(h,uid=identifier(2)),state(h,uid=identifier(2),on=ISSUED))
    r=Rule('parent-rule',(action.action_kind,),('SP',),('ASSESSOR_ROLE',),('EXPLICIT_SCOPE',),('EXPLICIT_TARGET',),date(2010,1,1),None,True,'ASSESSED',(REF,))
    d=Delegation('delegated-route','parent-rule',identifier(2),identifier(1),(action.action_kind,),('EXPLICIT_TARGET',),ISSUED,ISSUED,None,False,None,'ASSESSED',(REF,))
    if scenario=='revoked':d=replace(d,revoked_from=DAY)
    elif scenario=='expired':d=replace(d,end=DAY)
    elif scenario=='wrong_power':d=replace(d,powers=('OTHER_POWER',))
    elif scenario=='wrong_target':d=replace(d,target_scopes=('OTHER_TARGET',))
    elif scenario=='unassessed':d=replace(d,assessment='UNASSESSED')
    elif scenario=='parent_missing':d=replace(d,parent_id='missing-parent')
    delegations=(d,)
    if scenario=='cycle':
        d=replace(d,parent_id='cyclic-parent',may_delegate=True)
        second=Delegation('cyclic-parent','delegated-route',identifier(1),identifier(2),(action.action_kind,),('EXPLICIT_TARGET',),
            ISSUED,ISSUED,None,True,None,'ASSESSED',(REF,))
        delegations=(d,second);states=(*states,state(h,on=ISSUED,rank='PC',role='RECIPIENT'))
    p=AuthorityAssessment(packet['source_public_sha256'],A.digest(json_value(asdict(action))),action.destination_digest,identifier(1),
        'EXPLICIT_TARGET',fact(True),fact(True),fact(True),states,(r,),delegations,((REF,hashlib.sha256(DATA).hexdigest()),))
    record(e,p);item=authority(e)['items'][0]
    assert item['status']==expected and item['delegations'][0]['issued_on']==ISSUED.isoformat()
    assert item['delegations'][0]['issuer'] is None  # no officer-2 disclosure grant for station.one
    assert identifier(2) not in json.dumps(authority(e))
    if expected=='VALID':assert item['successful_paths']==['delegated-route']

def test_assessment_corrections_preserve_old_outcome_and_reject_backdating(env):
    e=env;first,_=record(e,typed(e));known=datetime.fromtimestamp(e['clock'][0],timezone.utc).isoformat()
    e['clock'][0]+=2;p=typed(e);p=replace(p,states=(replace(p.states[0],state=replace(p.states[0].state,active=fact(False))),))
    second,_=record(e,p)
    assert authority(e,known_at=known)['items'][0]['status']=='VALID'
    latest=authority(e)['items'][0];assert latest['status']=='INVALID' and latest['assessment_versions'][1]['supersedes']==first
    assert latest['assessment_reference']==second
    with pytest.raises(ValueError):record(e,p,at=known)

@pytest.mark.parametrize('target',['signature','evidence','actor_version','subject_version'])
def test_tampering_or_changed_evidence_never_reuses_a_valid_decision(env,target):
    e=env;receipt,_=record(e,typed(e))
    if target=='actor_version':
        e['clock'][0]+=1;new=deepcopy(e['packet']);new['generation']=3;new['history']['versions'][0]['claim']['value']=json.dumps({'to_rank':'Changed'})
        e['store'].import_packet(sign(e['key'],new))
    elif target=='subject_version':
        e['clock'][0]+=1;new=deepcopy(e['packet']);new['generation']=3;e['store'].import_packet(sign(e['key'],new))
    else:
        table='authority_assessments' if target=='signature' else 'authority_assessment_evidence'
        with e['store'].transaction() as db:
            db.execute(f'DROP TRIGGER no_{table}_update');db.execute(f'UPDATE {table} SET value=?',(b'tampered',))
    if target in ('signature','evidence'):
        with pytest.raises(AccessError) as error:authority(e)
        assert error.value.code=='AUTHORITY_ASSESSMENT_INVALID'
    else:
        item=authority(e)['items'][0];assert item['status']=='CANNOT_VERIFY' and item['assessment_reference'] is None

def test_csrf_scope_missing_dates_privacy_and_read_only_request_boundary(env):
    e=env
    with pytest.raises(AccessError):e['workflow'].authority(e['token'],'bad',auth_body())
    with pytest.raises(AccessError) as error:e['workflow'].authority(e['token'],e['csrf'],{**auth_body(),'officer_uid':identifier(5)})
    assert error.value.status==404
    e['clock'][0]+=1;e['install'](actor_nic='unknown actor',generation=3,action_date='not-a-date')
    item=authority(e)['items'][0];assert item['status']=='CANNOT_VERIFY' and item['action_on'] is None and item['actors']==[]
    with pytest.raises(AccessError):authority(e,assessment={'role':'IGP'})
    assert S.rows(e['store'],identifier(1))==[]

def test_contradiction_queries_filters_versions_and_corrected_knowledge(env):
    e=env;h=e['packet']['history'];before=h['coverage_start'];after=h['coverage_end']
    body=dict(officer_uid=identifier(1),effective_on='2024-12-31',known_at=before,dimension='ALL',status='ALL',relationship='ALL',limit=25,offset=0)
    result=e['workflow'].contradictions(e['token'],e['csrf'],body)
    assert result['items'][0]['status']=='REPORTED_CONTRADICTION_CANDIDATE' and result['items'][0]['cross_reported_source'] is True
    assert result['items'][0]['version_references'] and result['items'][0]['receipt_references']
    assert e['workflow'].contradictions(e['token'],e['csrf'],{**body,'known_at':after})['items'][0]['status']=='REPORTED_AGREEMENT'
    assert e['workflow'].contradictions(e['token'],e['csrf'],{**body,'relationship':'SAME_REPORTED'})['total']==0
    assert e['workflow'].contradictions(e['token'],e['csrf'],{**body,'dimension':'restrictions'})['total']==0
    with pytest.raises(AccessError):e['workflow'].contradictions(e['token'],'wrong',body)

def test_real_https_authority_contradictions_and_logout(env):
    e=env;record(e,typed(e))
    from research_workspace_https_fixture import server
    from scoped_access_http_fixture import request
    config=e['root']/'workspace-config.json';value=json.loads(config.read_text());value['workflow_assessment_keys']={'fixture-assessor':__import__('base64').b64encode(public(e['assessor'])).decode()};config.write_text(json.dumps(value));config.chmod(0o600)
    with server(e['root'],prepared=(e['store'],e['key'],config)) as (_,_,origin,context,_):
        status,headers,body=request(origin,context,'/api/auth/login',method='POST',body={'username':'station.one','password':PASSWORD})
        assert status==200;cookie=headers['set-cookie'].split(';')[0];csrf=body['csrf_token']
        status,headers,result=request(origin,context,'/api/research/authority',method='POST',body=auth_body(),cookie=cookie,csrf=csrf)
        assert status==200 and result['items'][0]['status']=='VALID' and headers['cache-control']=='no-store'
        assert request(origin,context,'/api/research/authority',method='POST',body=auth_body(),cookie=cookie)[0]==403
        b=dict(officer_uid=identifier(1),effective_on='2024-12-31',known_at=e['packet']['history']['coverage_start'],dimension='ALL',status='ALL',relationship='ALL',limit=25,offset=0)
        assert request(origin,context,'/api/research/contradictions',method='POST',body=b,cookie=cookie,csrf=csrf)[0]==200
        assert request(origin,context,'/api/auth/logout',method='POST',body={},cookie=cookie,csrf=csrf)[0]==200
        assert request(origin,context,'/api/research/authority',method='POST',body=auth_body(),cookie=cookie,csrf=csrf)[0]==401

from contradiction_benchmark_cases import benchmark_cases
@pytest.mark.parametrize('case',benchmark_cases(),ids=lambda c:c.case_id)
def test_every_annotated_contradiction_case_through_scoped_workflow(env,case):
    e=env;p=deepcopy(e['packet']);p['generation']=3;p['history']=json_value(asdict(case.history));p['history'].pop('officer_uid')
    e['store'].import_packet(sign(e['key'],p))
    body=dict(officer_uid=identifier(1),effective_on=case.effective_on.isoformat(),known_at=case.known_at.isoformat(),
        dimension='ALL',status='ALL',relationship='ALL',limit=25,offset=0)
    answer=e['workflow'].contradictions(e['token'],e['csrf'],body)
    assert [pair['status'] for pair in answer['items']]==[pair.status for pair in case.expected]
    for actual,expected in zip(answer['items'],case.expected):assert set(expected.required_reasons)<=set(actual['reasons'])
    assert not answer['accepted_contradiction'] and not answer['source_independence_verified']

def test_stalled_or_failed_assessment_publication_rolls_back_and_exact_replay_is_idempotent(env):
    e=env;receipt,envelope=record(e,typed(e));before=S.rows(e['store'],identifier(1))
    assert S.append(e['store'],envelope,lambda database=None:None,evidence={REF:DATA})==receipt
    new=deepcopy(envelope['payload']);new.update(operation_id=str(uuid4()),version=2,supersedes=receipt,
        recorded_at=datetime.fromtimestamp(e['clock'][0]-0.1,timezone.utc).isoformat())
    new=signed(e['assessor'],'fixture-assessor',new)
    def fail(database=None):
        if database is not None:raise OSError('Fixture interrupted commit')
    with pytest.raises(OSError):S.append(e['store'],new,fail,evidence={REF:DATA})
    assert S.rows(e['store'],identifier(1))==before
    with pytest.raises(ValueError):S.append(e['store'],new,lambda database=None:None,evidence={REF:b'wrong evidence'})
    with e['store'].transaction() as db:
        with pytest.raises(Exception):db.execute('DELETE FROM authority_assessments')

def test_unknown_assessor_cyclic_path_future_action_and_no_mutation(env):
    e=env;packet=deepcopy(e['store'].get_packet(identifier(1)));p=typed(e)
    receipt,envelope=record(e,p);bad=deepcopy(envelope);bad['key_id']='ordinary-login-or-presentation-key'
    with pytest.raises(ValueError):S.validate(bad,e['store'])
    assert e['store'].get_packet(identifier(1))==packet
    # A source date beyond knowledge cannot become a historical valid decision.
    e['clock'][0]+=1;e['install'](generation=3,action_date='2030-01-01');item=authority(e)['items'][0]
    assert item['status']=='CANNOT_VERIFY' and 'FUTURE_ACTION_AUTHORITY_UNESTABLISHED_AT_KNOWLEDGE_TIME' in item['reasons']

from test_generated_connection import deployment,prepare as prepare_deployment
from research_connection_fixture import connected,setup,verified,keys,OFFICER
def test_operator_prepare_template_record_and_connection_config_compatibility(deployment,monkeypatch):
    from app.access import generated_connection as G,research_connection_runtime as R,research_connection as C
    from app.access.research_app import configured
    from pathlib import Path
    from app.identity.protected_commitment import digest
    d=deployment;prepare_deployment(d);snapshot=d['t']['snapshot'];snapshot['captured_at']=datetime.now(timezone.utc)
    raw='e'*64;row={k:'' for k in A.HEADERS['promotion_history.csv']}
    row.update(to_rank='SP',effective_date='2024-01-01',promotion_authority='000000001V',promotion_authority_signed_date='2023-12-31')
    snapshot['catalog'][raw]=dict(raw_record_id=raw,filename='promotion_history.csv',classification='UNASSESSED',delivery={'complete':True},
        candidate_links=[dict(officer_uid=OFFICER,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED'),
            dict(officer_uid=OFFICER,role='promotion_authority',state='CANDIDATE_NOT_ACCEPTED')],
        original=dict(columns=sorted(row),values=[row[k] for k in sorted(row)]),provenance={'fixture':'promotion'},assertion={'fixture':'promotion'})
    snapshot['bindings']['raw_bindings'][raw]=[{'fixture':'promotion'}]
    G.connect(d['repo'],d['root'],d['app'],d['t']['config']['source']['audit_gate_attempt'],selected_officers=[OFFICER])
    source_before=deepcopy(snapshot['catalog']);packet_before=d['store'].get_packet(OFFICER)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    import manage_priority2 as operator
    assert operator.prepare(d['repo'],d['app'])['new_assessments_created'] is False
    seed=(d['app']/'keys/research-workflow-assessor.key').read_bytes();operator.prepare(d['repo'],d['app'])
    assert (d['app']/'keys/research-workflow-assessor.key').read_bytes()==seed
    # New optional workflow trust does not break subsequent guarded connectors.
    C.Connection(d['root']/'connection-config.json')
    store,_=configured(d['app']/'workspace-config.json');packet=store.get_packet(OFFICER)
    with store.access.transaction() as db:directory=store.access._directory(db)
    actions=A.inventory(packet,directory);ref,action=next(iter(actions.items()))
    output=d['app']/'priority2/assessment-draft.json'
    operator.template(d['repo'],d['app'],OFFICER,output,ref)
    draft=R.read_json(output,d['repo']);p=draft['assessment'];on=date.fromisoformat(action.reported_date)
    f=lambda value:dict(value=value,assessment='ASSESSED',evidence=[REF])
    p.update(identity=f(True),date_semantics=f(True),coverage=f(True),target_scope='DOCUMENTED_GENERATED_SCOPE')
    p['states'][0]['state'].update(identity=f(True),rank=f('SP'),role=f('DOCUMENTED_GENERATED_ROLE'),active=f(True),scope=f('DOCUMENTED_GENERATED_SCOPE'))
    p['rules']=[json_value(asdict(Rule('documented-generated-instrument',(action.action_kind,),('SP',),('DOCUMENTED_GENERATED_ROLE',),
        ('DOCUMENTED_GENERATED_SCOPE',),('DOCUMENTED_GENERATED_SCOPE',),date(2020,1,1),None,False,'ASSESSED',(REF,))))]
    evidence=output.parent/'reviewed-evidence.txt';evidence.write_bytes(DATA);evidence.chmod(0o600)
    p['evidence_digests']=[[REF,hashlib.sha256(DATA).hexdigest()]];draft['evidence_files']={REF:str(evidence)}
    draft['review_reference']='EXPLICIT_TEST_REVIEW';G.write(output,draft,replace=True)
    result=operator.record(d['repo'],d['app'],output);assert result['result']=='VALID' and not result['police_action_authorized']
    assert snapshot['catalog']==source_before and store.get_packet(OFFICER)==packet_before
    with pytest.raises(ValueError):operator.record(d['repo'],d['app'],output)
    store,_=configured(d['app']/'workspace-config.json');token,csrf=store.access.login('research.hq',PASSWORD,'operator-inspection')
    response=WorkflowService(ResearchService(store)).authority(token,csrf,dict(officer_uid=OFFICER,known_at=None,action_on=None,status='ALL',limit=25,offset=0))
    assert response['items'][0]['status']=='VALID'
    events=store.accountability.read(token,csrf,dict(limit=50,before_sequence=None,action='AUTHORITY_ASSESSMENT_RECORD',outcome=None))['items']
    assert any(v['outcome']=='ALLOWED' for v in events) and all(v['actor']['key_id']==operator.KEY_ID for v in events)
