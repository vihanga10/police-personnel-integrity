"""Retained evidence is historical; session and scope checks remain current."""
from copy import deepcopy
import time
import pytest
from app.access import research_policy as P
from app.access.policy import RETAINED_DIRECTORY_POLICY, AccessError
from app.access.research_service import ResearchService
from research_workspace_fixture import initialize, presentation, disclosure, sign
from scoped_access_fixture import PASSWORD, catalog, sign as sign_access, identifier

def test_retained_details_survive_five_minutes_and_idle_but_not_absolute_logout(tmp_path):
    now=[time.time()];store,key,_=initialize(tmp_path,clock=lambda:now[0]);now[0]+=2
    directory=catalog(key,now=now[0])['payload'];directory.update(policy=RETAINED_DIRECTORY_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS',generation=2)
    store.access.put_directory(sign_access(key,directory))
    p=presentation(key,now=now[0])['payload'];p.update(policy=P.RETAINED_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS',generation=2,
        full_records=[dict(dataset='officer_personal_information.csv',raw_record_id='f'*64,fields={'full_name':'Reported name','address':'Reported address'})])
    store.import_packet(sign(key,p))
    g=disclosure(key,now=now[0])['payload'];g.update(policy=P.RETAINED_POLICY,expires_at=int(now[0])+3500)
    store.import_grant(sign(key,g))
    token,csrf=store.access.login('station.one',PASSWORD,'fixture-peer');service=ResearchService(store)
    deadline=store.access.session(token)['expires_at'];now[0]+=1200
    w=service.workspace(token,identifier(1));assert w['expires_at'] is None and w['full_records'][0]['fields']['address']=='Reported address'
    assert not w['fresh_live_verification'] and w['display_lifecycle']=='RETAINED_LAST_VERIFIED_SNAPSHOT'
    assert store.access.session(token)['expires_at']==deadline
    with pytest.raises(AccessError):service.workspace(token,identifier(2))
    now[0]=deadline
    with pytest.raises(AccessError) as error:service.workspace(token,identifier(1))
    assert error.value.status==401
    # Logout expiry does not remove the stored signed evidence.
    assert store.get_packet(identifier(1))['full_records']==p['full_records']

def test_retained_schema_does_not_convert_legacy_expiry_or_future_observations(tmp_path):
    store,key,_=initialize(tmp_path)
    legacy=presentation(key,now=time.time()-4000)
    with pytest.raises(ValueError):P.packet(legacy,store.keys,time.time())
    p=presentation(key)['payload'];p.update(policy=P.RETAINED_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS',full_records=[])
    assert P.packet(sign(key,p),store.keys,time.time()+86400)['expires_at'] is None
    p['issued_at']=int(time.time())+60
    with pytest.raises(ValueError):P.packet(sign(key,p),store.keys,time.time())

def test_full_subject_rows_exclude_officers_mentioned_only_as_authorities():
    owner=identifier(1);other=identifier(2)
    def row(raw,role,person):return dict(raw_record_id=raw,filename='promotion_history.csv',candidate_links=[dict(officer_uid=person,role=role,state='CANDIDATE_NOT_ACCEPTED')],
        delivery={'complete':True},original=dict(columns=['officer_nic_no','to_rank'],values=['000000001V','Reported SP']))
    snapshot={'catalog':{'a'*64:row('a'*64,'officer_nic_no',owner),'b'*64:row('b'*64,'approving_officer_nic_no',owner),'c'*64:row('c'*64,'officer_nic_no',other)},
        'bindings':{'raw_bindings':{raw:{'bound':True} for raw in ('a'*64,'b'*64,'c'*64)}}}
    records=P.full_records(snapshot,owner)
    assert len(records)==1 and records[0]['raw_record_id']=='a'*64
    del snapshot['bindings']['raw_bindings']['a'*64]
    with pytest.raises(ValueError):P.full_records(snapshot,owner)
