"""Actual ASGI lifecycle worker, encrypted journal and explicit reader permission."""
import asyncio
from datetime import datetime
import json
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from test_accountability import env,events,FILTERS

def starts(logs):return [e for e in events(logs) if e['action']=='LOGIN' and e['phase']=='COMPLETED' and e['status']==200]
def ends(logs):return [e for e in events(logs) if e['action'] in ('SESSION_EXPIRED','SESSION_INTERRUPTED')]

def test_authenticated_search_terms_are_encrypted_and_only_explicit_reader_sees_them(env):
    _,logs,c,*_=env
    assert c.request('/api/officers/search','POST',{'kind':'NIC','query':'000000001V'})[0]==200
    assert c.request('/api/officers/search','POST',{'kind':'NAME','query':'Same Reported Name'})[0]==200
    values=[e['search'] for e in events(logs) if e.get('search')]
    assert values==[{'kind':'NIC','query':'000000001V'},{'kind':'NAME','query':'Same Reported Name'}]
    for secret in ('000000001V','Same Reported Name',c.cookie.split('=',1)[1],c.csrf):
        assert secret.encode() not in logs.db.read_bytes()
    text=json.dumps(events(logs));assert c.csrf not in text and c.cookie.split('=',1)[1] not in text
    status,_,result=c.request('/api/accountability/logs','POST',FILTERS)
    assert status==200 and any(e.get('search')==values[0] for e in result['items'])
    logs.grant_files=()
    assert c.request('/api/accountability/logs','POST',FILTERS)[0]==403

def test_expiry_is_server_derived_idempotent_and_has_the_original_deadline(env):
    _,logs,c,_,_,clock,*_=env;login=starts(logs)[0]
    clock[0]=datetime.fromisoformat(login['session_deadline']).timestamp()+5
    with ThreadPoolExecutor(max_workers=4) as pool:counts=list(pool.map(lambda _:logs.reconcile_sessions(),range(8)))
    assert sum(counts)==1
    value=ends(logs)[0];assert value['action']=='SESSION_EXPIRED' and value['session_effective_end_at']==login['session_deadline']
    assert value['reason']=='FIXED_30_MINUTE_LIMIT' and not value['logout_confirmed']
    assert value['recorded_at']!=value['session_effective_end_at']
    assert logs.reconcile_sessions()==0

def test_manual_logout_stays_distinct_and_prevents_later_expiry_event(env):
    _,logs,c,_,_,clock,*_=env
    assert c.request('/api/auth/logout','POST',{})[0]==200
    logout=events(logs)[-1]
    assert logout['logout_confirmed'] and logout['session_end_reason']=='MANUAL_LOGOUT'
    clock[0]+=1801;assert logs.reconcile_sessions()==0 and ends(logs)==[]

def test_page_exit_report_is_authenticated_bounded_and_does_not_end_session(env):
    _,logs,c,_,_,clock,*_=env
    body={'event':'PAGE_EXIT','page':'WORKSPACE','persisted':False}
    assert c.request('/api/accountability/session-signal','POST',body,csrf='bad')[0]==403
    assert c.request('/api/accountability/session-signal','POST',{**body,'user_id':'another'})[0]==400
    status,_,value=c.request('/api/accountability/session-signal','POST',body)
    assert status==200 and not value['logout_confirmed']
    event=events(logs)[-1];assert event['client_page_event']['event']=='PAGE_EXIT' and not event['client_page_event']['logout_confirmed']
    assert c.request('/api/auth/session')[0]==200 and not ends(logs)
    clock[0]+=1801;assert logs.reconcile_sessions()==1

def test_restart_and_shutdown_are_interruptions_without_invented_logout_time(env):
    _,logs,c,*_=env
    # A new process has a fresh session key; no prior browser token survives it.
    logs.access.boot_key=b'\x05'*32
    assert logs.reconcile_sessions(restart=True)==1
    value=ends(logs)[0]
    assert value['action']=='SESSION_INTERRUPTED' and value['reason']=='SERVER_RESTART_OBSERVED'
    assert value['session_effective_end_at'] is None and not value['logout_confirmed']
    assert logs.reconcile_sessions(restart=True)==0

def test_asgi_worker_records_expiry_without_any_http_request(env):
    _,logs,c,_,_,clock,*_=env;boundary=c.app;boundary.expiry_poll_seconds=.02
    async def check():
        queue=asyncio.Queue();started=asyncio.Event();sent=[]
        async def receive():return await queue.get()
        async def send(event):
            sent.append(event)
            if event['type']=='lifespan.startup.complete':started.set()
        task=asyncio.create_task(boundary({'type':'lifespan','asgi':{'version':'3.0'}},receive,send))
        try:
            await queue.put({'type':'lifespan.startup'});await asyncio.wait_for(started.wait(),3)
            clock[0]+=1801
            until=time.monotonic()+3
            while not ends(logs):
                assert time.monotonic()<until,'Independent expiry worker did not record the deadline'
                await asyncio.sleep(.02)
            assert ends(logs)[0]['action']=='SESSION_EXPIRED'
        finally:
            await queue.put({'type':'lifespan.shutdown'});await asyncio.wait_for(task,3)
        assert sent[-1]['type']=='lifespan.shutdown.complete'
    asyncio.run(check())

def test_lifecycle_failure_denies_http_and_history_is_preserved(env,monkeypatch):
    _,logs,c,*_=env;before=events(logs)
    monkeypatch.setattr(logs,'reconcile_sessions',lambda **kwargs:(_ for _ in ()).throw(OSError('private details')))
    status,_,value=c.request('/api/auth/session')
    assert status==503 and value['error']=='ACCOUNTABILITY_UNAVAILABLE'
    assert events(logs)==before

def test_replacement_login_and_graceful_stop_have_their_own_terminal_records(env):
    _,logs,c,*_=env
    old=starts(logs)[0]
    # Valid login with the earlier cookie explicitly replaces that server session.
    from research_workspace_fixture import PASSWORD
    status,_,_=c.request('/api/auth/login','POST',{'username':'station.one','password':PASSWORD})
    assert status==200
    assert logs.reconcile_sessions()==1
    replacement=ends(logs)[0]
    assert replacement['reason']=='REPLACED_BY_NEW_LOGIN' and replacement['session_reference']==old['session_reference']
    assert logs.reconcile_sessions(shutdown=True)==1
    assert ends(logs)[-1]['reason']=='SERVER_SHUTDOWN_OBSERVED'
    assert logs.reconcile_sessions(shutdown=True)==0
