import os,json
from copy import deepcopy
import pytest
from test_priority3 import env,saved,requested,decide
from app.access import application_findings_commitments as A,research_policy as P

def test_complete_prefix_contains_original_requests_rejections_corrections_and_policies(env):
    e=env;b,r=saved(e);_,req=requested(e,b,r);decide(e,req,'REJECT');_,corr=requested(e,b,r,'CORRECTION');decide(e,corr)
    selected=A.select(e['store'],b['officer_uid']);assert [v['kind'] for v in selected['entries']]==['SAVE','REQUEST','DECIDE','REQUEST','DECIDE']
    key=os.urandom(32);pubkey=os.urandom(32);salt=os.urandom(32);public=A.generate(selected,key,pubkey,salt=salt)
    assert len(public['entries'])==5
    text=json.dumps(public)
    for secret in (b['officer_uid'],'research.dig','Independent reviewer explanation','2024-12-31'):assert secret not in text
    assert A.fabric_payload(public)['public_sha256']==P.fingerprint(public)
    assert A.generate(selected,key,pubkey,salt=salt)==public
    changed=deepcopy(selected);changed['entries'].pop();assert A.generate(changed,key,pubkey,salt=salt)['merkle_root']!=public['merkle_root']

def test_source_is_archived_atomically_before_current_copy_advances(env):
    from research_workspace_fixture import sign
    e=env;b,r=saved(e);packet=deepcopy(e['store'].get_packet(b['officer_uid']));packet['generation']+=1;e['store'].import_packet(sign(e['key'],packet))
    selected=A.select(e['store'],b['officer_uid']);assert selected['sources'][selected['entries'][0]['source_sha256']]['payload']['generation']==2

def test_missing_unarchived_legacy_source_fails_closed(env):
    e=env;b,r=saved(e)
    import sqlite3
    with e['store'].transaction() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM application_review_sources')

def test_legacy_missing_archive_is_backfilled_only_from_exact_current_source(env):
    from research_workspace_fixture import sign
    e=env;b,_=saved(e)
    with e['store'].transaction() as c:
        c.execute('DROP TRIGGER application_review_sources_DELETE');c.execute('DELETE FROM application_review_sources')
    assert A.select(e['store'],b['officer_uid'])['sources']
    with e['store'].transaction() as c:
        c.execute('DROP TRIGGER application_review_sources_DELETE');c.execute('DELETE FROM application_review_sources')
    packet=deepcopy(e['store'].get_packet(b['officer_uid']));packet['generation']+=1;e['store'].import_packet(sign(e['key'],packet))
    with pytest.raises(ValueError):A.select(e['store'],b['officer_uid'])

def test_empty_history_and_same_commitment_keys_cannot_publish(env):
    with pytest.raises(ValueError):A.select(env['store'],'00000000-0000-0000-0000-000000000099')
    b,r=saved(env);selection=A.select(env['store'],b['officer_uid']);key=os.urandom(32)
    with pytest.raises(ValueError):A.generate(selection,key,key,salt=os.urandom(32))
