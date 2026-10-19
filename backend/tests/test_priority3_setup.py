import importlib.util
from pathlib import Path
import pytest
from test_generated_connection import deployment
from research_connection_fixture import connected,setup,verified,keys
from app.access import generated_connection as G,review_workflow as W
from app.access.research_app import configured
spec=importlib.util.spec_from_file_location('priority3_setup',Path(__file__).resolve().parents[1]/'scripts/manage_priority3.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

def test_ten_account_operator_setup_idempotence_policy_revision_and_backup(deployment,monkeypatch):
    d=deployment;monkeypatch.setattr(M.C,'revision',lambda _: 'fixture-revision');monkeypatch.setattr('provision_generated_connection.stopped_app',lambda *_:None)
    before=(d['app']/'accounts.json').read_bytes();r=M.prepare(d['repo'],d['app']);assert r['status']=='PRIORITY3_RESEARCH_POLICY_CONFIGURED'
    assert M.prepare(d['repo'],d['app'])['status']=='PRIORITY3_ALREADY_CONFIGURED'
    s,_=configured(d['app']/'workspace-config.json')
    with s.transaction() as c:p=W.policies(s,c)[0]['payload']
    assert len(p['accounts'])==9 and 'HQ_ADMIN' not in p['review_roles'] and 'STATION_OIC' not in p['request_roles']
    draft=d['app']/'policy-draft.json';G.write(draft,dict(request_roles=W.REQUEST,review_roles=['IGP'],inspect_roles=W.REQUEST,reason='Documented policy change'))
    assert M.prepare(d['repo'],d['app'],draft)['policy_version']==2
    with s.transaction() as c:assert len(W.policies(s,c))==2
    assert (d['app']/'accounts.json').read_bytes()==before
    with s.accountability.locked() as c:assert len([v for _,v in s.accountability.verify(c)[0] if v.get('action')=='RESEARCH_REVIEW_POLICY' and v['outcome']=='ALLOWED'])==2
    backup=d['app']/'key-backup/research-review-policy.key';G.write(backup,b'x'*32,replace=True)
    with pytest.raises(ValueError):M.prepare(d['repo'],d['app'],draft)
