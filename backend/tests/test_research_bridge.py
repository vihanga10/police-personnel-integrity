"""Actual protected journal fixtures; loader substitution is explicit in tests only."""
from copy import deepcopy
from datetime import datetime,timezone
import pytest
from app.access import research_bridge as B, research_policy as P
from app.identity.protected_commitment import digest
from research_workspace_fixture import initialize,sign,review_body,identifier
from test_recording_tip_witness import witnessed,next_checkpoint
from test_observed_recording_journal import setup,OFFICER
from test_protected_recording_review import verified,keys
from test_witness_secure_transport import secured,listener,wire_client

def test_authenticated_observed_export_replays_bound_original_claims(witnessed,tmp_path,monkeypatch):
    t=witnessed;s=t['s'];now=int(s['clock'][0].timestamp())+1
    monkeypatch.setattr(B.time,'time',lambda:now)
    draft=B._export_loaded(s['snapshot'],s['repo'],t['adapter'],officer_uid=OFFICER,generation=1)
    _,key,_=initialize(tmp_path/'web-export',clock=lambda:now)
    p=P.packet(sign(key,draft),{'workspace-test':B.J._public(key)},now)
    assert p['history']['coverage_start']==s['clock'][0].isoformat()
    assert p['source_public_sha256']==digest(s['snapshot']['public'])
    assert p['history']['versions'] and p['authority']==[] and p['findings']==[]
    assert all(v['status']=='NOT_CONFIGURED' for v in p['anchoring'].values())

@pytest.mark.parametrize('change',['catalog','officer','baseline','witness'])
def test_export_refuses_changed_source_or_missing_freshness(witnessed,change):
    t=witnessed;s=t['s']
    if change=='catalog':next(iter(s['snapshot']['catalog'].values()))['original']['values'][0]='changed'
    if change=='baseline':(s['root']/'baseline.encrypted.json').write_text('{}')
    if change=='witness':t['client'].exchange=lambda _:(_ for _ in ()).throw(OSError('fixture offline'))
    with pytest.raises(Exception):B._export_loaded(s['snapshot'],s['repo'],t['adapter'],officer_uid=identifier(2) if change=='officer' else OFFICER,generation=1)

def test_operational_export_has_no_fixture_transport_waiver(witnessed,monkeypatch):
    import app.identity.algorithm_snapshot as S
    monkeypatch.setattr(S,'load_verified_snapshot',lambda *args:pytest.fail('Loader reached without real mTLS'))
    t=witnessed
    with pytest.raises(ValueError,match='mutual-TLS'):B.export_observed_presentation(None,t['s']['repo'],'revision',t['adapter'],officer_uid=OFFICER,generation=1)

def test_operational_export_uses_unchanged_full_loader(secured,monkeypatch):
    import app.identity.algorithm_snapshot as S
    t=secured['t'];seen=[]
    def full(args,repo,revision):seen.append((args,repo,revision));return t['s']['snapshot']
    monkeypatch.setattr(S,'load_verified_snapshot',full)
    monkeypatch.setattr(B.time,'time',lambda:int(t['s']['clock'][0].timestamp())+1)
    with listener(secured):
        adapter=B.W.WitnessedCheckpointRegistry(t['r'],wire_client(secured))
        result=B.export_observed_presentation('fixture-loader',t['s']['repo'],'revision',adapter,officer_uid=OFFICER,generation=1)
    assert len(seen)==1 and result['recording_tip_sha256']==t['client'].head()['sha256']

def test_operator_requester_revocation_stops_before_protected_runner(tmp_path,monkeypatch):
    from scoped_access_fixture import grant
    s,k,_=initialize(tmp_path);s.append_request({**review_body(), 'user_id':identifier(100),'account_version':1,'reviewer_uid':identifier(1),'source_public_sha256':'a'*64})
    s.access.put_account(grant(k,version=2,active=False))
    import app.identity.temporal_findings_review as M
    monkeypatch.setattr(M,'record_review',lambda *a,**kw:pytest.fail('Protected runner reached after revocation'))
    with pytest.raises(ValueError,match='account changed'):B.record_requested_review(s,identifier(301),None,s.repo,'revision',None,intent={},expected_authority_sha256='a'*64,finding_receipt_path=tmp_path/'absent')

def test_protected_results_append_and_cannot_replace_prior_result(tmp_path):
    s,k,_=initialize(tmp_path);r=s.append_request({**review_body(), 'user_id':identifier(100),'account_version':1,'reviewer_uid':identifier(1),'source_public_sha256':'a'*64})
    s.protected_result(identifier(301),r['request_sha256'],'REVIEW_RECORDED','f'*64)
    before=s.path.read_bytes();s.protected_result(identifier(301),r['request_sha256'],'REVIEW_RECORDED','f'*64)
    assert s.path.read_bytes()==before and s.get_request(identifier(301))['status']=='REVIEW_RECORDED'
    with pytest.raises(ValueError):s.protected_result(identifier(301),r['request_sha256'],'REVIEW_RECORDED','e'*64)
