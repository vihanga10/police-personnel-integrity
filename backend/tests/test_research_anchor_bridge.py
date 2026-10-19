"""Read-only composition of the existing pipeline with explicit service fixtures."""
import pytest
from app.access.research_bridge import observe_anchoring
from test_findings_backend_pipeline import (
    pipeline,public_fixture,gate_fixture,prepared,recovered,witnessed_findings,
    registered,journal,output,witnessed,setup,verified,keys)

def test_anchor_observation_uses_only_reconcile_and_preserves_finality_limits(pipeline):
    t=pipeline;p,read,selection,grant=t['ready']('RECONCILE')
    officer=p.source.findings.registry.journal.officer_uid
    result=observe_anchoring(p,officer_uid=officer,fabric_read_approval=read,public_read_approval=grant)
    assert result['fabric']['status']=='OBSERVED_VALID' and result['public']['status']=='ISOLATED_ONLY'
    assert all(mode=='RECONCILE' for service,mode in t['calls'])

def test_execute_pipeline_cannot_be_exposed_as_a_refresh(pipeline):
    t=pipeline;before=list(t['calls'])
    with pytest.raises(ValueError,match='read-only'):observe_anchoring(t['p'],officer_uid=t['p'].source.findings.registry.journal.officer_uid,fabric_read_approval=t['fgrant']())
    assert t['calls']==before

def test_uncertain_public_receipt_stays_pending(pipeline):
    t=pipeline;p,read,selection,grant=t['ready']('RECONCILE');t['fault']['public']='pending'
    result=observe_anchoring(p,officer_uid=p.source.findings.registry.journal.officer_uid,fabric_read_approval=read,public_read_approval=grant)
    assert result['public']['status']=='PENDING'

def test_observation_never_claims_an_earlier_publication_covers_new_findings(pipeline,monkeypatch):
    from app.identity.protected_commitment import digest
    t=pipeline;p,read,selection,grant=t['ready']('RECONCILE')
    # Independent test substitute of the published history pin. Even a valid
    # receipt must not be represented as covering a different current history.
    current=p.fabric_selection();current['history_sha256']='f'*64
    monkeypatch.setattr(p,'fabric_selection',lambda:current)
    before=list(t['calls'])
    with pytest.raises(ValueError,match='earlier findings prefix'):
        observe_anchoring(p,officer_uid=p.source.findings.registry.journal.officer_uid,fabric_read_approval=read)
    assert t['calls']==before

def test_export_composes_current_history_findings_and_read_only_chain_receipts(pipeline,monkeypatch,tmp_path):
    from app.access import research_bridge as B,research_policy as P
    from research_workspace_fixture import initialize,sign
    import app.identity.algorithm_snapshot as S
    t=pipeline;original=t['t']['original'];p,read,selection,grant=t['ready']('RECONCILE')
    d=original['t']['d'];recording=d['t']['d']['t']['adapter'];snapshot=original['s']['snapshot']
    # Explicit loader/transport substitutions of the inherited disposable gate
    # fixture. Full history/findings replay and receipt composition remain real.
    monkeypatch.setattr(S,'load_verified_snapshot',lambda *args:snapshot)
    import app.identity.protected_findings_capture as C
    monkeypatch.setattr(C,'_recording_transport',lambda *args:None)
    now=int(original['s']['clock'][0].timestamp())+2;monkeypatch.setattr(B.time,'time',lambda:now)
    officer=p.source.findings.registry.journal.officer_uid
    draft=B.export_observed_presentation(original['args'],original['repo'],p.source.revision,recording,
        officer_uid=officer,generation=1,findings=original['f'],pipeline=p,
        fabric_read_approval=read,public_read_approval=grant)
    assert draft['findings'] and draft['history']['versions'] and draft['anchoring']['fabric']['status']=='OBSERVED_VALID'
    assert draft['anchoring']['public']['status']=='ISOLATED_ONLY'
    assert all(mode=='RECONCILE' for _,mode in t['calls'])
    _,key,_=initialize(tmp_path/'workspace',clock=lambda:now)
    assert P.packet(sign(key,draft),{'workspace-test':B.J._public(key)},now)['officer_uid']==officer
