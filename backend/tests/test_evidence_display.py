from datetime import datetime,timezone
from app.access.evidence_display import rank_timeline,source_description
from test_promotion_analysis import connected,publish,env
from test_promotion_approvals import e,batch,visible,assess
from research_workspace_fixture import identifier

def v(rank,start,*,mode='EVENT',withdrawn=False,dataset='promotion_history.csv'):
 return dict(withdrawn=withdrawn,claim=dict(dimension='rank',fields={'current_rank' if mode=='SNAPSHOT' else 'to_rank':rank},effective_from=start,mode=mode,reference=rank+str(start),reported_dataset=dataset))

def test_rank_boundaries_are_reported_sequence_only_and_unknown_starts_remain_unknown():
 rows=rank_timeline([v('PC','2020-01-01'),v('IP','2024-03-01'),v('SP',None,mode='SNAPSHOT'),v('BAD','2022-01-01',withdrawn=True),v('Unassessed demotion floor','2021-01-01',mode='REVIEW')],'2023-01-01')
 assert rows[0]['reported_until']=='2024-02-29'
 assert rows[0]['applies_at_selected_date'] is True
 assert rows[-1]['reported_from'] is None and rows[-1]['reported_until'] is None
 assert 'validity unassessed' in rows[0]['boundary_basis']
 assert not any(r['rank'] in ('BAD','Unassessed demotion floor') for r in rows)

def test_source_categories_do_not_claim_independent_custody():
 assert source_description('officer_restrictions.csv')['source_category']=='Service Record Book (SRB)'
 assert source_description('promotion_history.csv')['source_category']=='Personal File registry'
 assert source_description('untrusted.csv')['source_category']=='Origin not established'
 assert source_description('promotion_history.csv')['attribution_basis'].endswith('NOT_CUSTODY_VERIFICATION')

def test_upload_exposes_three_distinct_times_and_known_boundary_filters_rank_sequence(connected):
 e=connected;w=e['service'].workspace(e['token'],identifier(1));old=w['coverage_end']
 publish(e);e['analysis'].activate_visible();w=e['service'].workspace(e['token'],identifier(1))
 assert w['observed_at']==w['evidence_updates']['baseline_observed_at']
 assert w['evidence_updates']['latest_analysis_at']!=w['observed_at']
 assert w['evidence_updates']['latest_publication_verified_at']
 assert w['evidence_updates']['fresh_chain_reads'] is False
 early=e['service'].history(e['token'],e['csrf'],identifier(1),'2024-01-01',old)
 late=e['service'].history(e['token'],e['csrf'],identifier(1),'2024-01-01',w['coverage_end'])
 assert early['promotion_analysis']['reported_promotions']==0 and late['promotion_analysis']['reported_promotions']==1
 assert late['rank_timeline']
 assert all('source_description' in v['claim'] for v in late['versions'])

def test_pending_does_not_update_current_rank_and_reasons_follow_authority_then_acceptance(e):
 b=batch(e);visible(e,b);e['engine'].synchronize()
 result=e['engine'].current(identifier(1));assert result['accepted_promotion'] is None
 assert result['row_outcomes'][0]['status']=='PENDING_REVIEW'
 assert 'AUTHORITY_CANNOT_VERIFY' in result['row_outcomes'][0]['reasons']
 assess(e,b);e['engine'].synchronize();result=e['engine'].current(identifier(1))
 assert result['row_outcomes'][0]['status']=='ACCEPTED'
 assert result['accepted_promotion'] is not None
 assert result['source_service_record_preserved'] is True
