"""Display-only source categories and reported rank boundaries; no accepted state inference."""
from datetime import date, timedelta

SOURCES = {
 'officer_personal_information.csv': ('Police HR information system', 'Officer personal information'),
 'officer_service_information.csv': ('Police HR information system', 'Officer service information'),
 'officer_education.csv': ('Police HR information system', 'Officer education'),
 'officer_family_details.csv': ('Police HR information system', 'Officer family details'),
 'station_master.csv': ('Police HR information system', 'Station reference'),
 'sri_lanka_police_stations_sinhala.csv': ('Police HR information system', 'Sinhala station reference'),
 'promotion_history.csv': ('Personal File registry', 'Promotion history'),
 'transfer_history.csv': ('Personal File registry', 'Transfer history'),
 'operations.csv': ('Personal File registry', 'Operations'),
 'court_details.csv': ('Personal File registry', 'Court details'),
 'public_complaints.csv': ('Personal File registry', 'Public complaint records'),
 'officer_police_numbers.csv': ('Service Record Book (SRB)', 'Police number history'),
 'officer_restrictions.csv': ('Service Record Book (SRB)', 'Restrictions'),
 'restriction_overrides.csv': ('Service Record Book (SRB)', 'Restriction overrides'),
 'officer_firearms_expertise.csv': ('Service Record Book (SRB)', 'Firearms assessments'),
 'officer_duty_periods.csv': ('Service Record Book (SRB)', 'Duty periods'),
 'good_conduct_register.csv': ('Service Record Book (SRB)', 'Good conduct register'),
 'bad_conduct_register.csv': ('Service Record Book (SRB)', 'Bad conduct register'),
 '_demotions_enacted.csv': ('Personal File registry', 'Reported disciplinary demotion'),
}

def source_description(dataset):
    origin, record = SOURCES.get(dataset, ('Origin not established', 'Reported record'))
    return dict(source_category=origin, record_type=record,
                attribution_basis='DATASET_CATEGORY_MAPPING_NOT_CUSTODY_VERIFICATION')

def rank_timeline(versions, effective_on):
    """Only already-visible versions enter this table. Successor dates are display boundaries."""
    grouped={}
    for v in versions:
        c=v['claim']
        if v['withdrawn'] or c['dimension']!='rank' or c['mode']=='REVIEW':continue
        f=c['fields']; rank=next((f[k] for k in ('to_rank','entry_rank','current_rank') if f.get(k)),None)
        if not rank:continue
        start=c['effective_from'];mode=c['mode']
        key=(rank,start,mode)
        item=grouped.setdefault(key,dict(rank=rank,reported_from=start,reported_until=None,
             boundary_basis='No later reported change establishes an end',
             date_meaning=('Enlistment reference date; rank effective date unassessed' if 'entry_rank' in f else
                           'Current service snapshot; rank start date not supplied' if mode=='SNAPSHOT' else
                           'Reported event date; historical validity not automatically accepted'),
             source_categories=[],evidence_references=[],applies_at_selected_date=None))
        origin=source_description(c.get('reported_dataset'))['source_category']
        if origin not in item['source_categories']:item['source_categories'].append(origin)
        if c['reference'] not in item['evidence_references']:item['evidence_references'].append(c['reference'])
    rows=sorted(grouped.values(),key=lambda r:(r['reported_from'] is None,r['reported_from'] or '',r['rank']))
    dated=sorted({r['reported_from'] for r in rows if r['reported_from']})
    for item in rows:
        start=item['reported_from']
        if not start:continue
        following=next((d for d in dated if d>start),None)
        if following:
            item['reported_until']=(date.fromisoformat(following)-timedelta(days=1)).isoformat()
            item['boundary_basis']='Display boundary before the next reported rank event; continuity and validity unassessed'
        item['applies_at_selected_date']=start<=effective_on and (item['reported_until'] is None or effective_on<=item['reported_until'])
    return rows
