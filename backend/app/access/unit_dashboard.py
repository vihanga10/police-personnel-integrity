"""Unit statistics within signed web membership and detail-disclosure permissions."""
from collections import Counter
from app.access.policy import AccessError,permitted
from app.access import full_source_profiles as F
UNIT_LABELS={'CID':'CID','CCIB':'CCIB','CRIMINAL_DIVISION':'Criminal Divisions'}

def dashboard(service,token):
    access=service.access
    with access.transaction() as c:
        user,_=access._session(c,token);directory=access._directory(c)
    if user['role']!='SDIG' or user['scope_type']!='UNIT' or user['scope_id'] not in UNIT_LABELS:
        raise AccessError(403,'UNIT_DASHBOARD_FORBIDDEN')
    officers=[o for o in directory['officers'] if permitted(user,o)]
    metadata=F.active_set(service.store)
    capabilities=F.capabilities(service.store,user,directory,officers)
    ranks=Counter();statuses=Counter();divisions=set();source_dates=[]
    for o in officers:
        if o['officer_uid'] not in capabilities:continue
        p=F.profile(service.store,o['officer_uid'],directory['source_public_sha256'])
        rows=[r for r in p['full_records'] if r['dataset']=='officer_service_information.csv']
        if len(rows)!=1:raise AccessError(503,'UNIT_SOURCE_UNRESOLVED')
        f=rows[0]['fields'];expected='Criminal Division' if user['scope_id']=='CRIMINAL_DIVISION' else user['scope_id']
        if f.get('current_unit_type')!=expected:raise AccessError(503,'UNIT_SOURCE_CHANGED')
        ranks[f.get('current_rank') or 'Not recorded']+=1
        statuses[f.get('service_status') or 'Not recorded']+=1
        if f.get('current_division'):divisions.add(f['current_division'])
        source_dates.append(p['issued_at'])
    with access.transaction() as c:
        latest,_=access._session(c,token)
        if latest!=user or access._directory(c)!=directory:raise AccessError(409,'PRESENTATION_CHANGED')
    if F.active_set(service.store)!=metadata or F.capabilities(service.store,user,directory,officers)!=capabilities:
        raise AccessError(409,'PRESENTATION_CHANGED')
    return dict(unit=user['scope_id'],unit_label=UNIT_LABELS[user['scope_id']],officers=len(officers),
        details_available=len(capabilities),status_counts=dict(sorted(statuses.items())),rank_counts=dict(sorted(ranks.items())),
        divisions=len(divisions),latest_copy_issued_at=max(source_dates,default=None),
        evidence_basis='REPORTED_CONNECTED_SERVICE_RECORDS',authority_established=False)
