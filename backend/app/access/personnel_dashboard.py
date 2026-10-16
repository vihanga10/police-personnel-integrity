"""Read-only, linear-time service-record projection inside current disclosure scope.

Only compact verified fields are cached in memory. Encrypted row bytes, current
account, directory, grants and source-set pins are checked on each request.
"""
from collections import Counter
from copy import deepcopy
import hashlib
import threading
import time
from app.access import full_source_profiles as F
from app.access.policy import AccessError, permitted, projection, require
from app.identity.service_values import RANKS, UNITS

ORDER=('IGP','SDIG','DIG','SSP','SP','ASP','CIP','IP','SI','PS_C1','PS_C2','PC_C1','PC_C2','PC_C3','PC_C4','PC')
GROUPS=(('CID','CID'),('CCIB','CCIB'),('CRIMINAL_DIVISION','Criminal Divisions'),('STATION_CRIME_BRANCH','Station Crime Branches'))
NON_STATION={'CID','CCIB','DISTRICT_COMMAND','PROVINCIAL_COMMAND'}
RANK_CODES={**RANKS,**{k:k for k in ORDER},'Inspector General of Police':'IGP','Police Sergeant':'PS_C1'}
UNIT_CODES={**UNITS,**{v:v for v in UNITS.values()}}

def text(fields,name):
    v=fields.get(name)
    return v.strip() if type(v) is str and v.strip() else None

def rank_order(code):return ORDER.index(code) if code in ORDER else len(ORDER)

def project(p):
    rows=[r for r in p['full_records'] if r['dataset']=='officer_service_information.csv']
    if len(rows)!=1:return dict(unit_type='UNRESOLVED',rank_code='UNRESOLVED',rank_label='Service rows need review',quality='MULTIPLE_OR_MISSING_SERVICE_ROWS',source_reference=None)
    r=rows[0];f=r['fields'];unit_raw=text(f,'current_unit_type');unit=UNIT_CODES.get(unit_raw,'UNRESOLVED');rank_raw=text(f,'current_rank');rank=RANK_CODES.get(rank_raw,'UNRESOLVED')
    station=text(f,'current_station') or text(f,'current_station_code');division=text(f,'current_division')
    return dict(unit_type=unit,unit_type_reported=unit_raw,rank_code=rank,rank_label=rank_raw or 'Rank needs review',
      unit_name=text(f,'current_unit_name'),unit_location=text(f,'current_unit_location'),police_number=text(f,'current_police_no'),
      station=station,station_code=text(f,'current_station_code'),division=division,province=text(f,'current_province'),district=text(f,'current_district'),service_status=text(f,'service_status'),
      station_status='REPORTED' if station else 'NON_STATION_ASSIGNMENT' if unit in NON_STATION else 'SOURCE_STATION_MISSING',
      division_status='REPORTED' if division else 'NON_DIVISION_ASSIGNMENT' if unit in NON_STATION else 'SOURCE_DIVISION_MISSING',
      quality='REPORTED_SERVICE_ROW' if unit!='UNRESOLVED' and rank!='UNRESOLVED' else 'UNMAPPED_UNIT_OR_RANK',
      source_reference=r['raw_record_id'],source_observed_at=p['issued_at'])

def _cache(store):
    with store.lock:
        if not hasattr(store,'_personnel_dashboard_cache'):store._personnel_dashboard_cache={'lock':threading.RLock(),'key':None,'rows':{}}
        return store._personnel_dashboard_cache

def compact_profiles(store,metadata,officers):
    cache=_cache(store);key=F.P.fingerprint({'source_set':metadata,'authority_keys':{k:v.hex() for k,v in sorted(store.keys.items())}});selected={store.index('SOURCE_PROFILE',o['officer_uid']):o for o in officers};result=[];visited=set()
    with cache['lock']:
        if cache['key']!=key:cache.update(key=key,rows={})
        identifiers=sorted(set(selected)&set(metadata['profiles']))
        for start in range(0,len(identifiers),64):
            # Local keyset batches release the SQLite write-reservation lock
            # between reads, allowing review and worker activity to proceed.
            chunk=identifiers[start:start+64]
            placeholders=','.join('?' for _ in chunk)
            with store.transaction() as c:rows=c.execute('SELECT id,value FROM source_profiles WHERE generation=? AND id IN ('+placeholders+')',(metadata['generation'],*chunk)).fetchall()
            for ident,blob in rows:
                if ident not in selected or ident not in metadata['profiles']:continue
                visited.add(ident);cipher_sha=hashlib.sha256(blob).hexdigest();retained=cache['rows'].get(ident)
                if retained and retained[0]==cipher_sha:
                    value=retained[1]
                    require(value.get('source_observed_at',0)<=store.clock(),'Source observation is in the future')
                else:
                    envelope=store.open('SOURCE_PROFILE',[metadata['generation'],ident],blob)
                    require(F.P.fingerprint(envelope)==metadata['profiles'][ident],'Source profile digest differs')
                    p=F.validate_profile(envelope,store.keys,store.clock())
                    require(p['officer_uid']==selected[ident]['officer_uid'] and all(p[k]==metadata[k] for k in ('generation','source_public_sha256','source_context_sha256')),'Profile binding differs')
                    value=project(p);cache['rows'][ident]=(cipher_sha,value)
                result.append({**projection(selected[ident]),**deepcopy(value)})
        expected=set(selected)&set(metadata['profiles'])
        require(visited==expected,'Connected profile row missing')
        # Cache contains compact server-side projections only; disclosure is
        # rechecked for every caller and each selected ciphertext is rehashed.
    return result

def counts(rows,key):return dict(sorted(Counter(r.get(key) or 'Needs source review' for r in rows).items()))

def summarize(rows,total,withheld,unavailable):
    groups=[]
    for code,label in (*GROUPS,('OTHER','Other service units'),('UNRESOLVED','Unit needs review')):
        members=[r for r in rows if r['unit_type']==code or code=='OTHER' and r['unit_type'] not in {k for k,_ in GROUPS}|{'UNRESOLVED'}]
        by_rank=Counter(r['rank_code'] for r in members);known=[k for k in by_rank if k in ORDER];highest=min(known,key=rank_order) if known else None
        groups.append(dict(code=code,label=label,officers=len(members),rank_counts=[dict(code=k,count=by_rank[k]) for k in sorted(by_rank,key=rank_order)],
            highest_rank=highest,highest_rank_complete=all(r['rank_code'] in ORDER for r in members),
            highest_officer_uids=[r['officer_uid'] for r in members if highest and r['rank_code']==highest],
            unit_names=counts(members,'unit_name'),unit_name_count=len({r.get('unit_name') for r in members if r.get('unit_name')}),
            division_counts=counts([r for r in members if r.get('division')],'division'),station_counts=counts([r for r in members if r.get('station')],'station'),
            province_counts=counts([r for r in members if r.get('province')],'province'),location_counts=counts([r for r in members if r.get('unit_location')],'unit_location'),service_status_counts=counts(members,'service_status')))
    return dict(permitted_officers=total,disclosed_officers=len(rows),withheld_officers=withheld,profile_unavailable_officers=unavailable,groups=groups,
        data_quality=dict(unresolved_unit_or_rank=sum(r['quality']!='REPORTED_SERVICE_ROW' for r in rows),
            missing_station=sum(r.get('station_status')=='SOURCE_STATION_MISSING' for r in rows),
            non_station_assignments=sum(r.get('station_status')=='NON_STATION_ASSIGNMENT' for r in rows),
            missing_division=sum(r.get('division_status')=='SOURCE_DIVISION_MISSING' for r in rows)),
        officers=sorted(rows,key=lambda r:(rank_order(r['rank_code']),r['names'][0],r['officer_uid'])))

def dashboard(service,token):
    started=time.monotonic();access=service.access;store=service.store
    with access.transaction() as c:
        user,session=access._session(c,token);directory=access._directory(c);access._limit(c,'PERSONNEL_DASHBOARD',session['user'],12)
    officers=[o for o in directory['officers'] if permitted(user,o)];metadata=F.active_set(store)
    if metadata is None:raise AccessError(503,'DASHBOARD_SOURCE_NOT_CONNECTED')
    require(metadata['source_public_sha256']==directory['source_public_sha256'],'Source directory differs')
    allowed=F.capabilities(store,user,directory,officers);visible=[o for o in officers if o['officer_uid'] in allowed]
    try:rows=compact_profiles(store,metadata,visible)
    except Exception as e:raise AccessError(503,'DASHBOARD_SOURCE_VERIFICATION_FAILED') from e
    with access.transaction() as c:
        current,_=access._session(c,token)
        if current!=user or access._directory(c)!=directory:raise AccessError(409,'DASHBOARD_SOURCE_CHANGED')
    if F.active_set(store)!=metadata or F.capabilities(store,user,directory,officers)!=allowed:raise AccessError(409,'DASHBOARD_SOURCE_CHANGED')
    acceptance=getattr(service,'promotion_acceptance',None)
    if acceptance is not None:
        affected=acceptance.affected_officers()
        for row in rows:
            if row['officer_uid'] not in affected:continue
            decision=acceptance.current(row['officer_uid']);accepted=decision['accepted_promotion']
            if accepted:
                row.update(rank_code=accepted['rank_code'],rank_label=accepted['to_rank'],accepted_promotion_reference=accepted['acceptance_reference'],rank_basis='ACCEPTED_PROMOTION_EFFECTIVE_NOW')
        with access.transaction() as c:
            latest,_=access._session(c,token)
            if latest!=user or access._directory(c)!=directory:raise AccessError(409,'DASHBOARD_SOURCE_CHANGED')
    result=summarize(rows,len(officers),len(officers)-len(visible),len(visible)-len(rows))
    return dict(policy='SCOPED_REPORTED_PERSONNEL_DASHBOARD_V1',**result,source_generation=metadata['generation'],directory_generation=directory['generation'],
        source_public_sha256=metadata['source_public_sha256'],scope_type=user['scope_type'],scope_id=user['scope_id'],
        basis='SIGNED_SERVICE_RECORDS_WITH_ACCEPTED_PROMOTIONS' if any(r.get('accepted_promotion_reference') for r in rows) else 'SIGNED_CONNECTED_SERVICE_RECORDS',authority_established=False,verified_at=int(store.clock()),build_seconds=round(time.monotonic()-started,3))
