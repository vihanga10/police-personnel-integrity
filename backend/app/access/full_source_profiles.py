"""Signed, encrypted subject-row profiles. No invented journal history or findings.

The operator bulk importer uses a fresh exact anchored replay. Runtime access
still requires current signed membership and an ordinary disclosure grant.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.access.policy import AccessError, encoded, require, uid
from app.access import research_policy as P
from app.security.record_protection import (
    AssignmentProtection, RecordClassification, DisclosureCategory, ProtectionLevel, required_protection)

POLICY = 'GENERATED_FULL_SOURCE_PROFILES_V1'
SCHEMA = '''CREATE TABLE IF NOT EXISTS source_profile_sets
(generation INTEGER PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS source_profiles
(generation INTEGER NOT NULL, id TEXT NOT NULL, value BLOB NOT NULL,
PRIMARY KEY(generation,id));'''

def signed(envelope, keys, kind, now):
    require(type(envelope) is dict and set(envelope)=={'key_id','payload','signature'})
    require(envelope['key_id'] in keys)
    p=envelope['payload']
    require(p.get('policy')==POLICY and p.get('kind')==kind and
            p.get('record_origin')=='GENERATED_RESEARCH_RECORDS' and
            type(p.get('issued_at')) is int and p['issued_at']<=now and
            type(p.get('generation')) is int and p['generation']>0)
    P.sha(p['source_public_sha256']);P.sha(p['source_context_sha256'])
    Ed25519PublicKey.from_public_bytes(keys[envelope['key_id']]).verify(
        base64.b64decode(envelope['signature'],validate=True),encoded(p))
    return p

def validate_profile(envelope, keys, now):
    p=signed(envelope,keys,'SOURCE_PROFILE',now)
    require(set(p)=={'policy','kind','record_origin','issued_at','generation','source_public_sha256',
                    'source_context_sha256','officer_uid','full_records','reported_posting'})
    uid(p['officer_uid']);P.validate_full_records(p['full_records'])
    require(p['full_records'] and p['reported_posting']==posting(p['full_records']))
    return p

def posting(records):
    service=[r for r in records if r['dataset']=='officer_service_information.csv']
    # No selection of a convenient winner when the source has multiple rows.
    if len(service)!=1:return {'status':'UNRESOLVED_SOURCE_POSTING','division':None,'station':None,'station_code':None,'source_raw_id':None}
    fields=service[0]['fields']
    return dict(status='REPORTED_SERVICE_POSTING',division=fields.get('current_division') or None,
                station=fields.get('current_station') or None,station_code=fields.get('current_station_code') or None,
                source_raw_id=service[0]['raw_record_id'])

def group_records(snapshot, officers):
    """One pass over the catalog; authority-only mentions never grant ownership."""
    groups={officer:[] for officer in officers}
    for raw,item in sorted(snapshot['catalog'].items()):
        links=[v for v in item['candidate_links'] if v['role']=='officer_nic_no']
        if not links:continue
        require(len(links)==1 and links[0]['officer_uid'] in groups and
                links[0]['state']=='CANDIDATE_NOT_ACCEPTED' and raw==item['raw_record_id'] and
                item['delivery']['complete'] is True and snapshot['bindings']['raw_bindings'].get(raw),
                'Original subject row binding differs')
        source=item['original'];columns=source['columns'];values=source['values']
        require(len(columns)==len(set(columns))==len(values))
        groups[links[0]['officer_uid']].append(dict(dataset=item['filename'],raw_record_id=raw,fields=dict(zip(columns,values))))
    for records in groups.values():
        P.validate_full_records(records)
        require(sum(r['dataset']=='officer_personal_information.csv' for r in records)==1 and
                sum(r['dataset']=='officer_service_information.csv' for r in records)==1,
                'One original personal and service row per officer required')
    return groups

def active_set(store):
    with store.transaction() as c:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_profile_sets'").fetchone():return None
        row=c.execute('SELECT generation,value FROM source_profile_sets ORDER BY generation DESC LIMIT 1').fetchone()
    if row is None:return None
    envelope=store.open('SOURCE_SET',row[0],row[1]);p=signed(envelope,store.keys,'SOURCE_SET',store.clock())
    require(set(p)=={'policy','kind','record_origin','issued_at','generation','source_public_sha256',
                    'source_context_sha256','profiles'} and p['generation']==row[0] and
            type(p['profiles']) is dict and 0<len(p['profiles'])<=10000)
    for ident,digest in p['profiles'].items():P.sha(ident);P.sha(digest)
    return p

def profile(store, officer, directory_sha):
    metadata=active_set(store)
    if metadata is None:raise AccessError(503,'PRESENTATION_NOT_CONFIGURED')
    require(metadata['source_public_sha256']==directory_sha,'Source profile directory differs')
    ident=store.index('SOURCE_PROFILE',officer)
    if ident not in metadata['profiles']:raise AccessError(503,'PRESENTATION_NOT_CONFIGURED')
    with store.transaction() as c:
        row=c.execute('SELECT value FROM source_profiles WHERE generation=? AND id=?',(metadata['generation'],ident)).fetchone()
    require(row is not None,'Source profile missing')
    envelope=store.open('SOURCE_PROFILE',[metadata['generation'],ident],row[0])
    require(P.fingerprint(envelope)==metadata['profiles'][ident],'Source profile digest differs')
    p=validate_profile(envelope,store.keys,store.clock())
    require(p['officer_uid']==officer and all(p[k]==metadata[k] for k in
            ('generation','source_public_sha256','source_context_sha256')),'Source profile scope differs')
    return deepcopy(p)

def grant_allows(grant,user,source_sha):
    if grant['user_id']!=user['user_id'] or grant['account_version']!=user['version'] or grant['source_public_sha256']!=source_sha:return False
    decision=required_protection(assignment=AssignmentProtection(grant['assignment']),
        record_classification=RecordClassification(grant['classification']),category=DisclosureCategory.PERSONNEL_DETAILS)
    return decision.level is not ProtectionLevel.WITHHOLD and (decision.level is not ProtectionLevel.RESTRICTED or grant['restricted_clearance'])

def capabilities(store,user,directory,officers):
    """Check bounded grant metadata in one transaction; avoid reading every full profile."""
    metadata=active_set(store)
    candidates=set()
    if metadata is not None:
        require(metadata['source_public_sha256']==directory['source_public_sha256'])
        candidates={o['officer_uid'] for o in officers if store.index('SOURCE_PROFILE',o['officer_uid']) in metadata['profiles']}
    with store.transaction() as c:
        legacy={r[0] for r in c.execute('SELECT id FROM presentations')}
        rows=dict(c.execute('SELECT id,value FROM disclosures'))
    candidates.update(o['officer_uid'] for o in officers if store.index('OFFICER',o['officer_uid']) in legacy)
    allowed=set()
    for officer in candidates:
        ident=store.index('GRANT',user['user_id'],officer);blob=rows.get(ident)
        if blob is None:continue
        try:grant=P.grant(store.open('GRANT',ident,blob),store.keys,store.clock())
        except Exception:continue
        if grant['officer_uid']==officer and grant_allows(grant,user,directory['source_public_sha256']):allowed.add(officer)
    return allowed

def source_workspace(p,identity):
    observed=datetime.fromtimestamp(p['issued_at'],timezone.utc).isoformat()
    return dict(identity=identity,generation=p['generation'],observed_at=observed,expires_at=None,
        coverage_start=None,coverage_end=None,findings=[],authority=[],
        anchoring={k:dict(status='NOT_CONFIGURED',receipt_sha256=None) for k in ('fabric','public','recovery')},
        can_request_review=False,accepted_state=None,full_records=deepcopy(p['full_records']),
        reported_posting=deepcopy(p['reported_posting']),display_lifecycle='RETAINED_LAST_VERIFIED_SOURCE_PROFILE',
        evidence_view='SIGNED_FULL_SOURCE_PROFILE',coverage_semantics='JOURNAL_NOT_CONNECTED',
        historical_workspace_available=False,live_research_ready=False,fresh_live_verification=False,
        public_finality_verified=False,independent_deployment_verified=False)

def publish(store,profiles,metadata,grants,*,check=lambda:None):
    """Atomic generation publication; retain all older source sets and workspace journals."""
    meta=signed(metadata,store.keys,'SOURCE_SET',store.clock());validated={}
    require(set(meta)=={'policy','kind','record_origin','issued_at','generation','source_public_sha256','source_context_sha256','profiles'} and type(meta['profiles']) is dict and 0<len(meta['profiles'])<=10000)
    for envelope in profiles:
        p=validate_profile(envelope,store.keys,store.clock());ident=store.index('SOURCE_PROFILE',p['officer_uid'])
        require(ident not in validated and all(p[k]==meta[k] for k in
            ('generation','source_public_sha256','source_context_sha256')))
        validated[ident]=envelope
    require({ident:P.fingerprint(v) for ident,v in validated.items()}==meta['profiles'],'Complete source set required')
    validated_grants=[(envelope,P.grant(envelope,store.keys,store.clock())) for envelope in grants]
    check()
    with store.transaction() as c:
        for statement in SCHEMA.split(';'):
            if statement.strip():c.execute(statement)
        previous=c.execute('SELECT MAX(generation) FROM source_profile_sets').fetchone()[0] or 0
        require(meta['generation']==previous+1,'Source generation must advance exactly once')
        for ident,envelope in validated.items():
            c.execute('INSERT INTO source_profiles VALUES(?,?,?)',(meta['generation'],ident,
                store.seal('SOURCE_PROFILE',[meta['generation'],ident],envelope)))
        for envelope,grant in validated_grants:
            ident=store.index('GRANT',grant['user_id'],grant['officer_uid'])
            require(store.index('SOURCE_PROFILE',grant['officer_uid']) in validated and grant['source_public_sha256']==meta['source_public_sha256'])
            previous=c.execute('SELECT issued,value FROM disclosures WHERE id=?',(ident,)).fetchone()
            if previous:
                try:old=P.grant(store.open('GRANT',ident,previous[1]),store.keys,store.clock())
                except Exception:old=None
                # Keep current valid review/disclosure permissions for recorded workspaces.
                if old and old['account_version']==grant['account_version'] and old['source_public_sha256']==grant['source_public_sha256']:continue
                require(grant['issued_at']>previous[0],'Disclosure issuance must advance')
            c.execute('INSERT OR REPLACE INTO disclosures VALUES(?,?,?)',(ident,grant['issued_at'],store.seal('GRANT',ident,envelope)))
        c.execute('INSERT INTO source_profile_sets VALUES(?,?)',(meta['generation'],store.seal('SOURCE_SET',meta['generation'],metadata)))
        store.event(c,dict(kind='FULL_SOURCE_PROFILES_IMPORTED',generation=meta['generation'],officers=len(validated)))
        check() # Any expired permit or changed source rolls back the whole generation.
