"""Opaque full-prefix commitments for application research findings, not police authority.

Pure generation and authenticated retained selection. Publication requires a fresh
original-source gate plus independently verified destination receipts; preparation
by itself is not blockchain anchoring or independent witnessing.
"""
import hashlib,hmac
from copy import deepcopy
from datetime import datetime,timezone
from app.access.policy import require,encoded,uid
from app.access import review_workflow as W,research_policy as P
from app.identity.protected_commitment import merkle_root

POLICY='APPLICATION_FINDINGS_COMMITMENTS_V1'

def generate(selection,content_key,publication_key,*,salt):
    require(type(content_key) is bytes and type(publication_key) is bytes and len(content_key)==len(publication_key)==32 and content_key!=publication_key)
    require(type(salt) is bytes and len(salt)==32)
    require(set(selection)=={'policy','officer_uid','source_public_sha256','entries','policies','sources'} and selection['policy']==POLICY)
    uid(selection['officer_uid']);P.sha(selection['source_public_sha256'])
    require(selection['entries'],'Empty findings prefix cannot be published')
    private_prefix=P.fingerprint(selection)
    handle=lambda domain,value:hmac.new(publication_key,encoded([POLICY,domain,salt.hex(),value]),hashlib.sha256).hexdigest()
    commit=lambda domain,value:hmac.new(content_key,encoded([POLICY,domain,salt.hex(),value]),hashlib.sha256).hexdigest()
    publication=handle('PUBLICATION',private_prefix)
    leaves=[]
    for entry in selection['entries']:
        leaves.append(dict(kind='APPLICATION_FINDING_ENTRY',handle=handle('ENTRY',P.fingerprint(entry)),commitment=commit('ENTRY',entry)))
    leaves.sort(key=lambda x:x['handle'])
    leaves.append(dict(kind='APPLICATION_FINDING_CONTEXT',handle=publication,commitment=commit('COMPLETE_PREFIX',selection)))
    public=dict(policy=POLICY,publication_id=publication,entries=leaves[:-1],history_commitment=leaves[-1]['commitment'],merkle_root=merkle_root(leaves))
    public['publication_commitment']=commit('PUBLICATION',public)
    return public

def select(store,officer):
    """Retain all records, not only approved heads. Capture only exact signed sources.

    Old Priority 3 rows are backfilled only when their source hash equals an actual
    currently retained signed presentation. Missing older sources are a hard stop.
    """
    uid(officer);W.initialize(store)
    with store.transaction() as c:
        all_rows=W.entries(store,c);all_policies=W.policies(store,c)
        rows=[e for e in all_rows if e['input']['officer_uid']==officer]
        require(rows,'No application findings recorded for this officer')
        W.state(all_rows)
        sources={};policy_refs={e['policy_reference'] for e in rows}
        for sha in {e['source_sha256'] for e in rows}:
            row=c.execute('SELECT value FROM application_review_sources WHERE sha=?',(sha,)).fetchone()
            if row:envelope=store.open('APPLICATION_REVIEW_SOURCE',sha,row[0])
            else:
                ident=store.index('OFFICER',officer);current=c.execute('SELECT value FROM presentations WHERE id=?',(ident,)).fetchone()
                require(current is not None,'Missing historical presentation')
                envelope=store.open('PACKET',ident,current[0])
                require(P.fingerprint(envelope['payload'])==sha,'Historical signed source missing; do not fabricate or reset history')
                c.execute('INSERT INTO application_review_sources VALUES(?,?)',(sha,store.seal('APPLICATION_REVIEW_SOURCE',sha,envelope)))
                store.event(c,dict(kind='APPLICATION_REVIEW_SOURCE_ARCHIVED',officer_uid=officer,source_sha256=sha))
            packet=P.packet(envelope,store.keys,store.clock())
            require(packet['officer_uid']==officer and packet.get('record_origin')=='GENERATED_RESEARCH_RECORDS' and P.fingerprint(packet)==sha)
            require(all(P.instant(e['recorded_at'])>=P.instant(packet['observed_at']) for e in rows if e['source_sha256']==sha),'Recorded source chronology differs')
            sources[sha]=envelope
        public={s['payload']['source_public_sha256'] for s in sources.values()};require(len(public)==1,'Source publication changed across findings history')
        return dict(policy=POLICY,officer_uid=officer,source_public_sha256=next(iter(public)),entries=deepcopy(rows),
            policies=[deepcopy(p) for p in all_policies if P.fingerprint(p) in policy_refs],sources=deepcopy(sources))

def fabric_payload(public):
    return dict(policy='FINDINGS_FABRIC_ANCHOR_V1',namespace='findings-anchor-v1',publication_id=public['publication_id'],
        public_sha256=P.fingerprint(public),merkle_root=public['merkle_root'],publication_commitment=public['publication_commitment'])
