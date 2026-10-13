"""Read-only authority evaluation over authenticated retained UI evidence.

Present-day NIC matching supplies candidates only. It never establishes historical
identity, governing rules, delegation, source completeness or police authority.
Explicit assessed inputs come only from the separate pinned operator signer.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import date
import json
from app.access.policy import require
from app.access import research_policy as P
from app.identity.action_actor_history import ActorHistory
from app.identity.action_authority_integration import ActionAuthority,AuthorityAssessment,StateAssessment
from app.identity.temporal_authority import Fact,ActorState,Rule,Delegation
from app.identity.reported_authority_actions import review_actions,ROUTES,HEADERS
from app.identity.bitemporal_reconstruction import query
from app.identity.protected_commitment import digest
from app.identity.run_research_algorithms import json_value

POLICY='RETAINED_AUTHORITY_WORKFLOW_V1'
MAX_ACTIONS=500
MAX_ACTORS=128

def inventory(packet,directory):
    """Retained row provenance is named explicitly; missing originals are not invented."""
    require(packet.get('kind')=='PRESENTATION','Recorded workspace required')
    references={}
    for version in packet['history']['versions']:
        try:
            reference=json.loads(version['claim']['source_reference'])
            if type(reference) is dict and 'raw_record_id' in reference:references[reference['raw_record_id']]=reference
        except (TypeError,ValueError):continue
    identities={}
    for officer in directory['officers']:
        identities.setdefault(officer['nic'].strip().casefold(),[]).append(officer['officer_uid'])
    rows={};pin=P.fingerprint({'policy':POLICY,'officer_uid':packet['officer_uid'],'source_public_sha256':packet['source_public_sha256']})
    for row in packet.get('full_records',[]):
        filename=row['dataset']
        if filename not in ROUTES:continue
        fields=row['fields'];require(set(fields)==HEADERS[filename],'Retained action schema differs')
        raw=row['raw_record_id'];reference=references.get(raw)
        original=dict(columns=list(fields),values=list(fields.values()))
        if reference is not None:
            require(reference.get('filename')==filename and
                dict(zip(reference['original']['columns'],reference['original']['values']))==fields,
                'Retained action row differs from historical evidence')
            original=reference['original'];provenance=reference['provenance'];assertion=reference['assertion']
        else:
            provenance={'retained_workspace_sha256':pin,'provenance_semantics':'SIGNED_RETAINED_ROW_NOT_ORIGINAL_CATALOG'}
            assertion={'retained_row_sha256':digest(row)}
        links=[dict(officer_uid=packet['officer_uid'],role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')]
        for _,actor_field,_ in ROUTES[filename]:
            if actor_field is None:continue
            for officer in identities.get(fields[actor_field].strip().casefold(),[]):
                link=dict(officer_uid=officer,role=actor_field,state='CANDIDATE_NOT_ACCEPTED')
                if link not in links:links.append(link)
        rows[raw]=dict(raw_record_id=raw,filename=filename,classification='UNASSESSED',delivery={'complete':True},
            candidate_links=links,original=original,provenance=provenance,assertion=assertion)
    bindings={raw:[{'signed_retained_row_sha256':digest(row),'workspace_sha256':pin}]
        for raw,row in rows.items()}
    actions=review_actions(rows,bindings);require(len(actions)<=MAX_ACTIONS,'Bounded authority action inventory required')
    return {action_reference(packet,a):a for a in actions}

def action_reference(packet,action):
    return digest(dict(policy=POLICY,officer_uid=packet['officer_uid'],source_public_sha256=packet['source_public_sha256'],
        action_digest=digest(json_value(asdict(action)))))

def assessment_actors(packet):
    return {s.state.actor_uid for s in packet.states}|{d.issuer_uid for d in packet.delegations}|{d.recipient_uid for d in packet.delegations}

def actor_history(store,packet,directory,actions,known,extra_actors=()):
    """Use recorded claim heads, not current ranks, for each actor/date reconstruction."""
    candidates={uid for a in actions for uid in a.actor_candidates}|set(extra_actors)
    for officer in candidates:P.uid(officer)
    require(len(candidates)<=MAX_ACTORS,'Authority actor bound exceeded')
    history=ActorHistory({o['officer_uid']:{} for o in directory['officers']},{},known,packet['source_public_sha256'])
    pins={};missing=[]
    for officer in sorted(candidates):
        try:
            source=store.get_packet(officer)
            require(source['source_public_sha256']==packet['source_public_sha256'])
            require(P.instant(source['observed_at'])<=known,'Actor copy was not yet recorded')
            h=P.history(source['history'],officer);at=min(known,h.coverage_end)
            result=query(h,effective_on=known.date(),known_at=at)
        except Exception:
            missing.append(officer);history.buckets.pop(officer,None);continue
        claims=tuple(v.claim for v in result.visible_versions if not v.withdrawn)
        history.claims[officer]=claims
        history.inventory_ids[officer]=digest(dict(policy=POLICY,officer_uid=officer,
            workspace_sha256=P.fingerprint(source),known_at=at.isoformat(),claims=json_value([asdict(c) for c in claims])))
        pins[officer]=P.fingerprint(source)
    return history,pins,missing

def fact(value):
    require(type(value) is dict and set(value)=={'value','assessment','evidence'})
    require(type(value['evidence']) is list and len(value['evidence'])<=128)
    for reference in value['evidence']:P.text(reference,200)
    require(type(value['value']) in (str,bool,type(None)))
    if type(value['value']) is str:P.text(value['value'],1200)
    return Fact(value['value'],value['assessment'],tuple(value['evidence']))

def assessment(value):
    """Strict typed decoding; no rules or powers derived from ranks."""
    require(type(value) is dict and set(value)==set(AuthorityAssessment.__dataclass_fields__))
    for field in ('states','rules','delegations','evidence_digests'):
        require(type(value[field]) is list and len(value[field])<=128,'Bounded assessment collection required')
    states=[]
    for item in value['states']:
        require(set(item)=={'state_id','state'})
        s=item['state'];require(set(s)==set(ActorState.__dataclass_fields__))
        states.append(StateAssessment(item['state_id'],ActorState(s['actor_uid'],date.fromisoformat(s['on']),
            **{k:fact(s[k]) for k in ('identity','rank','role','active','scope')})))
    rules=[];delegations=[]
    for r in value['rules']:
        require(set(r)==set(Rule.__dataclass_fields__))
        for field in ('powers','ranks','roles','actor_scopes','target_scopes','evidence'):
            require(type(r[field]) is list and len(r[field])<=128)
            for label in r[field]:P.text(label,200)
        P.text(r['rule_id'],200)
        rules.append(Rule(**{**r,**{k:tuple(r[k]) for k in ('powers','ranks','roles','actor_scopes','target_scopes','evidence')},
            'start':date.fromisoformat(r['start']),'end':date.fromisoformat(r['end']) if r['end'] else None}))
    for d in value['delegations']:
        require(set(d)==set(Delegation.__dataclass_fields__))
        for field in ('powers','target_scopes','evidence'):
            require(type(d[field]) is list and len(d[field])<=128)
            for label in d[field]:P.text(label,200)
        P.text(d['delegation_id'],200);P.text(d['parent_id'],200)
        delegations.append(Delegation(**{**d,**{k:tuple(d[k]) for k in ('powers','target_scopes','evidence')},
            **{k:date.fromisoformat(d[k]) if d[k] else None for k in ('issued_on','start','end','revoked_from')}}))
    require(len(states)<=128 and len(rules)<=128 and len(delegations)<=128 and len(value['evidence_digests'])<=128)
    return AuthorityAssessment(**{**value,**{k:fact(value[k]) for k in ('identity','date_semantics','coverage')},
        'states':tuple(states),'rules':tuple(rules),'delegations':tuple(delegations),
        'evidence_digests':tuple(tuple(v) for v in value['evidence_digests'])})

def evidence_references(packet):
    facts=[packet.identity,packet.date_semantics,packet.coverage]
    facts.extend(getattr(s.state,k) for s in packet.states for k in ('identity','rank','role','active','scope'))
    refs={r for f in facts for r in f.evidence}
    refs.update(r for item in (*packet.rules,*packet.delegations) for r in item.evidence)
    require(refs and refs<=dict(packet.evidence_digests).keys(),'Assessment references missing evidence')
    return refs

def evaluate(store,packet,directory,actions,known,selected=None):
    extra=set().union(*(assessment_actors(assessment(p['assessment'])) for p in (selected or {}).values()))
    history,pins,missing=actor_history(store,packet,directory,actions.values(),known,extra)
    results={}
    for ref,action in actions.items():
        typed=None if selected is None or ref not in selected else assessment(selected[ref]['assessment'])
        if typed is not None:
            needed={u for a in actions.values() for u in a.actor_candidates}|assessment_actors(typed)
            require(not needed.intersection(missing) and selected[ref]['actor_packets']=={u:pins[u] for u in needed},'Assessment actor versions changed or unavailable')
            evidence_references(typed)
        results[ref]=ActionAuthority(history).review(action,typed)
    return results,history,pins
