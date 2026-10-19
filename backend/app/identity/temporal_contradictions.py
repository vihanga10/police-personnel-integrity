"""Find reported temporal disagreements without declaring source truth.

Different event dates normally represent a transition, not a contradiction.
Snapshots/uncertain dates are unresolved comparisons. Membership and provenance
are retained; source agreement does not establish independent corroboration.
"""
from dataclasses import dataclass, field
import json
from itertools import combinations
from app.identity.historical_reconstruction import Claim, require

POLICY = 'REPORTED_TEMPORAL_CONTRADICTIONS_V1'


@dataclass(frozen=True)
class Comparison:
    dimension: str
    status: str
    reasons: tuple[str, ...]
    claim_ids: tuple[str, str] = field(repr=False)
    source_references: tuple[str, str] = field(repr=False)
    destination_digests: tuple[str, str] = field(repr=False)
    cross_source: bool
    policy: str = POLICY
    accepted_contradiction: bool = False


def decoded(claim):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'Repeated comparison value field.')
            result[k]=v
        return result
    try:
        value=json.loads(claim.value,object_pairs_hook=unique)
        reference=json.loads(claim.source_reference,object_pairs_hook=unique)
    except (ValueError,TypeError):
        raise ValueError('Comparison evidence shape differs.') from None
    require(isinstance(value,dict) and all(isinstance(k,str) and isinstance(v,str) for k,v in value.items()),
        'Comparison value shape differs.')
    require(isinstance(reference,dict) and isinstance(reference.get('filename'),str) and
        isinstance(reference.get('provenance'),dict) and
        reference['provenance'].get('reported_source') in {'PF_REGISTRY','POLICE_HR_IS','SRB'},
        'Reported supplying source required.')
    return value,reference['provenance']['reported_source']


def comparable(a,av,b,bv):
    """Return aligned scalar values; never equate police and regimental types."""
    if not av or not bv or any(not v.strip() for v in (*av.values(),*bv.values())):
        return None,'REPORTED_VALUE_MISSING'
    if a.dimension=='police_number':
        if set(av)!= {'police_no','number_type'} or set(bv)!= {'police_no','number_type'}:
            return None,'NUMBER_TYPE_OR_FIELD_APPLICABILITY_UNKNOWN'
        if not av['number_type'].strip() or not bv['number_type'].strip():
            return None,'NUMBER_TYPE_OR_FIELD_APPLICABILITY_UNKNOWN'
        if av['number_type']!=bv['number_type']:return False,'DIFFERENT_REPORTED_NUMBER_TYPES'
        return (av['police_no'],bv['police_no']),None
    if a.dimension=='rank':
        if set(av)==set(bv)=={'to_rank'}:return (av['to_rank'],bv['to_rank']),None
        return None,'RANK_FIELD_APPLICABILITY_UNKNOWN'
    if a.dimension=='restrictions':
        if 'restriction_id' not in av or 'restriction_id' not in bv or not av['restriction_id'].strip():
            return None,'RESTRICTION_LINKAGE_UNKNOWN'
        if av['restriction_id']!=bv['restriction_id']:return False,'DIFFERENT_RESTRICTION_CLAIMS_CAN_COEXIST'
    if set(av)!=set(bv):return None,'FIELD_APPLICABILITY_UNKNOWN'
    return (json.dumps(av,sort_keys=True),json.dumps(bv,sort_keys=True)),None


def compare_claims(officer_uid,claims,*,on=None):
    """Pair exact subject claims; time comparisons use reported dates only.

    Optional on limits dated future reports. Review/snapshot evidence stays
    present because its historical applicability is not established.
    """
    from datetime import date
    require(on is None or type(on) is date,'Comparison calendar date required.')
    claims=tuple(claims)
    require(all(isinstance(c,Claim) and c.officer_uid==officer_uid for c in claims),'Comparison subject differs.')
    require(len({c.claim_id for c in claims})==len(claims),'Repeated comparison claim.')
    selected=[c for c in claims if on is None or c.start is None or c.start<=on or c.mode in {'REVIEW','SNAPSHOT'}]
    values={c.claim_id:decoded(c) for c in selected}
    results=[]
    for a,b in combinations(sorted(selected,key=lambda c:c.claim_id),2):
        if a.dimension!=b.dimension:continue
        av,sa=values[a.claim_id];bv,sb=values[b.claim_id]
        pair,reason=comparable(a,av,b,bv)
        if pair is False:continue
        reasons=[]
        if reason:reasons.append(reason)
        if pair is not None and pair[0]==pair[1]:continue
        uncertain = (a.mode in {'SNAPSHOT','REVIEW'} or b.mode in {'SNAPSHOT','REVIEW'} or
            a.start is None or b.start is None or a.issues or b.issues)
        if uncertain:
            reasons.append('HISTORICAL_APPLICABILITY_UNASSESSED');status='UNRESOLVED_COMPARISON'
        elif pair is None:
            status='UNRESOLVED_COMPARISON'
        elif a.mode==b.mode=='EVENT':
            if a.start!=b.start:continue
            reasons.append('SAME_REPORTED_EVENT_DATE_DIFFERENT_VALUES');status='REPORTED_CONTRADICTION_CANDIDATE'
        elif a.mode==b.mode=='INTERVAL':
            start=max(a.start,b.start)
            ends=[x for x in (a.end,b.end) if x is not None]
            end=min(ends) if ends else None
            if end is not None and start>end:continue
            if end==start:
                reasons.append('ENDPOINT_SEMANTICS_UNASSESSED');status='UNRESOLVED_COMPARISON'
            else:
                reasons.append('OVERLAPPING_REPORTED_INTERVALS_DIFFERENT_VALUES');status='REPORTED_CONTRADICTION_CANDIDATE'
        else:
            reasons.append('EVENT_INTERVAL_PRECEDENCE_UNASSESSED');status='UNRESOLVED_COMPARISON'
        reasons.extend(('HISTORICAL_IDENTITY_UNASSESSED','REPORTED_DATE_SEMANTICS_UNASSESSED',
            'SOURCE_INDEPENDENCE_UNVERIFIED','CLASSIFICATION_UNASSESSED'))
        results.append(Comparison(a.dimension,status,tuple(sorted(set(reasons))),
            (a.claim_id,b.claim_id),(a.source_reference,b.source_reference),
            (a.destination_digest,b.destination_digest),sa!=sb))
    return tuple(results)
