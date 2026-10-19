"""Pure point-in-time comparisons of reported version heads; no truth/authentication claim.

Authenticate the history and freshness before research use. V1 comparisons remain
unchanged. Outcomes concern exact reported fields, not accepted personnel state.
"""
from dataclasses import dataclass, field, asdict
from itertools import combinations
import json
from app.identity.bitemporal_reconstruction import query, canonical
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY='REPORTED_BITEMPORAL_CONTRADICTIONS_V2'
CANDIDATE='REPORTED_CONTRADICTION_CANDIDATE'
UNRESOLVED='UNRESOLVED_COMPARISON'
AGREEMENT='REPORTED_AGREEMENT'
NO_CONFLICT='NO_REPORTED_CONFLICT_AT_POINT'
STATUSES=(CANDIDATE,UNRESOLVED,AGREEMENT,NO_CONFLICT)
LIMITS=('HISTORICAL_IDENTITY_UNASSESSED','REPORTED_DATE_SEMANTICS_UNASSESSED',
    'SOURCE_INDEPENDENCE_UNVERIFIED','CLASSIFICATION_UNASSESSED')


@dataclass(frozen=True)
class PairComparison:
    dimension: str
    status: str
    reasons: tuple[str,...]
    claim_ids: tuple[str,str] = field(repr=False)
    version_ids: tuple[str,str] = field(repr=False)
    source_references: tuple[str,str] = field(repr=False)
    destination_digests: tuple[str,str] = field(repr=False)
    receipt_digests: tuple[str,str] = field(repr=False)
    cross_reported_source: bool | None
    accepted_contradiction: bool = False


@dataclass(frozen=True)
class ComparisonResult:
    policy: str
    effective_on: object
    known_at: object
    comparisons: tuple[PairComparison,...] = field(repr=False)
    visible_version_ids: tuple[str,...] = field(repr=False)
    exclusions: tuple[tuple[str,str],...] = field(repr=False)
    query_digest: str
    comparison_digest: str
    receipt_authenticity_claim: bool = False
    accepted_state: None = None
    source_change_completeness_established: bool = False


def _json(text):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'Repeated reported evidence field.')
            result[k]=v
        return result
    try:result=json.loads(text,object_pairs_hook=unique)
    except (TypeError,ValueError):raise ValueError('Reported comparison evidence shape differs.') from None
    require(type(result) is dict,'Reported comparison evidence object required.')
    return result


def _decode(claim):
    value=_json(claim.value);reference=_json(claim.source_reference)
    require(all(isinstance(k,str) and isinstance(v,str) for k,v in value.items()),'Reported scalar string fields required.')
    require(isinstance(reference.get('filename'),str) and reference['filename'].strip() and
        type(reference.get('provenance')) is dict,'Complete reported source reference required.')
    label=reference['provenance'].get('reported_source')
    require(label is None or isinstance(label,str),'Reported source label shape differs.')
    return value,label if label and label.strip() else None


def _pair(a,av,b,bv,on):
    # Date/interpretation uncertainty precedes exact-value agreement. No snapshot backdating.
    if a.mode in ('SNAPSHOT','REVIEW') or b.mode in ('SNAPSHOT','REVIEW') or a.start is None or b.start is None or a.issues or b.issues:
        return UNRESOLVED,('HISTORICAL_APPLICABILITY_UNASSESSED',*a.issues,*b.issues)
    if a.mode!=b.mode:return UNRESOLVED,('EVENT_INTERVAL_PRECEDENCE_UNASSESSED',)
    if a.mode=='INTERVAL' and (a.end==on or b.end==on):
        return UNRESOLVED,('ENDPOINT_SEMANTICS_UNASSESSED',)
    if not av or not bv or any(not v.strip() for v in (*av.values(),*bv.values())):
        return UNRESOLVED,('REPORTED_VALUE_MISSING',)
    if a.dimension=='rank' and not set(av)==set(bv)=={'to_rank'}:
        return UNRESOLVED,('RANK_FIELD_APPLICABILITY_UNKNOWN',)
    if a.dimension=='police_number':
        if not set(av)==set(bv)=={'police_no','number_type'}:
            return UNRESOLVED,('NUMBER_TYPE_OR_FIELD_APPLICABILITY_UNKNOWN',)
        if av['number_type']!=bv['number_type']:
            if av['number_type'].strip().casefold()==bv['number_type'].strip().casefold():
                return UNRESOLVED,('NUMBER_TYPE_EQUIVALENCE_UNASSESSED',)
            return NO_CONFLICT,('DIFFERENT_REPORTED_NUMBER_TYPES',)
    if a.dimension=='posting':
        return UNRESOLVED,('POSTING_DATE_AND_UNIT_IDENTITY_UNASSESSED',)
    if a.dimension=='service_status':
        return UNRESOLVED,('SERVICE_STATUS_HISTORICAL_APPLICABILITY_UNASSESSED',)
    if a.dimension=='restrictions':
        if 'restriction_id' not in av or 'restriction_id' not in bv:
            return UNRESOLVED,('RESTRICTION_LINKAGE_UNKNOWN',)
        if not set(av)==set(bv)=={'restriction_id','restriction_category','restriction_effect','restriction_scope'}:
            return UNRESOLVED,('RESTRICTION_FIELD_APPLICABILITY_UNKNOWN',)
        if av['restriction_id']!=bv['restriction_id']:
            if av['restriction_id'].strip().casefold()==bv['restriction_id'].strip().casefold():
                return UNRESOLVED,('RESTRICTION_ID_EQUIVALENCE_UNASSESSED',)
            return NO_CONFLICT,('DIFFERENT_RESTRICTION_CLAIMS_CAN_COEXIST',)
    if set(av)!=set(bv):return UNRESOLVED,('FIELD_APPLICABILITY_UNKNOWN',)
    if a.mode=='EVENT' and a.start!=b.start:
        return NO_CONFLICT,('DIFFERENT_REPORTED_EVENT_DATES_NO_SAME_EVENT_CONFLICT',)
    if av==bv:return AGREEMENT,('EXACT_REPORTED_FIELDS_AGREE',)
    if all(av[k].strip().casefold()==bv[k].strip().casefold() for k in av):
        return UNRESOLVED,('VALUE_EQUIVALENCE_UNASSESSED',)
    return CANDIDATE,('SAME_REPORTED_EVENT_DATE_DIFFERENT_VALUES' if a.mode=='EVENT'
        else 'OVERLAPPING_REPORTED_INTERVALS_AT_POINT_DIFFERENT_VALUES',)


def compare_history(history,*,effective_on,known_at):
    """Only nonwithdrawn heads visible at known_at; expired/future dated claims excluded.

    Empty output does not prove agreement or absence of contradiction. For events,
    unequal effective dates are not presumed competing state or source precedence.
    Reported source labels are descriptive, never authenticated independent custody.
    """
    result=query(history,effective_on=effective_on,known_at=known_at)
    selected=[];excluded=[];decoded={}
    for v in result.visible_versions:
        c=v.claim
        if v.withdrawn:excluded.append((v.version_id,'WITHDRAWN'));continue
        decoded[v.version_id]=_decode(c)
        uncertain=c.mode in ('SNAPSHOT','REVIEW') or c.start is None or bool(c.issues)
        if not uncertain and c.start>effective_on:excluded.append((v.version_id,'FUTURE'));continue
        if not uncertain and c.mode=='INTERVAL' and c.end is not None and c.end<effective_on:
            excluded.append((v.version_id,'EXPIRED'));continue
        selected.append(v)
    comparisons=[]
    for a,b in combinations(sorted(selected,key=lambda v:v.claim.claim_id),2):
        if a.claim.dimension!=b.claim.dimension:continue
        av,sa=decoded[a.version_id];bv,sb=decoded[b.version_id]
        status,reasons=_pair(a.claim,av,b.claim,bv,effective_on)
        if effective_on>result.known_at.date():
            status=UNRESOLVED;reasons=(*reasons,'REQUEST_AFTER_KNOWLEDGE_CANNOT_ESTABLISH_FUTURE_STATE')
        if a.claim.mode==b.claim.mode=='INTERVAL' and (a.claim.end is None or b.claim.end is None):
            reasons=(*reasons,'OPEN_END_DOES_NOT_PROVE_CONTINUING_VALIDITY')
        attribution=() if sa is not None and sb is not None else ('SOURCE_ATTRIBUTION_UNASSESSED',)
        comparisons.append(PairComparison(a.claim.dimension,status,tuple(sorted(set((*reasons,*LIMITS,*attribution)))),
            (a.claim.claim_id,b.claim.claim_id),(a.version_id,b.version_id),
            (a.claim.source_reference,b.claim.source_reference),(a.claim.destination_digest,b.claim.destination_digest),
            (a.receipt_digest,b.receipt_digest),None if sa is None or sb is None else sa!=sb))
    payload=dict(policy=POLICY,effective_on=effective_on,known_at=result.known_at,query_digest=result.query_digest,
        comparisons=[asdict(c) for c in comparisons],exclusions=excluded,
        visible_version_ids=[v.version_id for v in result.visible_versions])
    fingerprint=digest(json.loads(json.dumps(payload,default=canonical,sort_keys=True)))
    return ComparisonResult(POLICY,effective_on,result.known_at,tuple(comparisons),
        tuple(v.version_id for v in result.visible_versions),tuple(excluded),result.query_digest,fingerprint)
