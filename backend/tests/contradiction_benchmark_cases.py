"""Hand-authored toy annotations; require independent review before research evaluation."""
from dataclasses import replace
from datetime import date, datetime, timezone, timedelta
from uuid import UUID
import json
from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.contradiction_evaluation import BenchmarkCase, ExpectedPair
from app.identity.bitemporal_contradictions import CANDIDATE, UNRESOLVED, AGREEMENT, NO_CONFLICT

UID=str(UUID(int=1));T0=datetime(2026,10,1,tzinfo=timezone.utc);T1=T0+timedelta(days=1)
T2=T1+timedelta(days=1);ON=date(2024,6,1)


def claim(key='a',value=None,source='PF_REGISTRY',**changes):
    provenance={} if source is None else dict(reported_source=source)
    fields=dict(claim_id=key,officer_uid=UID,dimension='rank',value=json.dumps(value or {'to_rank':'fixture-A'}),
        source_reference=json.dumps(dict(filename='fixture.csv',provenance=provenance)),destination_digest='a'*64,
        start=date(2024,1,1))
    fields.update(changes);return Claim(**fields)


def version(c,key=None,**changes):
    fields=dict(version_id=key or 'version-'+c.claim_id,claim=c,source_key='fixture:'+c.claim_id,
        recorded_at=T0,receipt_reference='fixture-receipt',receipt_digest='b'*64)
    fields.update(changes);return EvidenceVersion(**fields)


def history(*versions):
    return RecordingHistory(UID,T0,T2,'fixture-coverage','c'*64,tuple(versions))


def number(key='a',number='fixture-1',kind='police',**changes):
    return claim(key,{'police_no':number,'number_type':kind},dimension='police_number',mode='INTERVAL',**changes)


def benchmark_cases():
    # Expected labels/reasons are explicit annotations, not computed from the detector.
    a=claim();b=claim('b',{'to_rank':'fixture-B'},source='POLICE_HR_IS')
    cases=[]
    def add(key,claims,status,reason,on=ON):
        expected=() if status is None else (ExpectedPair(('a','b'),status,(reason,)),)
        cases.append(BenchmarkCase(key,history(*(version(c) for c in claims)),on,T0,expected))
    add('same-event-different-rank',(a,b),CANDIDATE,'SAME_REPORTED_EVENT_DATE_DIFFERENT_VALUES')
    add('exact-agreement',(a,claim('b')),AGREEMENT,'EXACT_REPORTED_FIELDS_AGREE')
    add('normal-transition',(a,replace(b,start=date(2024,2,1))),NO_CONFLICT,'DIFFERENT_REPORTED_EVENT_DATES_NO_SAME_EVENT_CONFLICT')
    add('equal-snapshot-is-unresolved',(a,claim('b',mode='SNAPSHOT',start=None)),UNRESOLVED,'HISTORICAL_APPLICABILITY_UNASSESSED')
    add('uncertain-effective-date',(a,replace(b,issues=('REPORTED_DATE_INVALID',))),UNRESOLVED,'REPORTED_DATE_INVALID')
    add('rank-field-ambiguity',(a,claim('b',{'current_rank':'fixture-B'})),UNRESOLVED,'RANK_FIELD_APPLICABILITY_UNKNOWN')
    add('lexical-equivalence',(a,claim('b',{'to_rank':' FIXTURE-A '})),UNRESOLVED,'VALUE_EQUIVALENCE_UNASSESSED')
    add('blank-rank',(a,claim('b',{'to_rank':''})),UNRESOLVED,'REPORTED_VALUE_MISSING')
    add('overlapping-numbers',(number(),number('b',number='fixture-2')),CANDIDATE,'OVERLAPPING_REPORTED_INTERVALS_AT_POINT_DIFFERENT_VALUES')
    add('different-number-types',(number(),number('b',number='fixture-2',kind='regimental')),NO_CONFLICT,'DIFFERENT_REPORTED_NUMBER_TYPES')
    add('unknown-number-type',(number(),number('b',number='fixture-2',kind='')),UNRESOLVED,'REPORTED_VALUE_MISSING')
    add('number-type-spelling',(number(),number('b',number='fixture-2',kind='POLICE')),UNRESOLVED,'NUMBER_TYPE_EQUIVALENCE_UNASSESSED')
    add('shared-end-day',(number(end=ON),number('b',number='fixture-2',start=ON)),UNRESOLVED,'ENDPOINT_SEMANTICS_UNASSESSED')
    add('expired-interval',(number(end=date(2024,5,31)),number('b',number='fixture-2')),None,None)
    add('future-event',(a,replace(b,start=date(2025,1,1))),None,None)
    def restriction(key,id,effect):return claim(key,{'restriction_id':id,'restriction_category':'fixture-category',
        'restriction_effect':effect,'restriction_scope':'fixture-scope'},dimension='restrictions',mode='INTERVAL')
    add('coexisting-restrictions',(restriction('a','one','A'),restriction('b','two','B')),NO_CONFLICT,'DIFFERENT_RESTRICTION_CLAIMS_CAN_COEXIST')
    add('same-restriction-different-effect',(restriction('a','one','A'),restriction('b','one','B')),CANDIDATE,'OVERLAPPING_REPORTED_INTERVALS_AT_POINT_DIFFERENT_VALUES')
    add('event-interval-ambiguity',(a,replace(b,mode='INTERVAL')),UNRESOLVED,'EVENT_INTERVAL_PRECEDENCE_UNASSESSED')
    add('unknown-custodian',(a,claim('b',{'to_rank':'fixture-B'},source=None)),CANDIDATE,'SOURCE_ATTRIBUTION_UNASSESSED')
    add('npc-label-is-descriptive',(a,claim('b',{'to_rank':'fixture-B'},source='NPC')),CANDIDATE,'SOURCE_INDEPENDENCE_UNVERIFIED')
    return tuple(cases)
