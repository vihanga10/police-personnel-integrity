"""Explicitly annotated fixture evaluation; not independent research ground truth."""
from dataclasses import dataclass, field
from app.identity.bitemporal_contradictions import compare_history, STATUSES, CANDIDATE, UNRESOLVED
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require

POLICY='ANNOTATED_REPORTED_CONTRADICTION_EVALUATION_V1'


@dataclass(frozen=True)
class ExpectedPair:
    claim_ids: tuple[str,str] = field(repr=False)
    status: str
    required_reasons: tuple[str,...]

    def __post_init__(self):
        require(type(self.claim_ids) is tuple and len(self.claim_ids)==2 and
            all(isinstance(v,str) and v for v in self.claim_ids) and self.claim_ids[0]<self.claim_ids[1],
            'Canonical distinct annotated claim pair required.')
        require(self.status in STATUSES and type(self.required_reasons) is tuple and
            all(isinstance(r,str) and r for r in self.required_reasons),'Annotated outcome differs.')


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    history: object = field(repr=False)
    effective_on: object
    known_at: object
    expected: tuple[ExpectedPair,...] = field(repr=False)


def evaluate_cases(cases):
    cases=tuple(cases)
    require(bool(cases) and all(type(c) is BenchmarkCase and isinstance(c.case_id,str) and c.case_id.strip()
        for c in cases) and len({c.case_id for c in cases})==len(cases),'Unique nonempty benchmark cases required.')
    labels=(*STATUSES,'NOT_EMITTED');matrix={e:{p:0 for p in labels} for e in STATUSES}
    explanations=0;reason_total=0;total=0;exact=0;predicted_unresolved=0;case_digests=[]
    for case in sorted(cases,key=lambda c:c.case_id):
        require(type(case.expected) is tuple and all(type(e) is ExpectedPair for e in case.expected),
            'Explicit immutable benchmark annotations required.')
        gold={e.claim_ids:e for e in case.expected}
        require(len(gold)==len(case.expected),'Repeated annotated pair.')
        result=compare_history(case.history,effective_on=case.effective_on,known_at=case.known_at)
        visible={v.claim.claim_id:v.claim for v in case.history.versions
            if v.version_id in result.visible_version_ids and not v.withdrawn}
        require(all(all(k in visible for k in pair) and visible[pair[0]].dimension==visible[pair[1]].dimension
            for pair in gold),'Benchmark pair references unavailable or different-dimension evidence.')
        predicted={c.claim_ids:c for c in result.comparisons}
        require(set(predicted)<=set(gold),'Prediction lacks an explicit benchmark annotation.')
        for pair,e in gold.items():
            actual=predicted.get(pair);status=actual.status if actual else 'NOT_EMITTED'
            matrix[e.status][status]+=1;total+=1
            predicted_unresolved+=status==UNRESOLVED
            exact+=status==e.status
            if e.required_reasons:
                reason_total+=1
                explanations+=bool(actual and set(e.required_reasons)<=set(actual.reasons))
        case_digests.append(dict(case_id=case.case_id,comparison_digest=result.comparison_digest,
            expected=[dict(claim_ids=e.claim_ids,status=e.status,required_reasons=e.required_reasons) for e in sorted(case.expected,key=lambda e:e.claim_ids)]))
    tp=matrix[CANDIDATE][CANDIDATE]
    fp=sum(matrix[e][CANDIDATE] for e in STATUSES if e!=CANDIDATE)
    fn=sum(n for p,n in matrix[CANDIDATE].items() if p!=CANDIDATE)
    def ratio(a,b):return a/b if b else None
    precision=ratio(tp,tp+fp);recall=ratio(tp,tp+fn)
    return dict(policy=POLICY,cases=len(cases),annotated_pairs=total,confusion_matrix=matrix,
        candidate_detection=dict(tp=tp,fp=fp,fn=fn,precision=precision,recall=recall,
            f1=ratio(2*tp,2*tp+fp+fn)),exact_status_accuracy=ratio(exact,total),
        explanation_annotated_pairs=reason_total,required_reason_coverage=ratio(explanations,reason_total),unresolved_rate=ratio(predicted_unresolved,total),
        benchmark_digest=digest(case_digests),ground_truth_semantics='DEVELOPER_AUTHORED_FIXTURES_NOT_INDEPENDENT_RESEARCH_LABELS',
        research_accuracy_established=False)
