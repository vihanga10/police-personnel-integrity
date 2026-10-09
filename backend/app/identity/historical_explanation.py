"""Value-free explanations for verified saved reported-state projections."""
from collections import Counter
import json
from app.identity.historical_reconstruction import Projection, require, DIMENSIONS
from app.identity.historical_source_claims import HEADERS

POLICY = 'SAVED_HISTORICAL_EXPLANATION_V1'
# Only fixed, developer-defined codes/descriptions may appear in aggregate output.
REASONS = {
    'CLASSIFICATION_UNASSESSED': 'Evidence classification has not been assessed.',
    'HISTORICAL_IDENTITY_UNASSESSED': 'The candidate link is not accepted historical identity.',
    'REPORTED_DATE_SEMANTICS_UNASSESSED': 'Reported dates are not accepted effective dates.',
    'AUTHORITY_AND_DELEGATION_UNASSESSED': 'Action authority and delegation have not been checked.',
    'SOURCE_INDEPENDENCE_UNVERIFIED': 'Agreement between reports does not establish independent corroboration.',
    'SOURCE_COVERAGE_NOT_HISTORICAL_COMPLETENESS': 'Received-batch coverage does not prove complete historical coverage.',
    'REQUEST_AFTER_CAPTURE_CANNOT_ESTABLISH_FUTURE_STATE': 'The query date is after this captured snapshot.',
    'LATEST_REPORTED_EVENT_CARRY_FORWARD_HYPOTHESIS': 'The latest dated report is carried forward only as a candidate hypothesis.',
    'REPORTED_INTERVAL_BOUNDARIES_UNASSESSED': 'Reported start and end boundaries have not been accepted.',
    'OPEN_END_DOES_NOT_PROVE_CONTINUING_VALIDITY': 'An empty end date does not prove continuing validity.',
    'END_DAY_INCLUSION_IS_CANDIDATE_ONLY': 'Inclusion on the reported end day is a candidate convention.',
    'UNPLACED_OR_UNASSESSED_EVIDENCE_REQUIRES_REVIEW': 'Snapshot, undated or semantically uncertain reports prevent a unique answer.',
    'NO_DATED_CANDIDATE_AT_REQUESTED_DATE': 'No usable dated candidate was available at the query date.',
    'COMPETING_REPORTED_VALUES_WITHOUT_ACCEPTED_PRECEDENCE': 'Candidate values differ and no accepted precedence chooses one.',
    'NO_RESTRICTION_OR_OVERRIDE_EFFECT_ACCEPTED': 'Restriction and override effects have not been accepted.',
}
ISSUES = frozenset({'REPORTED_VALUE_MISSING', 'REPORTED_DATE_MISSING', 'REPORTED_DATE_INVALID',
    'INVERTED_REPORTED_PERIOD', 'PROMOTION_POSTING_SEMANTICS_UNASSESSED',
    'TRANSFER_CANCELLATION_OR_FLAG_UNASSESSED', 'POSTING_DATE_AND_UNIT_IDENTITY_UNASSESSED',
    'OVERRIDE_AUTHORITY_SCOPE_AND_LINKAGE_UNASSESSED', 'DEMOTION_FLOOR_NOT_ACCEPTED_RESULTING_RANK',
    'ENLISTMENT_NOT_ACCEPTED_RANK_EFFECTIVE_DATE', 'INITIAL_POSTING_IDENTITY_AND_DATE_UNASSESSED'})


def explain(projection):
    """Use counts and fixed codes; never return a value, NIC, UUID or raw row ID."""
    require(isinstance(projection, Projection) and projection.accepted_state is None,
        'Unaccepted typed reported projection required.')
    require(projection.dimension in DIMENSIONS and projection.status in {'REPORTED_CANDIDATES', 'CANNOT_VERIFY', 'CONFLICTING_REPORTS'} and
        all(reason in REASONS for reason in projection.reasons), 'Unsupported explanation status or reason.')
    groups = {name: getattr(projection, name) for name in ('candidates','supporting','review','future','expired')}
    # Candidate events also occur in supporting; count each evidence claim once.
    unique = {}
    for claims in groups.values():
        for claim in claims:
            require(claim.dimension == projection.dimension and all(i in ISSUES for i in claim.issues),
                'Explanation claim policy differs.')
            require(claim.claim_id not in unique or unique[claim.claim_id] == claim,
                'Conflicting duplicate explanation claim.')
            unique[claim.claim_id] = claim
    sources, issues, modes = Counter(), Counter(), Counter()
    for claim in unique.values():
        reference = json.loads(claim.source_reference)
        filename = reference['filename']
        require(filename in HEADERS, 'Unrecognized explanation source.')
        sources[filename] += 1
        issues.update(claim.issues)
        modes[claim.mode] += 1
    observations = {}
    if projection.dimension == 'police_number' and len(projection.candidates) > 1:
        values = [json.loads(c.value) for c in projection.candidates]
        # Number types can legitimately differ. This is an observation, not a resolved conflict.
        require(all(set(v) == {'police_no','number_type'} and all(isinstance(x,str) for x in v.values())
            for v in values), 'Police number candidate shape differs.')
        by_type = {}
        for v in values:
            by_type.setdefault(v['number_type'], set()).add(v['police_no'])
        observations = dict(distinct_reported_number_types=len(by_type),
            types_with_multiple_reported_numbers=sum(len(v)>1 for v in by_type.values()),
            missing_type_candidates=sum(not v['number_type'].strip() for v in values),
            interpretation='TYPE_AND_BOUNDARY_REVIEW_REQUIRED')
    return dict(policy=POLICY, dimension=projection.dimension, status=projection.status,
        group_counts={name:len(claims) for name,claims in groups.items()}, unique_claims=len(unique),
        source_claim_counts=dict(sorted(sources.items())), claim_mode_counts=dict(sorted(modes.items())),
        review_issue_counts=dict(sorted(issues.items())), reasons=[dict(code=r, explanation=REASONS[r])
            for r in projection.reasons], police_number_observations=observations,
        accepted_state_claim=False, classification='UNASSESSED')
