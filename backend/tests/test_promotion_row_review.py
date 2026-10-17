"""Independent IGP row review of pending promotion acceptance; generated fixtures only."""
from copy import deepcopy
from uuid import uuid4
import pytest
from app.access.policy import AccessError
from app.intake.promotion_pipeline.core import IntakeError
from research_workspace_fixture import identifier
from test_promotion_approvals import e, batch, visible, assess  # noqa: F401  (fixture reuse)
from test_promotion_analysis import connected  # noqa: F401
from test_priority2_workflows import env  # noqa: F401


def pending(e, **changes):
    b = batch(e, **changes)
    visible(e, b)
    e['engine'].synchronize()
    head = e['engine'].journal.head('ROW:' + b['batch_id'] + ':1')
    return b, head


def review(b, head, decision='ACCEPT', version=0, **changes):
    value = dict(batch_id=b['batch_id'], row=1, operation_id=str(uuid4()), expected_version=version, decision=decision,
                 reason='Order reviewed against the signed promotion instrument',
                 evidence_reference='HQ/PROM/ORDER/0001', evaluation_reference=e_digest(head))
    value.update(changes)
    return value


def e_digest(head):
    from app.intake.promotion_pipeline.core import digest
    return digest(head)


def test_unassessed_authority_stays_pending_until_independent_row_review(e):
    b, head = pending(e)
    assert head['result']['status'] == 'PENDING_REVIEW' and 'AUTHORITY_CANNOT_VERIFY' in head['result']['reasons']
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    result = e['promotion'].review(*e['igp'], review(b, head))
    outcome = next(h for h in result['promotion_acceptance'] if h['result']['source_row'] == 1)
    assert outcome['result']['status'] == 'ACCEPTED' and outcome['result']['acceptance_basis'] == 'INDEPENDENT_IGP_ROW_REVIEW'
    accepted = e['engine'].current(identifier(1))['accepted_promotion']
    assert accepted['to_rank'] == 'Inspector of Police' and accepted['review_reference'] == outcome['result']['review_reference']
    # The earlier pending evaluation is preserved, not replaced.
    assert [r['result']['status'] for r in e['engine'].journal.rows('ROW:' + b['batch_id'] + ':1')] == ['PENDING_REVIEW', 'ACCEPTED']


def test_row_rejection_is_final_and_preserves_source_packet(e):
    before = deepcopy(e['store'].get_packet(identifier(1)))
    b, head = pending(e)
    e['promotion'].review(*e['igp'], review(b, head, 'REJECT'))
    assert e['engine'].journal.head('ROW:' + b['batch_id'] + ':1')['result']['status'] == 'NOT_ACCEPTED'
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None
    assert e['store'].get_packet(identifier(1)) == before
    with pytest.raises(IntakeError, match='ROW_NOT_AWAITING_REVIEW'):
        e['promotion'].review(*e['igp'], review(b, e['engine'].journal.head('ROW:' + b['batch_id'] + ':1'), version=1))


def test_uploader_and_non_reviewer_cannot_review(e):
    b, head = pending(e)
    with pytest.raises(AccessError, match='IGP_APPROVAL_FORBIDDEN'):
        e['promotion'].review(*e['hq'], review(b, head))
    uploader = e['promotion'].actor(e['hq'][0])
    e['engine'].reviewer = lambda user: True
    with pytest.raises(IntakeError, match='SELF_APPROVAL_FORBIDDEN'):
        e['engine'].review_row(b, uploader, review(b, head))


def test_review_must_target_the_exact_displayed_evaluation(e):
    b, head = pending(e)
    with pytest.raises(IntakeError, match='ROW_EVALUATION_CHANGED'):
        e['promotion'].review(*e['igp'], review(b, head, evaluation_reference='0' * 64))
    for changes, code in [({'reason': ' '}, 'APPROVAL_REASON_REQUIRED'), ({'evidence_reference': ''}, 'ROW_REVIEW_EVIDENCE_REQUIRED'),
                          ({'decision': 'APPROVE'}, 'ROW_REVIEW_DECISION_INVALID'), ({'row': 9}, 'ROW_REVIEW_TARGET_INVALID')]:
        with pytest.raises(IntakeError, match=code):
            e['promotion'].review(*e['igp'], review(b, head, **changes))
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None


def test_reviewer_cannot_accept_past_a_rank_sequence_conflict(e):
    b, head = pending(e, from_rank='Police Constable')
    if b['rows'][0]['status'] == 'NEEDS_REVIEW':
        pytest.skip('planner already blocks this fixture rank at intake')
    assert 'FROM_RANK_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE' in head['result']['reasons']
    with pytest.raises(IntakeError, match='ROW_HAS_BLOCKING_ISSUES'):
        e['promotion'].review(*e['igp'], review(b, head))


def test_new_evidence_voids_an_earlier_row_review(e):
    b, head = pending(e)
    e['promotion'].review(*e['igp'], review(b, head))
    assert e['engine'].current(identifier(1))['accepted_promotion'] is not None
    # A later signed authority assessment changes the evidence the reviewer saw.
    assess(e, b, 'PC')
    assert e['engine'].current(identifier(1))['accepted_promotion'] is None


def test_exact_review_replay_is_idempotent_and_changed_replay_conflicts(e):
    b, head = pending(e)
    q = review(b, head)
    first = e['engine'].review_row(b, e['promotion'].actor(e['igp'][0]), q)
    assert e['engine'].review_row(b, e['promotion'].actor(e['igp'][0]), q) == first
    with pytest.raises(IntakeError, match='DECISION_OPERATION_CONFLICT'):
        e['engine'].review_row(b, e['promotion'].actor(e['igp'][0]), dict(q, reason='A different retained reason'))
