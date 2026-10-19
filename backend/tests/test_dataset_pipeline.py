"""Generated fixtures for multi-dataset HQ upload, IGP approval, publication and acceptance.

Real signed accounts, sessions, profiles, planners and acceptance rules; storage
and ledgers are deterministic in-memory destinations. No private data or RPC.
"""
import base64
import csv
import io
import json
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4
import pytest
from app.access import full_source_profiles as F, research_policy as P
from app.access.policy import AccessError
from app.intake.dataset_pipeline.acceptance import DatasetApprovals, POLICY as APPROVAL_POLICY
from app.intake.dataset_pipeline.analysis import DatasetAnalysis, DatasetAvailabilityJournal
from app.intake.dataset_pipeline.core import IntakeError, digest, expected_public, parse
from app.intake.dataset_pipeline.registry import DATASETS, dataset
from app.intake.dataset_pipeline.service import DatasetService
from app.intake.dataset_pipeline.store import DatasetStore
from app.intake.promotion_pipeline.delivery import process
from research_workspace_fixture import identifier
from test_promotion_approvals import e  # noqa: F401  (fixture reuse)
from test_promotion_analysis import connected  # noqa: F401
from test_priority2_workflows import env  # noqa: F401
from test_promotion_pipeline import Destination

NIC = '000000001V'


class Chains:
    """Deterministic dual-chain coordinator returning exactly bound receipts."""
    def __init__(self):
        self.pending, self.payloads = False, []

    def __call__(self, batch, payload, boundary):
        boundary()
        self.payloads.append(payload)
        if self.pending:
            return {'status': 'PENDING'}
        fabric = {'status': 'FINAL', 'payload': payload, 'transaction_id': 'b' * 64,
                  'destination': {'chaincode': 'personnel-intake-anchor-v1'}}
        result = {'fabric': fabric}
        return {'status': 'BOTH_CHAINS_VERIFIED', 'fabric': fabric,
                'public': {'status': 'FINAL', 'payload': expected_public(payload, result), 'transaction_id': '0x' + 'd' * 64,
                           'destination': {'contract': '0x' + 'e' * 40}}}


@pytest.fixture
def d(e, tmp_path):
    w = e['store']
    root = tmp_path / 'dataset-intake'
    root.mkdir(mode=0o700)
    keys = []
    for name in ('dataset-key', 'dataset-backup'):
        file = tmp_path / name
        file.write_bytes(b'y' * 32)
        file.chmod(0o600)
        keys.append(file)
    store = DatasetStore(root, *keys, repo=w.repo, create=True)
    service = [r for r in F.profile(w, identifier(1), e['directory']['source_public_sha256'])['full_records']
               if r['dataset'] == 'officer_service_information.csv'][0]['fields']
    station = service.get('current_station_code', '').strip() or 'ST-001'
    from app.intake.dataset_pipeline.core import raw_record_id
    master = [row('station_master.csv', station_code=code, station_name=name, station_name_si=si, division='D', province='P')
              for code, name, si in ((station, 'Fixture Origin', 'මූලය'), ('ST-002', 'Kandy', 'මහනුවර'), ('ST-003', 'Galle', 'ගාල්ල'))]
    pin = digest({'fixture': 'dataset-baseline'})
    store.install_baseline({'source_set_sha256': pin, 'rows': 0, 'index_sha256': digest({}), 'stations': {},
                            'references': digest({}), 'station_master': [[raw_record_id(dataset('STATION_REFERENCE'), r), r] for r in master]}, {}, {})
    analysis = DatasetAnalysis.__new__(DatasetAnalysis)
    analysis.workspace, analysis.intake, analysis.runtime = w, store, {}
    journal = tmp_path / 'dataset-analysis'
    journal.mkdir(mode=0o700)
    analysis.journal = DatasetAvailabilityJournal(journal, store.key, repo=w.repo, create=True)
    analysis.guard = lambda: None
    decisions = tmp_path / 'dataset-decisions'
    decisions.mkdir(mode=0o700)
    config = tmp_path / 'dataset-approval.json'
    config.write_text(json.dumps(dict(policy=APPROVAL_POLICY, decision_root=str(decisions),
                                      reviewer_ids=[identifier(101)], legacy_queued={})))
    config.chmod(0o600)
    approvals = DatasetApprovals(w, analysis, config, create=True)
    e['service'].dataset_analysis = w.dataset_analysis = analysis
    e['service'].dataset_acceptance = w.dataset_acceptance = approvals
    svc = DatasetService(e['service'], store, {'importer_ids': [identifier(100)], 'baseline_source_set_sha256': pin,
                                              'source_public_sha256': e['directory']['source_public_sha256']})
    resolver = {NIC: [identifier(1)]}
    original = svc.preview

    def preview(token, csrf, request):
        # The fixture directory carries generated NICs; bind the subject explicitly.
        import app.intake.dataset_pipeline.service as module
        real = module.validate_rows

        def bound(spec, rows, *, resolve, **kwargs):
            return real(spec, rows, resolve=lambda nic: resolver.get(nic, resolve(nic)), **kwargs)
        module.validate_rows = bound
        try:
            return original(token, csrf, request)
        finally:
            module.validate_rows = real
    svc.preview = preview
    e.update(dataset_store=store, dataset_analysis=analysis, dataset_engine=approvals, dataset=svc,
             origin_station=station, chains=Chains())
    return e


def row(name, **values):
    r = dict.fromkeys(DATASETS[name].columns, '')
    r.update(values)
    return r


def transfer(**changes):
    values = dict(transfer_id='T-' + str(uuid4())[:8], officer_nic_no=NIC, from_station_name='Fixture Origin',
        to_station_code='ST-002', to_station_name='Kandy', from_unit_type='CID', to_unit_type='CID',
        from_rank='Sub Inspector of Police', to_rank='Sub Inspector of Police', effective_date='2024-01-01',
        transfer_type='Routine', is_same_unit='FALSE', is_cancelled='FALSE')
    values.update(changes)
    return row('transfer_history.csv', **values)


def csv_bytes(name, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out)
    writer.writerow(DATASETS[name].columns)
    for r in rows:
        writer.writerow([r[c] for c in DATASETS[name].columns])
    return out.getvalue().encode()


def preview(d, name, rows, system=None):
    spec = DATASETS[name]
    return d['dataset'].preview(*d['hq'], dict(operation_id=str(uuid4()), dataset=spec.code, filename='upload.csv',
        source_reference='HQ/ORDER/FIXTURE', source_system=system or spec.source_systems[0],
        csv_base64=base64.b64encode(csv_bytes(name, rows)).decode()))


def decide(d, b, decision='APPROVE', version=1):
    return d['dataset'].decide(*d['igp'], dict(batch_id=b['batch_id'], file_sha256=b['file_sha256'], operation_id=str(uuid4()),
                                               expected_version=version, decision=decision, reason='Independently inspected exact upload'))


def published(d, name, rows):
    """HQ preview and submit, independent IGP approval, delivery, both chains, activation, evaluation."""
    import time
    # Production uses one clock; the fixture clock may run ahead of the real verification clock.
    lag = d['clock'][0] - time.time()
    if lag > 0:
        time.sleep(lag + 0.05)
    b = preview(d, name, rows)
    assert b['status'] == 'PREVIEW_READY', b['rows']
    d['dataset'].commit(*d['hq'], {'batch_id': b['batch_id'], 'file_sha256': b['file_sha256']})
    assert decide(d, b)['status'] == 'QUEUED'
    result = process(d['dataset_store'], b['batch_id'], Destination(), Destination(), d['chains'],
                     d['dataset_engine'].processing_allowed)
    assert result['status'] == 'BOTH_CHAINS_VERIFIED'
    receipt = d['dataset_store'].phase(b['batch_id'], 'CHAINS_VERIFIED')
    d['clock'][0] = max(d['clock'][0] + 2, P.instant(receipt['verification_observed_at']).timestamp() + 2)
    d['dataset_analysis'].activate_visible()
    d['clock'][0] += 1
    d['dataset_engine'].synchronize()
    return d['dataset'].summary(d['dataset_store'].get(b['batch_id']))


def review(d, summary, row_number=1, decision='ACCEPT', **changes):
    item = next(a for a in summary['row_acceptance'] if a['row'] == row_number)
    body = dict(batch_id=summary['batch_id'], row=row_number, operation_id=str(uuid4()),
                expected_version=item['row_review_version'], decision=decision,
                reason='Transfer order checked against the signed instrument', evidence_reference='HQ/TRF/0001',
                evaluation_reference=item['evaluation_reference'])
    body.update(changes)
    return d['dataset'].review(*d['igp'], body)


def state(d):
    return d['service'].workspace(d['hq'][0], identifier(1))['current_state']


def test_registry_covers_eighteen_datasets_with_exact_headers():
    assert len(DATASETS) == 18 and 'promotion_history.csv' not in DATASETS
    assert {d.code for d in DATASETS.values()} >= {'TRANSFER_HISTORY', 'POLICE_NUMBERS', 'RESTRICTIONS', 'COURT_CASES', 'DEMOTIONS'}
    spec = dataset('TRANSFER_HISTORY')
    with pytest.raises(IntakeError, match='CSV_HEADER_DIFFERS'):
        parse(csv_bytes('officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC)]), spec)
    assert parse(csv_bytes('transfer_history.csv', [transfer()]), spec)[0]['to_station_code'] == 'ST-002'


def test_transfer_pipeline_pending_authority_then_independent_review_updates_posting(d):
    before = deepcopy(F.profile(d['store'], identifier(1), d['directory']['source_public_sha256']))
    s = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    assert s['publication']['status'] == 'BOTH_CHAINS_VERIFIED' and s['publication']['dataset'] == 'TRANSFER_HISTORY'
    outcome = s['row_acceptance'][0]
    assert outcome['status'] == 'PENDING_REVIEW' and 'AUTHORITY_CANNOT_VERIFY' in outcome['reasons']
    assert state(d)['fields'].get('current_station_code') != 'ST-002'
    s = review(d, s)
    assert s['row_acceptance'][0]['status'] == 'ACCEPTED' and s['row_acceptance'][0]['acceptance_basis'] == 'INDEPENDENT_IGP_ROW_REVIEW'
    current = state(d)
    assert current['fields']['current_station_code'] == 'ST-002' and current['fields']['current_station'] == 'Kandy'
    assert current['basis']['current_station_code']['basis'] == 'ACCEPTED_TRANSFER_EFFECTIVE_NOW'
    # The signed source profile is unchanged; the change is a displayed, referenced projection.
    assert F.profile(d['store'], identifier(1), d['directory']['source_public_sha256']) == before
    rows = d['dataset'].officer_rows(d['hq'][0], identifier(1))
    assert rows['items'][0]['dataset'] == 'TRANSFER_HISTORY' and rows['items'][0]['outcome']['status'] == 'ACCEPTED'


def test_future_effective_transfer_is_scheduled_not_current(d):
    s = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'], effective_date='2099-01-01')])
    review(d, s)
    current = state(d)
    assert current['fields'].get('current_station_code') != 'ST-002'
    assert [x['effective_on'] for x in current['scheduled_effects']] == ['2099-01-01']


def test_transfer_from_a_different_posting_cannot_be_reviewed_into_acceptance(d):
    s = published(d, 'transfer_history.csv', [transfer(from_station_code='ST-003', from_station_name='Galle')])
    item = s['row_acceptance'][0]
    assert item['status'] == 'PENDING_REVIEW' and 'FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE' in item['row_review_blocked']
    with pytest.raises(IntakeError, match='ROW_HAS_BLOCKING_ISSUES'):
        review(d, s)
    assert not state(d)['changed']


def test_education_record_without_authority_route_is_accepted_as_a_record(d):
    s = published(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2005')])
    item = s['row_acceptance'][0]
    assert item['status'] == 'ACCEPTED' and item['effect'] == 'NONE'
    assert not state(d)['changed']
    shown = d['dataset'].officer_rows(d['hq'][0], identifier(1))['items']
    assert shown[0]['dataset_label'] == 'Education' and shown[0]['fields']['ol_year'] == '2005'


def test_police_number_accepted_projection(d):
    s = published(d, 'officer_police_numbers.csv', [row('officer_police_numbers.csv', police_no='77777', officer_nic_no=NIC,
                                                        number_type='Police Number', valid_from='2024-02-01')])
    assert s['row_acceptance'][0]['status'] == 'ACCEPTED'
    numbers = state(d)['police_numbers']
    assert numbers == [dict(numbers[0], number_type='Police Number', police_no='77777', effective_on='2024-02-01')]


def test_override_of_unknown_restriction_is_refused_at_intake(d):
    # The reviewed SRB planner refuses an unresolved restriction reference before retention.
    b = preview(d, 'restriction_overrides.csv', [row('restriction_overrides.csv', override_id='O-0', restriction_id='R-NONE',
                                                     officer_nic_no=NIC, override_date='2024-01-01')])
    assert b['status'] == 'NEEDS_REVIEW' and 'restriction_id:REFERENCE_UNRESOLVED_OR_AMBIGUOUS' in b['rows'][0]['issues']
    with pytest.raises(IntakeError, match='ROWS_REQUIRE_REVIEW'):
        d['dataset'].commit(*d['hq'], {'batch_id': b['batch_id'], 'file_sha256': b['file_sha256']})


def test_restriction_then_override_resolve_through_uploaded_reference(d):
    published(d, 'officer_restrictions.csv', [row('officer_restrictions.csv', restriction_id='R-9', officer_nic_no=NIC,
        restriction_category='Transfer', restriction_start_date='2024-01-01', restriction_record_date='2024-01-01')])
    b = preview(d, 'restriction_overrides.csv', [row('restriction_overrides.csv', override_id='O-9', restriction_id='R-9',
                                                     officer_nic_no=NIC, override_date='2024-02-01')])
    assert not any('REFERENCE_UNRESOLVED' in i for i in b['rows'][0]['issues'])


def test_demotion_needs_upstream_punishment_and_is_derived(d):
    s = published(d, '_demotions_enacted.csv', [row('_demotions_enacted.csv', officer_nic_no=NIC, punishment_date='2024-01-01',
                                                    floor_rank='Police Constable', punishment_id='P-404')])
    reasons = s['row_acceptance'][0]['reasons']
    assert 'DERIVED_NON_INDEPENDENT_SOURCE' in reasons and 'UPSTREAM_PUNISHMENT_NOT_FOUND' in reasons


def test_demotion_with_uploaded_punishment_changes_rank_only_after_review(d):
    published(d, 'bad_conduct_register.csv', [row('bad_conduct_register.csv', punishment_id='P-1', officer_nic_no=NIC,
                                                  date_of_punishment='2024-01-01', reduction_in_rank_enacted='TRUE')])
    s = published(d, '_demotions_enacted.csv', [row('_demotions_enacted.csv', officer_nic_no=NIC, punishment_date='2024-01-01',
                                                    floor_rank='Police Constable', punishment_id='P-1')])
    assert s['row_acceptance'][0]['status'] == 'PENDING_REVIEW' and s['row_acceptance'][0]['row_review_blocked'] == []
    assert state(d)['fields'].get('current_rank') == 'Sub Inspector of Police'
    review(d, s)
    current = state(d)
    assert current['fields']['current_rank'] == 'Police Constable'
    assert current['basis']['current_rank']['basis'] == 'ACCEPTED_DEMOTION_EFFECTIVE_NOW'


def test_hq_cannot_decide_or_review_and_igp_cannot_upload(d):
    b = preview(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2001')])
    d['dataset'].commit(*d['hq'], {'batch_id': b['batch_id'], 'file_sha256': b['file_sha256']})
    with pytest.raises(AccessError, match='IGP_APPROVAL_FORBIDDEN'):
        d['dataset'].decide(*d['hq'], dict(batch_id=b['batch_id'], file_sha256=b['file_sha256'], operation_id=str(uuid4()),
                                           expected_version=1, decision='APPROVE', reason='Self approval attempt'))
    with pytest.raises(AccessError, match='DATASET_IMPORT_FORBIDDEN'):
        d['dataset'].preview(*d['igp'], {})
    assert d['dataset_store'].pending() == []


def test_unresolved_subject_or_bad_source_system_blocks_the_batch(d):
    b = preview(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC),
                                             row('officer_education.csv', officer_nic_no='999999999V', ol_year='1999')])
    assert b['status'] == 'NEEDS_REVIEW' and 'officer_nic_no:OFFICER_NOT_FOUND' in b['rows'][1]['issues']
    with pytest.raises(IntakeError, match='ROWS_REQUIRE_REVIEW'):
        d['dataset'].commit(*d['hq'], {'batch_id': b['batch_id'], 'file_sha256': b['file_sha256']})
    with pytest.raises(IntakeError, match='SOURCE_SYSTEM_NOT_REGISTERED'):
        preview(d, 'transfer_history.csv', [transfer()], system='SRB')


def test_identical_reupload_is_duplicate_and_changed_row_conflicts(d):
    values = transfer(transfer_id='T-FIXED', from_station_code=d['origin_station'])
    published(d, 'transfer_history.csv', [values])
    again = preview(d, 'transfer_history.csv', [values, transfer(transfer_id='T-NEW', from_station_code=d['origin_station'])])
    assert [r['status'] for r in again['rows']] == ['DUPLICATE', 'READY']
    changed = preview(d, 'transfer_history.csv', [dict(values, to_station_code='ST-003', to_station_name='Galle')])
    assert 'SOURCE_ID_CONFLICT' in changed['rows'][0]['issues']


def test_ledger_payload_binds_dataset_code_and_only_opaque_digests(d):
    published(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2010')])
    payload = d['chains'].payloads[-1]
    assert payload['dataset'] == 'EDUCATION' and payload['namespace'] == 'personnel-intake-anchor-v1'
    assert set(payload) == {'policy', 'namespace', 'dataset', 'publication_id', 'public_sha256', 'merkle_root', 'publication_commitment'}
    assert NIC not in json.dumps(payload) and identifier(1) not in json.dumps(payload)


def test_pending_chain_confirmation_never_reaches_analysis(d):
    d['chains'].pending = True
    b = preview(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2011')])
    d['dataset'].commit(*d['hq'], {'batch_id': b['batch_id'], 'file_sha256': b['file_sha256']})
    decide(d, b)
    result = process(d['dataset_store'], b['batch_id'], Destination(), Destination(), d['chains'], d['dataset_engine'].processing_allowed)
    assert result['status'] == 'CHAIN_CONFIRMATION_PENDING'
    assert d['dataset_analysis'].activate_visible() == [] and d['dataset_analysis'].reports(identifier(1)) == []


def test_history_query_sees_uploaded_transfer_only_after_activation(d):
    before = datetime.fromtimestamp(d['clock'][0], timezone.utc).isoformat()
    s = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    after = d['dataset_analysis'].journal.get(s['batch_id'])['available_at']
    early = d['service'].history(d['hq'][0], d['hq'][1], identifier(1), '2024-06-01', before)
    late = d['service'].history(d['hq'][0], d['hq'][1], identifier(1), '2024-06-01', after)
    assert not early.get('dataset_evidence')
    assert [x['dataset'] for x in late['dataset_evidence']] == ['TRANSFER_HISTORY']
    assert early['query_digest'] != late['query_digest']


def station(**changes):
    values = dict(station_code='ST-777', station_name='Matara', station_name_si='මාතර', town='Matara', division='Matara',
                  district='Matara', province='Southern', province_of_district='Southern', province_matches_district='TRUE',
                  district_source='SOURCE', district_confidence='HIGH', latitude='5.9549', longitude='80.5550')
    values.update(changes)
    return row('station_master.csv', **values)


def person(**changes):
    values = dict(officer_nic_no='199912345678', full_name='Fixture Person Name', name_with_initials='F. P. Name',
                  gender='Male', date_of_birth='1999-05-01', nationality='Sri Lankan', marital_status='Single')
    values.update(changes)
    return row('officer_personal_information.csv', **values)


def test_accepted_uploaded_station_extends_validation_for_later_transfers(d):
    moved = transfer(from_station_code=d['origin_station'], to_station_code='ST-777', to_station_name='Matara')
    before = preview(d, 'transfer_history.csv', [moved])
    assert before['status'] == 'NEEDS_REVIEW' and any('STATION' in i for i in before['rows'][0]['issues'])
    s = published(d, 'station_master.csv', [station()])
    assert s['row_acceptance'][0]['status'] == 'ACCEPTED' and s['row_acceptance'][0]['effect'] == 'STATION_REFERENCE'
    assert s['publication']['dataset'] == 'STATION_REFERENCE'
    after = preview(d, 'transfer_history.csv', [dict(moved, transfer_id='T-AFTER')])
    assert after['status'] == 'PREVIEW_READY', after['rows'][0]['issues']


def test_original_station_code_cannot_be_rewritten_by_upload(d):
    changed = preview(d, 'station_master.csv', [station(station_code='ST-002', station_name='Renamed Kandy')])
    assert changed['status'] == 'NEEDS_REVIEW'


def test_new_officer_registration_requires_independent_review_and_is_never_signed_by_the_web_tier(d):
    s = published(d, 'officer_personal_information.csv', [person()])
    item = s['row_acceptance'][0]
    assert item['status'] == 'PENDING_REVIEW' and item['reasons'] == ['NEW_OFFICER_REGISTRATION_REQUIRES_REVIEW']
    assert d['dataset_engine'].accepted_rows('OFFICER_REGISTRATION') == []
    s = review(d, s)
    assert s['row_acceptance'][0]['status'] == 'ACCEPTED' and s['row_acceptance'][0]['effect'] == 'REGISTRATION'
    accepted = d['dataset_engine'].accepted_rows('OFFICER_REGISTRATION')
    assert [r['source']['officer_nic_no'] for _, r, _ in accepted] == ['199912345678']
    # The signed directory is unchanged: only the offline operator key can add an identity.
    with d['store'].access.transaction() as c:
        assert d['store'].access._directory(c) == d['directory']


def test_existing_officer_cannot_be_re_registered(d):
    b = preview(d, 'officer_personal_information.csv', [person(officer_nic_no=NIC)])
    assert b['status'] == 'NEEDS_REVIEW' and 'OFFICER_ALREADY_REGISTERED' in b['rows'][0]['issues']
