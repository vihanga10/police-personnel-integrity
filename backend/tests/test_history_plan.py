"""Synthetic history claims: preservation, uncertainty and authenticated binding."""
import base64
from dataclasses import replace
from datetime import date
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
from cryptography.exceptions import InvalidTag
from app.identity.history_plan import ROUTES, plan_history, validate_history_routing
from app.identity.history_plan_crypto import seal_history_plan, open_history_plan
from app.security.identity_crypto import IdentityCrypto

TRANSFER = 'transfer_history.csv'
PROMOTION = 'promotion_history.csv'


def sample(filename=TRANSFER, **changes):
    # Empty optional values model absent evidence, not invented posting history.
    row = dict.fromkeys(ROUTES[filename], '')
    row.update(officer_nic_no='SYNTHETIC NIC', to_rank='Inspector of Police',
               effective_date='2020-01-01', is_same_unit='FALSE')
    if filename == TRANSFER:
        row.update(transfer_id='00001', is_cancelled='FALSE')
    else:
        row.update(promotion_id='00002', from_rank='Sub Inspector of Police')
    row.update(changes)
    return row


def planned(filename=TRANSFER, **changes):
    return plan_history(filename, sample(filename, **changes), officer_uid=uuid4(),
                        station_candidates={'Synthetic Station': ('001',)})


def item(plan, name):
    return next(f for f in plan.fields if f.source_column == name)


class HistoryPlanTests(unittest.TestCase):
    def test_both_sources_preserve_every_original_field(self):
        for filename, count in ((TRANSFER, 35), (PROMOTION, 21)):
            row = sample(filename)
            plan = plan_history(filename, row, officer_uid=uuid4())
            self.assertEqual(len(plan.fields), count)
            self.assertEqual({f.source_column: f.source_value for f in plan.fields}, row)
            self.assertFalse(plan.needs_review)

    def test_missing_from_fields_do_not_invent_initial_posting(self):
        plan = planned()
        for name in ('from_unit_type', 'from_rank', 'departure_date'):
            self.assertIsNone(item(plan, name).value)
            self.assertEqual(item(plan, name).status, 'MISSING')
        self.assertNotIn('INITIAL_POSTING', str(plan.observations))

    def test_required_values_and_source_contract_are_checked(self):
        for name in ('transfer_id', 'officer_nic_no', 'to_rank', 'effective_date', 'is_same_unit', 'is_cancelled'):
            self.assertTrue(planned(**{name: ''}).needs_review)
        for row in (dict(sample(), extra='x'), sample(is_cancelled=True)):
            with self.assertRaises(ValueError):
                plan_history(TRANSFER, row, officer_uid=uuid4())
        with self.assertRaises(ValueError):
            plan_history(TRANSFER, sample(), officer_uid='00001')

    def test_boolean_mapping_is_exact_and_preserves_unmapped_text(self):
        self.assertIs(item(planned(is_same_unit=' TRUE '), 'is_same_unit').value, True)
        for value in ('true', '1', 'yes'):
            field = item(planned(is_cancelled=value), 'is_cancelled')
            self.assertEqual(field.source_value, value)
            self.assertEqual(field.status, 'REVIEW_REQUIRED')
            self.assertIsNone(field.value)

    def test_cancelled_transfer_is_preserved_without_deciding_its_effect(self):
        plan = planned(is_cancelled='TRUE', cancellation_ref='0009', cancellation_date='2020-02-01')
        self.assertFalse(plan.needs_review)
        self.assertIn('SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL', plan.observations)
        self.assertIn('CANCELLATION_EFFECT_UNASSESSED', plan.uncertainties)
        self.assertEqual(item(plan, 'effective_date').value, date(2020, 1, 1))

    def test_cancellation_evidence_conflicts_require_review(self):
        self.assertTrue(planned(is_cancelled='TRUE').needs_review)
        self.assertTrue(planned(cancellation_ref='0009').needs_review)
        self.assertTrue(planned(is_cancelled='TRUE', cancellation_ref='0009', cancellation_date='bad').needs_review)

    def test_calendar_dates_require_iso_and_valid_calendar(self):
        self.assertEqual(item(planned(effective_date='2000-02-29'), 'effective_date').value, date(2000, 2, 29))
        for value in ('2001-02-29', '2020-1-1', '01/01/2020', '20200101'):
            self.assertTrue(planned(effective_date=value).needs_review)

    def test_chronology_is_an_observation_without_automatic_invalidity(self):
        for filename, changes in ((TRANSFER, {'transfer_signed_date': '2021-01-01'}),
                                  (PROMOTION, {'promotion_order_date': '2021-01-01'})):
            plan = planned(filename, **changes)
            self.assertTrue(plan.observations)
            self.assertFalse(plan.needs_review)
            self.assertIn('AUTHORITY_POLICY_UNASSESSED', plan.uncertainties)

    def test_unknown_rank_or_unit_is_not_fuzzy_mapped(self):
        for name, value in (('to_rank', 'Inspector'), ('to_unit_type', 'CCID')):
            plan = planned(**{name: value})
            self.assertTrue(plan.needs_review)
            self.assertEqual(item(plan, name).source_value, value)
            self.assertIsNone(item(plan, name).value)
        self.assertEqual(item(planned(to_unit_type='CID'), 'to_unit_type').value, 'CID')

    def test_unit_and_category_labels_stay_unresolved(self):
        plan = planned(to_unit_name='Synthetic Unit', transfer_type='Unreviewed category')
        self.assertEqual(item(plan, 'to_unit_name').value['resolution'], 'UNRESOLVED')
        self.assertIsNone(item(plan, 'transfer_type').value['code'])

    def test_station_pair_requires_one_exact_source_match(self):
        good = planned(to_station_code='001', to_station_name='Synthetic Station')
        self.assertFalse(good.needs_review)
        self.assertIn('HISTORICAL_APPLICABILITY_UNKNOWN', item(good, 'to_station_code').issues[0])
        for changes in ({'to_station_code': '002', 'to_station_name': 'Synthetic Station'},
                        {'to_station_code': '001'}, {'to_station_name': 'Synthetic Station'}):
            self.assertTrue(planned(**changes).needs_review)
        row = sample(to_station_code='001', to_station_name='Synthetic Station')
        for candidates in (None, {'Synthetic Station': ('001', '002')}):
            self.assertTrue(plan_history(TRANSFER, row, officer_uid=uuid4(), station_candidates=candidates).needs_review)

    def test_incomplete_station_code_is_not_eligible_as_a_matched_reference(self):
        field = item(planned(to_station_code='001'), 'to_station_code')
        self.assertEqual(field.status, 'REVIEW_REQUIRED')
        self.assertIsNone(field.value)

    def test_durations_are_nonnegative_and_do_not_reconstruct_periods(self):
        self.assertEqual(item(planned(days_in_previous_posting='00012'), 'days_in_previous_posting').value, 12)
        self.assertEqual(item(planned(PROMOTION, years_in_previous_rank='02.50'), 'years_in_previous_rank').value, Decimal('2.50'))
        for value in ('-1', 'NaN', '1e2'):
            self.assertTrue(planned(PROMOTION, years_in_previous_rank=value).needs_review)
        self.assertTrue(planned(days_in_previous_posting='12.5').needs_review)

    def test_identifiers_and_narratives_preserve_source_format(self):
        plan = planned(previous_police_no='00010', transfer_reason=' Line one\nLine two ')
        self.assertEqual(item(plan, 'previous_police_no').value, '00010')
        self.assertEqual(item(plan, 'transfer_reason').source_value, ' Line one\nLine two ')
        self.assertFalse(plan.needs_review)
        self.assertTrue(planned(transfer_reason='bad\x00text').needs_review)
        self.assertNotIn('SYNTHETIC NIC', repr(plan))

    def test_agreed_routing_and_duplicate_coverage_guard(self):
        path = Path(__file__).resolve().parents[2] / 'docs/field-routing.json'
        contract = json.loads(path.read_text())
        validate_history_routing(contract)
        source = next(f for f in contract['files'] if f['filename'] == TRANSFER)
        source['fields'][0] = dict(source['fields'][1])
        with self.assertRaises(ValueError):
            validate_history_routing(contract)


class HistoryCryptoTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'keys.json'
        key = base64.b64encode(b'K' * 32).decode()
        path.write_text(json.dumps(dict(active_encryption_key_version='test', active_lookup_key_version='test',
            encryption_keys={'test': key}, lookup_keys={'test': key})))
        self.crypto = IdentityCrypto(path)
        self.backup = IdentityCrypto(path)
        self.plan = planned(PROMOTION, years_in_previous_rank='02.50')
        self.binding = dict(filename=PROMOTION, officer_uid=self.plan.officer_uid, raw_record_id='a' * 64)

    def seal(self, plan=None):
        return seal_history_plan(self.crypto, plan or self.plan, raw_record_id=self.binding['raw_record_id'], reference_evidence={'source': 'synthetic'})

    def test_recovery_preserves_claims_without_authority_or_period_decisions(self):
        cipher, version = self.seal()
        result = open_history_plan(self.crypto, cipher, key_version=version, **self.binding)
        self.assertEqual(result, open_history_plan(self.backup, cipher, key_version=version, **self.binding))
        self.assertEqual(result['record_classification'], 'UNASSESSED')
        self.assertEqual(result['authority_assessment'], 'NOT_RUN')
        for name in ('valid_from', 'valid_to', 'authority_result'):
            self.assertIsNone(result[name])
        fields = {f['source_column']: f for f in result['fields']}
        self.assertEqual(fields['years_in_previous_rank']['value'], {'type': 'decimal', 'value': '2.50'})
        self.assertEqual(fields['officer_nic_no']['source_value'], 'SYNTHETIC NIC')
        self.assertNotIn(b'SYNTHETIC NIC', cipher)

    def test_rebinding_and_tampering_fail_authentication(self):
        cipher, version = self.seal()
        for changes in ({'filename': TRANSFER}, {'officer_uid': uuid4()}, {'raw_record_id': 'b' * 64}):
            with self.assertRaises(InvalidTag):
                open_history_plan(self.crypto, cipher, key_version=version, **dict(self.binding, **changes))
        with self.assertRaises(InvalidTag):
            open_history_plan(self.crypto, cipher[:-1] + bytes([cipher[-1] ^ 1]), key_version=version, **self.binding)

    def test_plan_binding_policy_and_field_coverage_cannot_be_replaced(self):
        for plan in (replace(self.plan, officer_uid=uuid4()), replace(self.plan, fields=self.plan.fields[:-1]),
                     replace(self.plan, policy_version='unapproved')):
            with self.assertRaises(ValueError):
                self.seal(plan)

    def test_review_values_are_preserved_inside_encrypted_envelope(self):
        plan = plan_history(PROMOTION, sample(PROMOTION, effective_date='not a date'), officer_uid=self.plan.officer_uid)
        cipher, version = self.seal(plan)
        result = open_history_plan(self.crypto, cipher, key_version=version, **self.binding)
        self.assertTrue(result['needs_review'])
        self.assertEqual(next(f for f in result['fields'] if f['source_column'] == 'effective_date')['source_value'], 'not a date')
