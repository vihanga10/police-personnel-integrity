import base64
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from uuid import uuid4
from cryptography.exceptions import InvalidTag
from app.identity.service_values import map_service_category, parse_service_date
from app.identity.service_plan import ROUTES, plan_service, validate_service_routing
from app.identity.service_plan_crypto import seal_service_plan, open_service_plan
from app.security.identity_crypto import IdentityCrypto


def sample(**changes):
    row = {name:'' for name in ROUTES}
    row.update(service_id='0001',officer_nic_no='Example Test NIC',entry_rank='Police Constable',
        current_rank='Police Constable Class 1',current_rank_category='Non-Gazetted',
        current_unit_type='Station Crime Branch',service_status='Active',enrollment_type='normal_service',
        date_of_enlistment='2000-01-01',first_posted_date='2000-02-01',
        pensionable_post_appointment_date='2001-01-01',pensionable_post_confirmation_date='2002-01-01',
        current_posted_to_unit_date='2020-01-01',retirement_date='2040-01-01')
    row.update(changes)
    return row


def planned(**changes):
    return plan_service(sample(**changes),officer_uid=uuid4(),station_candidates={'Example Station':('001',)})


def field(plan,name):
    return next(f for f in plan.fields if f.source_column == name)


class ServicePlanTests(unittest.TestCase):
    def test_all_thirty_two_fields_preserved(self):
        plan = planned()
        self.assertEqual(len(plan.fields),32)
        self.assertEqual({f.source_column for f in plan.fields},set(ROUTES))
        self.assertFalse(plan.needs_review)

    def test_schema_changes_and_non_text_are_rejected(self):
        for row in (dict(sample(),unexpected='x'),{k:v for k,v in sample().items() if k!='time_left'},sample(service_years=10)):
            with self.assertRaises(ValueError):
                plan_service(row,officer_uid=uuid4())

    def test_officer_uid_is_established_and_not_a_police_number(self):
        uid = uuid4()
        plan = plan_service(sample(),officer_uid=uid)
        self.assertEqual(field(plan,'officer_nic_no').value,uid)
        with self.assertRaises(ValueError):
            plan_service(sample(),officer_uid='12345')

    def test_rank_classes_and_unspecified_entry_rank_are_distinct(self):
        values = [map_service_category('current_rank',f'Police Constable Class {n}').value for n in range(1,5)]
        self.assertEqual(len(set(values)),4)
        self.assertNotIn(map_service_category('entry_rank','Police Constable').value,values)
        self.assertNotEqual(map_service_category('current_rank','Police Sergeant Class 1').value,
                            map_service_category('current_rank','Police Sergeant Class 2').value)

    def test_unknown_labels_require_review_without_fuzzy_mapping(self):
        for value in ('CCID','cid','Criminal Investigation Dept'):
            plan = planned(current_unit_type=value)
            item = field(plan,'current_unit_type')
            self.assertEqual(item.source_value,value)
            self.assertTrue(plan.needs_review)
            self.assertIsNone(item.value)

    def test_outer_spaces_only_are_trimmed(self):
        self.assertEqual(map_service_category('current_unit_type',' CID ').value,'CID')
        self.assertEqual(map_service_category('current_unit_type','Station  Crime Branch').status,'REVIEW_REQUIRED')

    def test_missing_entry_unit_is_not_filled_from_current_unit(self):
        plan = planned(entry_rank='Assistant Superintendent of Police',current_unit_type='CID')
        self.assertEqual(field(plan,'entry_unit_type').status,'MISSING')
        self.assertIsNone(field(plan,'entry_unit_name').value)

    def test_blank_required_value_requires_review(self):
        for name in ('service_id','officer_nic_no','current_rank','current_unit_type','service_status'):
            self.assertTrue(planned(**{name:''}).needs_review)

    def test_calendar_dates_are_strict_iso_without_invented_snapshot(self):
        self.assertEqual(parse_service_date('2000-02-29').value,date(2000,2,29))
        for value in ('2001-02-29','2026-2-1','01/02/2026','20260201'):
            self.assertEqual(parse_service_date(value).status,'REVIEW_REQUIRED')
        self.assertIn('SNAPSHOT_DATE_UNAVAILABLE',planned().uncertainties)

    def test_future_retirement_does_not_change_active_status(self):
        plan = planned(retirement_date='2099-01-01')
        self.assertEqual(field(plan,'service_status').value,'ACTIVE')
        self.assertFalse(plan.needs_review)
        self.assertIn('RETIREMENT_DATE_MEANING_UNASSESSED',plan.uncertainties)

    def test_reported_dates_are_not_current_rank_effective_dates(self):
        plan = planned(current_rank='Inspector of Police')
        self.assertIn('REPORTED_DATE_NOT_STATE_EFFECTIVE_DATE',field(plan,'current_posted_to_unit_date').issues)
        self.assertNotIn('current_rank_effective_date',{f.target_field for f in plan.fields})

    def test_chronology_conflicts_preserve_both_dates(self):
        plan = planned(pensionable_post_confirmation_date='1999-01-01')
        self.assertIn('REPORTED_CONFIRMATION_BEFORE_APPOINTMENT',plan.review_issues)
        self.assertEqual(field(plan,'pensionable_post_confirmation_date').value,date(1999,1,1))

    def test_rank_category_conflicts_do_not_silently_replace_reported_category(self):
        plan = planned(current_rank='Senior Deputy Inspector General of Police',current_rank_category='Non-Gazetted')
        self.assertIn('REPORTED_RANK_CATEGORY_CONFLICT',plan.review_issues)
        self.assertEqual(field(plan,'current_rank_category').value,'NON_GAZETTED')

    def test_station_code_and_name_pair_must_match_exactly(self):
        good = planned(current_station='Example Station',current_station_code='001')
        self.assertEqual(field(good,'current_station_code').value,'001')
        self.assertFalse(good.needs_review)
        bad = planned(current_station='Example Station',current_station_code='002')
        self.assertTrue(bad.needs_review)
        self.assertEqual(field(bad,'current_station_code').source_value,'002')

    def test_ambiguous_and_unprovided_station_snapshots_require_review(self):
        row = sample(current_station='Example Station',current_station_code='001')
        for candidates in (None,{'Example Station':('001','002')}):
            self.assertTrue(plan_service(row,officer_uid=uuid4(),station_candidates=candidates).needs_review)

    def test_missing_station_fields_are_preserved_without_guessing(self):
        plan = planned()
        self.assertEqual(field(plan,'current_station_code').status,'MISSING')
        self.assertFalse(plan.needs_review)
        self.assertTrue(planned(current_station='Example Station').needs_review)

    def test_police_numbers_service_id_and_derived_values_keep_leading_zeros(self):
        plan = planned(entry_police_no='000001',current_police_no='000002',service_years='025.00',time_left='0012')
        for name,value in (('service_id','0001'),('entry_police_no','000001'),('current_police_no','000002'),('service_years','025.00'),('time_left','0012')):
            self.assertEqual(field(plan,name).value,value)

    def test_units_do_not_become_fabricated_reference_ids(self):
        item = field(planned(current_unit_name='Example CID Unit'),'current_unit_name')
        self.assertEqual(item.value,{'reported_label':'Example CID Unit','resolution':'UNRESOLVED'})
        self.assertIn('UNIT_REFERENCE_UNRESOLVED',item.issues)

    def test_sensitive_values_are_hidden_from_representations(self):
        plan = planned(officer_nic_no='PRIVATE NIC VALUE',current_unit_name='PRIVATE UNIT VALUE')
        self.assertNotIn('PRIVATE',repr(plan))
        self.assertNotIn('PRIVATE',repr(field(plan,'current_unit_name')))

    def test_live_routing_contract_covers_service_fields(self):
        contract = json.loads((Path(__file__).resolve().parents[2]/'docs/field-routing.json').read_text())
        validate_service_routing(contract)
        service = next(f for f in contract['files'] if f['filename']=='officer_service_information.csv')
        service['fields'][0]['target_field']='wrong'
        with self.assertRaises(ValueError):
            validate_service_routing(contract)


class ServicePlanCryptoTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        key = base64.b64encode(b'K'*32).decode()
        path = Path(directory.name)/'keys.json'
        path.write_text(json.dumps(dict(active_encryption_key_version='test',active_lookup_key_version='test',
                                       encryption_keys={'test':key},lookup_keys={'test':key})))
        self.crypto = IdentityCrypto(path)
        self.binding = dict(officer_uid=uuid4(),raw_record_id='a'*64)
        self.plan = plan_service(sample(),officer_uid=self.binding['officer_uid'])

    def test_envelope_preserves_originals_typed_dates_and_unknown_applicability(self):
        sealed,version = seal_service_plan(self.crypto,self.plan,reference_evidence={'source':'test'},**self.binding)
        result = open_service_plan(self.crypto,sealed,key_version=version,**self.binding)
        fields = {f['source_column']:f for f in result['fields']}
        self.assertEqual(len(fields),32)
        self.assertEqual(fields['officer_nic_no']['source_value'],'Example Test NIC')
        self.assertEqual(fields['date_of_enlistment']['value'],{'type':'date','value':'2000-01-01'})
        self.assertEqual(result['record_classification'],'UNASSESSED')
        self.assertIsNone(result['snapshot_date'])
        self.assertIsNone(result['valid_from'])
        self.assertNotIn(b'Example Test NIC',sealed)

    def test_wrong_officer_source_or_ciphertext_is_rejected(self):
        sealed,version = seal_service_plan(self.crypto,self.plan,reference_evidence={},**self.binding)
        for binding in (dict(self.binding,officer_uid=uuid4()),dict(self.binding,raw_record_id='b'*64)):
            with self.assertRaises(InvalidTag):
                open_service_plan(self.crypto,sealed,key_version=version,**binding)
        changed = sealed[:-1]+bytes([sealed[-1]^1])
        with self.assertRaises(InvalidTag):
            open_service_plan(self.crypto,changed,key_version=version,**self.binding)

    def test_repeated_encryption_has_distinct_nonces(self):
        first,_ = seal_service_plan(self.crypto,self.plan,reference_evidence={},**self.binding)
        second,_ = seal_service_plan(self.crypto,self.plan,reference_evidence={},**self.binding)
        self.assertNotEqual(first[:12],second[:12])

    def test_plan_officer_cannot_be_rebound_during_encryption(self):
        with self.assertRaises(ValueError):
            seal_service_plan(self.crypto,self.plan,reference_evidence={},**dict(self.binding,officer_uid=uuid4()))


class ServiceIdentifierEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        key = base64.b64encode(b'K'*32).decode()
        path = Path(directory.name)/'keys.json'
        path.write_text(json.dumps(dict(active_encryption_key_version='test',active_lookup_key_version='test',
                                       encryption_keys={'test':key},lookup_keys={'test':key})))
        self.crypto = IdentityCrypto(path)

    def fixture(self):
        from types import SimpleNamespace
        from app.identity.registration_service import evidence_context
        from app.identity.normalization import normalize_identifier, NORMALIZATION_PROFILE
        from app.identity.inspect_service_plans import CONFIRMATION
        nic = normalize_identifier('Example Test NIC',identifier_type='NIC')
        officer,identifier_id,assertion_id = uuid4(),uuid4(),uuid4()
        cipher,key = self.crypto.encrypt(nic.value.encode(),context=evidence_context('IDENTIFIER',identifier_id))
        digest,lookup = self.crypto.lookup_hmac(nic.value,identifier_type='NIC')
        saved = dict(officer_uid=officer,identifier_type='NIC',normalization_profile=NORMALIZATION_PROFILE,
            identifier_value_ciphertext=cipher,encryption_key_version=key,identifier_lookup_hmac=digest,lookup_key_version=lookup)
        claim = dict(normalized_value=nic.value,reported_value=nic.value,identifier_type='NIC',normalization_profile=NORMALIZATION_PROFILE,
            raw_record_id='a'*64,source_confirmation_sha256=CONFIRMATION,source_column='officer_nic_no')
        cipher,key = self.crypto.encrypt_assertion(claim,context=evidence_context('ASSERTION',assertion_id))
        assertion = dict(officer_uid=officer,assertion_type='IDENTIFIER_NIC',asserted_value_ciphertext=cipher,
            encryption_key_version=key,raw_record_id='a'*64,transaction_end=None)
        evidence = SimpleNamespace(officer_uid=officer,identifier_version_id=identifier_id,source_assertion_id=assertion_id,
            registry_state='REGISTERED',record_state='ASSERTED',assertion_state='ACTIVE',transaction_end=None)
        candidates = SimpleNamespace(evidence=(evidence,))
        return nic,saved,assertion,candidates

    def run_verification(self,nic,saved,assertion,candidates):
        from types import SimpleNamespace
        from app.identity.inspect_service_plans import verified_nic_evidence
        results = iter((saved,assertion))
        connection = SimpleNamespace(execute=lambda query:SimpleNamespace(mappings=lambda:SimpleNamespace(one=lambda:next(results))))
        return verified_nic_evidence(connection,self.crypto,self.crypto,nic,candidates)

    def test_exact_encrypted_nic_and_assertion_produce_opaque_references(self):
        values = self.fixture()
        refs = self.run_verification(*values)
        self.assertEqual(len(refs),1)
        self.assertNotIn('Example Test NIC',str(refs))
        self.assertEqual(refs[0]['historical_eligibility'],'UNASSESSED')

    def test_wrong_officer_or_hmac_is_rejected(self):
        nic,saved,assertion,candidates = self.fixture()
        with self.assertRaises(RuntimeError):
            self.run_verification(nic,dict(saved,officer_uid=uuid4()),assertion,candidates)
        with self.assertRaises(RuntimeError):
            self.run_verification(nic,dict(saved,identifier_lookup_hmac='0'*64),assertion,candidates)

    def test_tampered_nic_ciphertext_is_rejected(self):
        nic,saved,assertion,candidates = self.fixture()
        cipher = saved['identifier_value_ciphertext']
        saved['identifier_value_ciphertext'] = cipher[:-1]+bytes([cipher[-1]^1])
        with self.assertRaises(InvalidTag):
            self.run_verification(nic,saved,assertion,candidates)

    def test_disputed_evidence_does_not_become_usable_identity_support(self):
        nic,saved,assertion,candidates = self.fixture()
        candidates.evidence[0].record_state = 'DISPUTED'
        self.assertEqual(self.run_verification(nic,saved,assertion,candidates),[])
