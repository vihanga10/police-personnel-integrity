import base64
import json
import tempfile
import unittest
from datetime import date
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from app.identity.profile_plan import EXPECTED_COLUMNS, ROUTES, plan_profile, validate_routing
from app.identity.profile_plan_crypto import seal_plan, open_plan
from app.security.identity_crypto import IdentityCrypto


def sample(**changes):
    row = {name: "" for name in EXPECTED_COLUMNS}
    row.update(full_name="Example Officer", gender="Female", nationality="Sri Lankan",
               date_of_birth="1990-01-02", age="36", height_cm="165.25")
    row.update(changes)
    return row


def fields(plan):
    return {item.source_column: item for item in plan.fields}


class ProfilePlanTests(unittest.TestCase):
    def test_exact_twenty_field_coverage_without_identifiers(self):
        plan = plan_profile(sample())
        self.assertEqual(len(plan.fields), 20)
        self.assertEqual(set(fields(plan)), set(ROUTES))
        self.assertNotIn("officer_nic_no", fields(plan))

    def test_added_or_missing_columns_are_rejected(self):
        for row in (dict(sample(), surprise="x"), {k:v for k,v in sample().items() if k != "age"}):
            with self.assertRaises(ValueError):
                plan_profile(row)

    def test_non_string_source_rejected(self):
        with self.assertRaises(ValueError):
            plan_profile(sample(age=36))

    def test_blank_required_name_requires_review(self):
        self.assertTrue(plan_profile(sample(full_name=" ")).needs_review)

    def test_optional_blank_values_remain_missing(self):
        item = fields(plan_profile(sample()))["father_name"]
        self.assertEqual((item.value, item.status), (None, "MISSING"))

    def test_unknown_category_preserved_for_review(self):
        item = fields(plan_profile(sample(religion="Unmapped label")))["religion"]
        self.assertEqual(item.source_value, "Unmapped label")
        self.assertEqual(item.status, "REVIEW_REQUIRED")

    def test_original_text_preserved_and_hidden_from_repr(self):
        plan = plan_profile(sample(full_name="  Hidden Example  "))
        item = fields(plan)["full_name"]
        self.assertEqual(item.source_value, "  Hidden Example  ")
        self.assertEqual(item.value, "Hidden Example")
        self.assertNotIn("Hidden Example", repr(item))
        self.assertNotIn("Hidden Example", repr(plan))

    def test_length_limit_and_nul_require_review(self):
        for value in ("x" * 301, "x\x00y"):
            self.assertEqual(fields(plan_profile(sample(full_name=value)))["full_name"].status, "REVIEW_REQUIRED")

    def test_measurements_are_exact_and_not_rounded(self):
        self.assertEqual(fields(plan_profile(sample()))["height_cm"].value, Decimal("165.25"))
        for value in ("NaN", "inf", "-1", "0", "1000", "165.251", "1e2"):
            with self.subTest(value=value):
                self.assertEqual(fields(plan_profile(sample(height_cm=value)))["height_cm"].status, "REVIEW_REQUIRED")

    def test_unknown_snapshot_is_flagged(self):
        item = fields(plan_profile(sample()))["date_of_birth"]
        self.assertIn("SNAPSHOT_DATE_UNAVAILABLE", item.issues)

    def test_birth_after_snapshot_requires_review(self):
        item = fields(plan_profile(sample(), snapshot_date=date(1980, 1, 1)))["date_of_birth"]
        self.assertEqual(item.status, "REVIEW_REQUIRED")

    def test_reported_age_compared_only_with_supported_date(self):
        good = fields(plan_profile(sample(), snapshot_date=date(2026, 10, 7)))["age"]
        bad = fields(plan_profile(sample(age="35"), snapshot_date=date(2026, 10, 7)))["age"]
        self.assertEqual(good.status, "PARSED")
        self.assertEqual(bad.issues, ("REPORTED_AGE_MISMATCH",))
        self.assertEqual(bad.value, 35)

    def test_station_names_are_not_invented_references(self):
        row = sample(present_address_local_police_station_name="Example Station")
        for candidates in (None, {"Example Station": ("S1", "S2")}):
            item = fields(plan_profile(row, station_candidates=candidates))["present_address_local_police_station_name"]
            self.assertEqual(item.status, "REVIEW_REQUIRED")
            self.assertIsNone(item.value)
        item = fields(plan_profile(row, station_candidates={"Example Station": ("S1",)}))["present_address_local_police_station_name"]
        self.assertEqual(item.value, "S1")

    def test_email_retains_local_case(self):
        item = fields(plan_profile(sample(officer_email="Example.User@EXAMPLE.ORG")))["officer_email"]
        self.assertEqual(item.value, "Example.User@example.org")
        for value in ("a..b@example.org", "a@-bad.org", "a@b", "a b@example.org"):
            self.assertEqual(fields(plan_profile(sample(officer_email=value)))["officer_email"].status, "REVIEW_REQUIRED")

    def test_mobile_needs_explicit_country_context(self):
        row = sample(officer_mobile_number="0712345678")
        self.assertEqual(fields(plan_profile(row))["officer_mobile_number"].status, "REVIEW_REQUIRED")
        self.assertEqual(fields(plan_profile(row, phone_region="LK"))["officer_mobile_number"].value, "+94712345678")
        self.assertEqual(fields(plan_profile(sample(officer_mobile_number="+94712345678")))["officer_mobile_number"].status, "PARSED")

    def test_actual_routing_contract_matches(self):
        contract = Path(__file__).resolve().parents[2] / "docs/field-routing.json"
        data = json.loads(contract.read_text())
        validate_routing(data)
        personal = next(f for f in data["files"] if f["filename"] == "officer_personal_information.csv")
        next(f for f in personal["fields"] if f["source_column"] == "full_name")["target_field"] = "wrong"
        with self.assertRaises(ValueError):
            validate_routing(data)


class ProfilePlanCryptoTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        key = base64.b64encode(b"K" * 32).decode()
        path = Path(self.directory.name) / "keys.json"
        path.write_text(json.dumps({
            "active_encryption_key_version": "v1", "active_lookup_key_version": "v1",
            "encryption_keys": {"v1": key}, "lookup_keys": {"v1": key},
        }))
        self.crypto = IdentityCrypto(path)
        self.backup = IdentityCrypto(path)
        self.binding = dict(officer_uid=uuid4(), raw_record_id="a" * 64)
        self.plan = plan_profile(sample())

    def test_encryption_round_trip_preserves_originals_types_and_unknown_dates(self):
        ciphertext, version = seal_plan(self.crypto, self.plan, **self.binding)
        result = open_plan(self.backup, ciphertext, key_version=version, **self.binding)
        by_name = {f["source_column"]: f for f in result["fields"]}
        self.assertEqual(by_name["height_cm"]["value"], {"type":"decimal", "value":"165.25"})
        self.assertEqual(by_name["date_of_birth"]["value"], {"type":"date", "value":"1990-01-02"})
        self.assertEqual(result["record_classification"], "UNASSESSED")
        self.assertIsNone(result["valid_from"])
        self.assertIsNone(result["measured_at"])
        self.assertNotIn(b"Example Officer", ciphertext)

    def test_tampered_ciphertext_is_rejected(self):
        ciphertext, version = seal_plan(self.crypto, self.plan, **self.binding)
        changed = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            open_plan(self.crypto, changed, key_version=version, **self.binding)

    def test_wrong_officer_or_source_is_rejected(self):
        ciphertext, version = seal_plan(self.crypto, self.plan, **self.binding)
        for binding in (dict(self.binding, officer_uid=uuid4()), dict(self.binding, raw_record_id="b" * 64)):
            with self.assertRaises(InvalidTag):
                open_plan(self.crypto, ciphertext, key_version=version, **binding)

    def test_repeated_encryption_uses_distinct_nonces(self):
        first, _ = seal_plan(self.crypto, self.plan, **self.binding)
        second, _ = seal_plan(self.crypto, self.plan, **self.binding)
        self.assertNotEqual(first[:12], second[:12])


class ProfileDestinationTests(unittest.TestCase):
    def test_optional_missing_groups_are_not_fabricated(self):
        from app.identity.profile_records import logical_records
        records = logical_records(plan_profile(sample()))
        self.assertEqual({r.table for r in records}, {"officer_name_version", "officer_demographic_version", "officer_physical_profile_version"})
        self.assertFalse(any(r.table == "source_assertion" for r in records))

    def test_father_name_is_a_protected_relationship_value(self):
        from app.identity.profile_records import logical_records
        record = next(r for r in logical_records(plan_profile(sample(father_name="Example Parent"))) if r.table == "officer_family_relation")
        self.assertEqual(record.kind, "FATHER")
        self.assertEqual(record.values, {"related_person_name": "Example Parent"})
        self.assertNotIn("Example Parent", repr(record))

    def test_contacts_are_distinct_normalized_records(self):
        from app.identity.profile_records import logical_records
        records = logical_records(plan_profile(sample(officer_email="User@EXAMPLE.ORG", officer_mobile_number="0712345678"), phone_region="LK"))
        contacts = {r.kind:r.values["value"] for r in records if r.table == "officer_contact_version"}
        self.assertEqual(contacts, {"EMAIL":"User@example.org", "MOBILE":"+94712345678"})

    def test_review_required_plan_is_not_importable(self):
        from app.identity.profile_records import logical_records
        with self.assertRaises(ValueError):
            logical_records(plan_profile(sample(religion="Unknown")))

    def test_birth_date_and_measurements_remain_typed_payload_values(self):
        from app.identity.profile_records import logical_records
        records = {r.table:r for r in logical_records(plan_profile(sample()))}
        self.assertEqual(records["officer_demographic_version"].values["date_of_birth"], {"type":"date", "value":"1990-01-02"})
        self.assertEqual(records["officer_physical_profile_version"].values["height_cm"], {"type":"decimal", "value":"165.25"})

    def test_storage_context_changes_for_every_binding(self):
        from app.identity.profile_records import storage_context
        binding = dict(raw_record_id="a"*64, officer_uid=uuid4(), record_id=uuid4(), table="officer_demographic_version")
        first = storage_context("DESTINATION", **binding)
        for changed in (dict(binding, raw_record_id="b"*64), dict(binding, officer_uid=uuid4()), dict(binding, record_id=uuid4()), dict(binding, table="officer_address_version")):
            self.assertNotEqual(first, storage_context("DESTINATION", **changed))

    def test_storage_context_rejects_wrong_purpose_table_and_source(self):
        from app.identity.profile_records import storage_context
        binding = dict(raw_record_id="a"*64, officer_uid=uuid4(), record_id=uuid4(), table="officer_demographic_version")
        for purpose, changed in (("UNSUPPORTED", binding), ("ASSERTION", binding), ("DESTINATION", dict(binding, raw_record_id="invalid")), ("DESTINATION", dict(binding, officer_uid="text"))):
            with self.assertRaises(ValueError):
                storage_context(purpose, **changed)

    def test_storage_ciphertext_cannot_move_to_another_destination(self):
        from app.identity.profile_records import storage_context
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(b"T"*32).decode()
            path = Path(directory)/"keys.json"
            path.write_text(json.dumps({"active_encryption_key_version":"v1", "active_lookup_key_version":"v1", "encryption_keys":{"v1":key}, "lookup_keys":{"v1":key}}))
            crypto = IdentityCrypto(path)
            binding = dict(raw_record_id="a"*64, officer_uid=uuid4(), record_id=uuid4(), table="officer_demographic_version")
            context = storage_context("DESTINATION", **binding)
            ciphertext, version = crypto.encrypt_assertion({"date_of_birth":"1990-01-02"}, context=context)
            moved = storage_context("DESTINATION", **dict(binding, table="officer_address_version"))
            with self.assertRaises(InvalidTag):
                crypto.decrypt_assertion(ciphertext, key_version=version, context=moved)
