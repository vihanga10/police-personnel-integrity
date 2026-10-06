"""Policy tests without database connections or production encryption keys."""

import unittest
from dataclasses import FrozenInstanceError

from app.security.record_protection import (
    POLICY_VERSION,
    AssignmentProtection as A,
    DisclosureCategory as D,
    ProtectionLevel as P,
    RecordClassification as R,
    required_protection,
)


def decide(assignment, record_classification, category=D.PERSONNEL_DETAILS):
    return required_protection(
        assignment=assignment,
        record_classification=record_classification,
        category=category,
    )


class RecordProtectionTests(unittest.TestCase):
    def test_ordinary_record_requires_base_authorization(self):
        result = decide(A.ORDINARY, R.ORDINARY)
        self.assertEqual(result.level, P.NORMAL)
        self.assertEqual(result.reason_code, "ORDINARY_RECORD_REQUIRES_BASE_ACCESS")

    def test_current_sensitive_assignment_restricts_ordinary_record(self):
        self.assertEqual(decide(A.CID_CCIB, R.ORDINARY).level, P.RESTRICTED)

    def test_transfer_does_not_release_sensitive_history(self):
        before = decide(A.CID_CCIB, R.CID_CCIB_RESTRICTED)
        after = decide(A.ORDINARY, R.CID_CCIB_RESTRICTED)
        self.assertEqual(before.level, P.RESTRICTED)
        self.assertEqual(after.level, P.RESTRICTED)
        self.assertEqual(after.reason_code, "PERSISTENT_CID_CCIB_RESTRICTION")

    def test_transfer_allows_normal_treatment_of_assessed_ordinary_record(self):
        self.assertEqual(decide(A.CID_CCIB, R.ORDINARY).level, P.RESTRICTED)
        self.assertEqual(decide(A.ORDINARY, R.ORDINARY).level, P.NORMAL)

    def test_unresolved_assignment_withholds_details(self):
        for classification in R:
            with self.subTest(classification=classification):
                self.assertEqual(decide(A.UNRESOLVED, classification).level, P.WITHHOLD)

    def test_unassessed_history_is_not_made_ordinary_by_transfer(self):
        for assignment in A:
            with self.subTest(assignment=assignment):
                self.assertEqual(decide(assignment, R.UNASSESSED).level, P.WITHHOLD)

    def test_identity_exception_only_requires_normal_access(self):
        for assignment in A:
            for classification in R:
                with self.subTest(assignment=assignment, classification=classification):
                    result = decide(assignment, classification, D.OFFICER_NAME_NIC)
                    self.assertEqual(result.level, P.NORMAL)
                    self.assertEqual(result.reason_code, "IDENTITY_PROJECTION_REQUIRES_BASE_ACCESS")

    def test_invalid_assignment_is_rejected_even_for_identity(self):
        for invalid in (None, "ORDINARY", False, "CID"):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                decide(invalid, R.ORDINARY, D.OFFICER_NAME_NIC)

    def test_invalid_classification_is_rejected(self):
        for invalid in (None, "ORDINARY", A.ORDINARY):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                decide(A.ORDINARY, invalid)

    def test_invalid_category_is_rejected(self):
        for invalid in (None, "OFFICER_NAME_NIC", "family_name"):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                decide(A.ORDINARY, R.ORDINARY, invalid)

    def test_decision_is_immutable_and_identifies_policy(self):
        result = decide(A.ORDINARY, R.ORDINARY)
        self.assertEqual(result.policy_version, POLICY_VERSION)
        with self.assertRaises(FrozenInstanceError):
            result.level = P.RESTRICTED

    def test_omitted_assessment_is_rejected(self):
        with self.assertRaises(TypeError):
            required_protection(assignment=A.ORDINARY, category=D.PERSONNEL_DETAILS)
