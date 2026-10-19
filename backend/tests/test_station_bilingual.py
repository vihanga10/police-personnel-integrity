import copy
import json
import unittest
from app.identity.station_bilingual import components, bilingual_review
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL


def master(name="Example", si="උදාහරණ", code="001"):
    row = dict.fromkeys(HEADERS[MASTER], "")
    row.update(station_code=code, station_name=name, station_name_si=si, division="Division", province="Province")
    return row


def sinhala(label="Example (උදාහරණ)"):
    row = dict.fromkeys(HEADERS[SINHALA], "")
    row.update({LABEL: label, "Division": "Division (අංශය)", "Province ": "Province (පළාත)"})
    return row


def report(master_rows, rows, mode="EXACT_TRIM"):
    return next(r for r in bilingual_review(master_rows, rows)["candidate_comparisons"] if r["mode"] == mode)


class BilingualTests(unittest.TestCase):
    def test_parentheses_both_orders(self):
        for value, first in (("Example (උදාහරණ)", "LATIN"), ("උදාහරණ (Example)", "SINHALA")):
            with self.subTest(first=first):
                shape, pair = components(value)
                self.assertEqual(shape, "PARENTHESIZED:" + first + "_FIRST")
                self.assertEqual(pair, {"LATIN": "Example", "SINHALA": "උදාහරණ"})

    def test_delimiters(self):
        for separator in ("/", "|", " - ", " – ", " — "):
            with self.subTest(separator=separator):
                self.assertEqual(components("Example" + separator + "උදාහරණ")[1], {"LATIN": "Example", "SINHALA": "උදාහරණ"})

    def test_nested_and_multiple_brackets_require_review(self):
        for value in ("Example (උදාහරණ (වචනය))", "Example (උදාහරණ) (වචනය)", "Example (උදාහරණ", "Example [උදාහරණ]", "Example (උදාහරණ) tail"):
            with self.subTest(value=value):
                self.assertIsNone(components(value)[1])

    def test_multiple_delimiters_require_review(self):
        for value in ("Example / උදාහරණ / වචනය", "Example | උදාහරණ / වචනය", "Example - උදාහරණ - වචනය"):
            with self.subTest(value=value):
                self.assertEqual(components(value), ("MULTIPLE_SEPARATORS_REVIEW", None))

    def test_unseparated_mixed_not_guessed(self):
        self.assertEqual(components("Example උදාහරණ"), ("UNSEPARATED_MIXED_SCRIPTS", None))
        self.assertIsNone(components("Example-උදාහරණ")[1])

    def test_same_scripts_and_empty_parts_rejected(self):
        for value in ("Example (Other)", "උදාහරණ (වචනය)", "Example / ", "Example (123)", "Example (උදාහරණ Other)"):
            with self.subTest(value=value):
                self.assertEqual(components(value), ("COMPONENT_SCRIPTS_REVIEW", None))

    def test_missing_and_single_script(self):
        self.assertEqual(components("  "), ("MISSING", None))
        self.assertEqual(components("Example"), ("UNSEPARATED_LATIN", None))

    def test_internal_name_punctuation_preserved(self):
        pair = components("Example-Town (උදාහරණ)")[1]
        self.assertEqual(pair["LATIN"], "Example-Town")
        self.assertEqual(components("Example (උදා\u200dහරණ)")[1]["SINHALA"], "උදා\u200dහරණ")

    def test_unique_joint_and_context(self):
        result = report([master()], [sinhala()])
        self.assertEqual(result["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)
        self.assertEqual(result["unique_joint_context"], {"Division:SAME_REPORTED_LATIN_TEXT": 1, "Province :SAME_REPORTED_LATIN_TEXT": 1})

    def test_disjoint_candidates_never_context_join(self):
        result = report([master(si="වෙනත්"), master(name="Other", code="002")], [sinhala()])
        self.assertEqual(result["observations"]["joint:DISJOINT_CANDIDATES"], 1)
        self.assertEqual(result["unique_joint_context"], {})

    def test_sinhala_collision_can_have_one_joint_candidate(self):
        result = report([master(), master(name="Other", code="002")], [sinhala()])
        self.assertEqual(result["observations"]["SINHALA:MULTIPLE_CANDIDATES"], 1)
        self.assertEqual(result["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)

    def test_duplicate_rows_remain_joint_ambiguous(self):
        result = report([master(), master()], [sinhala()])
        self.assertEqual(result["observations"]["joint:MULTIPLE_JOINT_CANDIDATES"], 1)
        self.assertEqual(result["unique_joint_context"], {})

    def test_one_or_neither_component_matches(self):
        for row, state in ((master(si="වෙනත්"), "ONE_COMPONENT_HAS_CANDIDATES"),
                           (master(name="Other", si="වෙනත්"), "NEITHER_COMPONENT_HAS_CANDIDATES")):
            with self.subTest(state=state):
                self.assertEqual(report([row], [sinhala()])["observations"]["joint:" + state], 1)

    def test_no_casefolding_or_fuzzy_match(self):
        for value in ("example", "Exampl", "Example."):
            with self.subTest(value=value):
                result = report([master()], [sinhala(value + " (උදාහරණ)")])
                self.assertEqual(result["observations"]["LATIN:NO_CANDIDATE"], 1)

    def test_normalization_modes_preserve_originals(self):
        a, b = master(name="Café Town"), sinhala("Cafe\u0301  Town (උදාහරණ)")
        before = copy.deepcopy((a, b))
        self.assertEqual(report([a], [b])["observations"]["LATIN:NO_CANDIDATE"], 1)
        self.assertEqual(report([a], [b], "NFC_TRIM")["observations"]["LATIN:NO_CANDIDATE"], 1)
        self.assertEqual(report([a], [b], "NFC_WHITESPACE")["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)
        self.assertEqual((a, b), before)

    def test_missing_or_different_context_observed(self):
        a, b = master(), sinhala()
        a["division"], b["Province "] = "", "Other (පළාත)"
        self.assertEqual(report([a], [b])["unique_joint_context"], {"Division:MASTER_CONTEXT_MISSING": 1, "Province :DIFFERENT_REPORTED_LATIN_TEXT": 1})

    def test_no_values_in_serialized_report(self):
        a, b = master(name="SecretLabel", code="SecretCode"), sinhala("SecretLabel (උදාහරණ)")
        output = json.dumps(bilingual_review([a], [b]), ensure_ascii=False)
        for secret in ("SecretLabel", "SecretCode", "උදාහරණ", "අංශය", "පළාත"):
            self.assertNotIn(secret, output)

    def test_malformed_rows_rejected(self):
        for a, b in (([], [sinhala()]), ([master()], []), ([dict(master(), station_name=1)], [sinhala()]),
                     ([master()], [{LABEL: "Example"}])):
            with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                bilingual_review(a, b)


if __name__ == "__main__":
    unittest.main()
