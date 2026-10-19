import copy
import json
import unittest
from app.identity.station_brackets import bracket_structure, bracket_review
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL


def master(name="Example (North)", si="උදාහරණ (North)", code="001"):
    row = dict.fromkeys(HEADERS[MASTER], "")
    row.update(station_code=code, station_name=name, station_name_si=si, division="Division", province="Province")
    return row


def source(label="Example (North) (උදාහරණ (North))"):
    row = dict.fromkeys(HEADERS[SINHALA], "")
    row.update({LABEL: label, "Division": "Division (අංශය)", "Province ": "Province (පළාත)"})
    return row


def report(masters, rows, orientation="PREFIX_NAME_TERMINAL_SI", mode="EXACT_TRIM"):
    return next(r for r in bracket_review(masters, rows)["candidate_comparisons"] if r["orientation"] == orientation and r["mode"] == mode)


class BracketTests(unittest.TestCase):
    def test_nested_group_preserves_all_qualifiers(self):
        metadata, pair = bracket_structure("Example (North) (උදාහරණ (North))")
        self.assertEqual(pair, ("Example (North)", "උදාහරණ (North)"))
        self.assertEqual(metadata, dict(state="BALANCED_TERMINAL_GROUP", maximum_depth=2,
            top_level_groups=2, prefix_script="LATIN", terminal_script="MIXED_SCRIPTS"))

    def test_reversed_order_is_separate_hypothesis(self):
        result = report([master()], [source("උදාහරණ (North) (Example (North))")], "PREFIX_SI_TERMINAL_NAME")
        self.assertEqual(result["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)

    def test_unbalanced_brackets_rejected(self):
        for text, state in (("A) (B)", "UNBALANCED_CLOSE"), ("A (B", "UNBALANCED_OPEN")):
            with self.subTest(state=state):
                metadata, pair = bracket_structure(text)
                self.assertEqual(metadata["state"], state)
                self.assertIsNone(pair)

    def test_suffix_other_brackets_and_empty_parts(self):
        for text, state in (("A (B) tail", "TEXT_AFTER_FINAL_GROUP"), ("A [X] (B)", "OTHER_BRACKETS_REVIEW"),
                            ("A ()", "EMPTY_COMPONENT"), ("(B)", "EMPTY_COMPONENT"), ("", "NO_PARENTHESIS_GROUP")):
            with self.subTest(state=state):
                metadata, pair = bracket_structure(text)
                self.assertEqual(metadata["state"], state)
                self.assertIsNone(pair)

    def test_deep_nesting_uses_iterative_scan(self):
        metadata, pair = bracket_structure("A (" + "(" * 1500 + "B" + ")" * 1500 + ")")
        self.assertEqual(metadata["maximum_depth"], 1501)
        self.assertEqual(pair[0], "A")

    def test_only_prior_bracket_review_rows_selected(self):
        result = bracket_review([master()], [source(), source("Example (උදාහරණ)"), source("Example උදාහරණ")])
        self.assertEqual((result["bracket_review_rows"], result["other_rows"]), (1, 2))

    def test_unique_joint_context_is_observation(self):
        result = report([master()], [source()])
        self.assertEqual(result["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)
        self.assertEqual(result["unique_joint_context"], {"Division:SAME_REPORTED_LATIN_TEXT": 1, "Province :SAME_REPORTED_LATIN_TEXT": 1})

    def test_annotation_not_dropped_to_manufacture_match(self):
        result = report([master(name="Example", si="උදාහරණ")], [source()])
        self.assertEqual(result["observations"]["joint:NEITHER_COMPONENT_HAS_CANDIDATES"], 1)

    def test_disjoint_candidates_remain_disjoint(self):
        result = report([master(si="වෙනත්"), master(name="Other", code="002")], [source()])
        self.assertEqual(result["observations"]["joint:DISJOINT_CANDIDATES"], 1)
        self.assertEqual(result["unique_joint_context"], {})

    def test_duplicate_master_rows_stay_ambiguous(self):
        result = report([master(), master(code="002")], [source()])
        self.assertEqual(result["observations"]["joint:MULTIPLE_JOINT_CANDIDATES"], 1)
        self.assertEqual(result["unique_joint_context"], {})

    def test_one_sided_match(self):
        result = report([master(si="වෙනත්")], [source()])
        self.assertEqual(result["observations"]["joint:ONE_COMPONENT_HAS_CANDIDATES"], 1)

    def test_modes_and_originals_preserved(self):
        a, b = master(name="Café (North)"), source("Cafe\u0301  (North) (උදාහරණ (North))")
        before = copy.deepcopy((a, b))
        self.assertEqual(report([a], [b])["observations"]["PREFIX:NO_CANDIDATE"], 1)
        self.assertEqual(report([a], [b], mode="NFC_WHITESPACE")["observations"]["joint:SINGLE_JOINT_CANDIDATE"], 1)
        self.assertEqual((a, b), before)

    def test_case_punctuation_and_format_characters_remain(self):
        for name in ("example (North)", "Example. (North)", "Example\u200d (North)"):
            with self.subTest(name=name):
                self.assertEqual(report([master(name=name)], [source()])["observations"]["PREFIX:NO_CANDIDATE"], 1)

    def test_no_values_in_report(self):
        output = json.dumps(bracket_review([master(code="PRIVATE_CODE")], [source()]), ensure_ascii=False)
        for value in ("Example", "North", "උදාහරණ", "PRIVATE_CODE"):
            self.assertNotIn(value, output)

    def test_empty_selected_set_valid(self):
        result = bracket_review([master()], [source("Example (උදාහරණ)")])
        self.assertEqual(result["bracket_review_rows"], 0)
        self.assertTrue(all(not r["observations"] for r in result["candidate_comparisons"]))

    def test_invalid_rows_rejected(self):
        for a, b in (([], [source()]), ([master()], []), ([dict(master(), station_name=1)], [source()]), ([master()], [{}])):
            with self.subTest(a=a, b=b), self.assertRaises(ValueError):
                bracket_review(a, b)


if __name__ == "__main__":
    unittest.main()
