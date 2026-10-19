import copy
import json
import unittest
from app.identity.station_vocabulary import (HEADERS, MASTER, SINHALA, LABEL, comparison,
    script_shape, label_shapes, review, validate_recovered)


def master(name="Example", sinhala="උදාහරණ", code="001", division="Division", province="Province"):
    result = dict.fromkeys(HEADERS[MASTER], "")
    result.update(station_code=code, station_name=name, station_name_si=sinhala,
                  division=division, province=province, latitude="6.9", longitude="79.9")
    return result


def sinhala(name="උදාහරණ", division="Division", province="Province"):
    return {LABEL: name, "Division": division, "Province ": province, "Latitude": "6.9", "Longitude": "79.9"}


def match(result, field="station_name_si", mode="EXACT_TRIM"):
    return next(r for r in result["comparison_candidates"] if r["target_field"] == field and r["mode"] == mode)


class StationVocabularyTests(unittest.TestCase):
    def test_exact_unique_candidate_with_context(self):
        result = match(review([master()], [sinhala()]))
        self.assertEqual(result["observations"], {"SINGLE_CANDIDATE": 1})
        self.assertEqual(result["unique_candidate_context"], {"Division:SAME_REPORTED_TEXT": 1, "Province :SAME_REPORTED_TEXT": 1})

    def test_other_master_name_field_is_separate_candidate(self):
        result = review([master()], [sinhala("Example")])
        self.assertEqual(match(result)["observations"], {"NO_CANDIDATE": 1})
        self.assertEqual(match(result, "station_name")["observations"], {"SINGLE_CANDIDATE": 1})

    def test_nfc_only_changes_derived_comparison(self):
        a, b = master(sinhala="Café"), sinhala("Cafe\u0301")
        before = copy.deepcopy((a, b))
        result = review([a], [b])
        self.assertEqual(match(result)["observations"], {"NO_CANDIDATE": 1})
        self.assertEqual(match(result, mode="NFC_TRIM")["observations"], {"SINGLE_CANDIDATE": 1})
        self.assertEqual((a, b), before)

    def test_collapsed_whitespace_is_separate(self):
        result = review([master(sinhala="Example Station")], [sinhala(" Example\t Station ")])
        self.assertEqual(match(result, mode="NFC_TRIM")["observations"], {"NO_CANDIDATE": 1})
        self.assertEqual(match(result, mode="NFC_WHITESPACE")["observations"], {"SINGLE_CANDIDATE": 1})

    def test_repeated_names_stay_ambiguous(self):
        result = match(review([master(), master(code="002")], [sinhala()]))
        self.assertEqual(result["observations"], {"MULTIPLE_CANDIDATES": 1})
        self.assertEqual(result["unique_candidate_context"], {})

    def test_normalization_collision_stays_ambiguous(self):
        result = review([master(sinhala="Café"), master(sinhala="Cafe\u0301", code="002")], [sinhala("Café")])
        self.assertEqual(match(result, mode="NFC_TRIM")["observations"], {"MULTIPLE_CANDIDATES": 1})

    def test_no_case_punctuation_fuzzy_or_transliteration(self):
        for value in ("example", "Example.", "Exampl", "උදාහරණ"):
            with self.subTest(value=value):
                result = review([master(name="Example", sinhala="Different")], [sinhala(value)])
                for candidate in result["comparison_candidates"]:
                    self.assertEqual(candidate["observations"], {"NO_CANDIDATE": 1})

    def test_missing_values_do_not_match(self):
        result = review([master(sinhala="")], [sinhala("  ")])
        self.assertEqual(match(result)["observations"], {"MISSING": 1})

    def test_script_shapes_and_control_presence(self):
        for value, expected in (("", "MISSING"), ("123", "NO_LETTERS"), ("උදාහරණ", "SINHALA"),
                                ("Example", "LATIN"), ("駅", "OTHER"), ("Station උදාහරණ", "MIXED_SCRIPTS")):
            with self.subTest(expected=expected):
                self.assertEqual(script_shape(value), expected)
        self.assertEqual(label_shapes(["A\u200dB"])["control_or_format:TRUE"], 1)
        self.assertEqual(comparison("A\u200dB", "NFC_WHITESPACE"), "A\u200dB")

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            comparison("A", "FUZZY")

    def test_context_missing_and_difference_preserved(self):
        result = match(review([master(division="", province="Other")], [sinhala()]))
        self.assertEqual(result["unique_candidate_context"], {"Division:MISSING_CONTEXT": 1, "Province :DIFFERENT_REPORTED_TEXT": 1})

    def test_no_label_code_or_coordinates_in_output(self):
        a, b = master(name="PRIVATE_LABEL", sinhala="SECRET_LABEL", code="CODE_SECRET"), sinhala("SECRET_LABEL")
        output = json.dumps(review([a], [b]))
        for value in ("PRIVATE_LABEL", "SECRET_LABEL", "CODE_SECRET", "79.9", "6.9"):
            self.assertNotIn(value, output)

    def test_coordinate_invalid_and_out_of_range(self):
        a, b = master(), sinhala()
        a["latitude"], b["Longitude"] = "NaN", "181"
        result = review([a], [b])
        coordinates = {(r["filename"], r["field"]): r["observations"] for r in result["coordinate_shapes"]}
        self.assertNotIn("WITHIN_DECIMAL_DEGREE_RANGE", coordinates[(MASTER, "latitude")])
        self.assertNotIn("WITHIN_DECIMAL_DEGREE_RANGE", coordinates[(SINHALA, "Longitude")])

    def test_bad_or_empty_header_coverage_rejected(self):
        with self.assertRaises(ValueError):
            review([], [sinhala()])
        b = sinhala(); b["Province"] = b.pop("Province ")
        with self.assertRaises(ValueError):
            review([master()], [b])

    def test_station_codes_preserve_leading_zeros(self):
        result = review([master(code="001"), master(code="1")], [sinhala()])
        key = next(r for r in result["key_shapes"] if r["field"] == "station_code" and r["mode"] == "EXACT_TRIM")
        self.assertEqual((key["distinct_nonempty"], key["repeated_rows"]), (2, 0))

    def test_recovery_guards_each_provenance_and_sequence_field(self):
        file = dict(batch_id="B", archive_path="folder/station_master.csv", source_file_sha256="hash", import_file_id="file", columns=list(HEADERS[MASTER]))
        raw = dict(file, source_row_number=1)
        original = dict(columns=file["columns"], values=list(master().values()))
        self.assertEqual(validate_recovered(file, raw, 1, original, copy.deepcopy(original)), master())
        for key in ("batch_id", "archive_path", "source_file_sha256", "import_file_id", "source_row_number"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_recovered(file, dict(raw, **{key: "different"}), 1, original, original)

    def test_unequal_backup_and_changed_header_rejected(self):
        file = dict(batch_id="B", archive_path="p", source_file_sha256="h", import_file_id="f", columns=["a"])
        raw = dict(file, source_row_number=1)
        for original, backup in ((dict(columns=["a"], values=["v"]), dict(columns=["a"], values=["w"])),
                                 (dict(columns=["b"], values=["v"]), dict(columns=["b"], values=["v"]))):
            with self.subTest(original=original), self.assertRaises(ValueError):
                validate_recovered(file, raw, 1, original, backup)

    def test_nontext_and_cell_count_mismatch_rejected(self):
        file = dict(batch_id="B", archive_path="p", source_file_sha256="h", import_file_id="f", columns=["a"])
        raw = dict(file, source_row_number=1)
        for values in ([1], [], ["a", "b"]):
            original = dict(columns=["a"], values=values)
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_recovered(file, raw, 1, original, original)


if __name__ == "__main__":
    unittest.main()
