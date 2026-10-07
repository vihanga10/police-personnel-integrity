import unittest
from app.identity.station_reference import build_station_index
from app.identity.profile_plan import EXPECTED_COLUMNS, plan_profile


def row(code, name):
    return {"station_code": code, "station_name": name}


class StationReferenceTests(unittest.TestCase):
    def test_unique_name_resolves_and_retains_source(self):
        index = build_station_index([("source-1", row("001", "Example"))])
        self.assertEqual(index.candidates["Example"], ("001",))
        self.assertEqual(index.source_rows["001"], "source-1")

    def test_only_outer_whitespace_is_removed(self):
        index = build_station_index([("source-1", row(" 001 ", " Example Station "))])
        self.assertIn("Example Station", index.candidates)
        self.assertNotIn("example station", index.candidates)
        self.assertNotIn("Example  Station", index.candidates)

    def test_duplicate_code_rejected_even_when_names_match(self):
        for name in ("Example", "Different"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build_station_index([("r1", row("001", "Example")), ("r2", row("001", name))])

    def test_duplicate_source_reference_rejected(self):
        with self.assertRaises(ValueError):
            build_station_index([("r1", row("001", "Example")), ("r1", row("002", "Other"))])

    def test_empty_or_invalid_snapshot_rejected(self):
        for rows in ([], [("r", row("", "A"))], [("r", row("1", ""))], [("r", row(1, "A"))]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                build_station_index(rows)

    def test_multiple_codes_for_one_name_stay_ambiguous(self):
        index = build_station_index([("r1", row("001", "Example")), ("r2", row("002", "Example"))])
        self.assertEqual(index.candidates["Example"], ("001", "002"))
        values = dict.fromkeys(EXPECTED_COLUMNS, "")
        values.update(full_name="Example Officer", present_address_local_police_station_name="Example")
        plan = plan_profile(values, station_candidates=index.candidates)
        station = next(f for f in plan.fields if f.source_column == "present_address_local_police_station_name")
        self.assertEqual(station.status, "REVIEW_REQUIRED")

    def test_unique_match_reaches_planner_without_changing_source(self):
        index = build_station_index([("r1", row("001", "Example"))])
        values = dict.fromkeys(EXPECTED_COLUMNS, "")
        values.update(full_name="Example Officer", present_address_local_police_station_name=" Example ")
        plan = plan_profile(values, station_candidates=index.candidates)
        station = next(f for f in plan.fields if f.source_column == "present_address_local_police_station_name")
        self.assertEqual((station.value, station.status, station.source_value), ("001", "PARSED", " Example "))

    def test_no_fuzzy_matching(self):
        index = build_station_index([("r1", row("001", "Example"))])
        self.assertNotIn("Exampl", index.candidates)
        self.assertNotIn("EXAMPLE", index.candidates)
