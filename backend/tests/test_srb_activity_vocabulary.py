"""Regress privacy-safe vocabulary and missing-block observations."""
from collections import Counter
import pytest
from app.identity.inspect_srb_activity_vocabulary import (
    rank_label, boolean_label, status_label, h2_shape, total_observation,
    observe, HEADERS, H2_CORE, EXPECTED_ROWS,
)

@pytest.mark.parametrize("value,expected", [("ASP", "ASP"), (" SP ", "SP"),
    ("Assistant Superintendent of Police", "Assistant Superintendent of Police"),
    ("", "MISSING"), ("TEST PERSON NAME", "UNREVIEWED_TEXT")])
def test_rank_label_is_observed_without_guessing(value, expected):
    assert rank_label(value) == expected

@pytest.mark.parametrize("value,expected", [("TRUE", "TRUE"), ("False", "False"),
    ("yes", "yes"), ("0", "0"), ("", "MISSING"), ("TEST NIC", "OTHER_TEXT")])
def test_boolean_spelling_remains_unconverted(value, expected):
    assert boolean_label(value) == expected

@pytest.mark.parametrize("populated,expected", [(0, "ALL_CORE_MISSING"), (1, "PARTIAL_CORE"),
    (len(H2_CORE), "ALL_CORE_PRESENT")])
def test_h2_core_shape_has_no_completion_claim(populated, expected):
    row = dict.fromkeys(H2_CORE, "")
    for key in H2_CORE[:populated]:
        row[key] = "TEST"
    assert h2_shape(row) == expected

@pytest.mark.parametrize("h2,annual,expected", [("", "20", "YEAR_EQUALS_REPORTED_H1_WITH_H2_MISSING"),
    ("", "21", "YEAR_DIFFERS_FROM_REPORTED_H1_WITH_H2_MISSING"),
    ("10", "30", "YEAR_EQUALS_REPORTED_H1_PLUS_H2"),
    ("10", "31", "YEAR_DIFFERS_FROM_REPORTED_H1_PLUS_H2"),
    ("10", "NaN", "UNCOMPARABLE_TOTALS"), ("10", "PRIVATE TEXT", "UNCOMPARABLE_TOTALS")])
def test_arithmetic_observation_never_fills_missing_h2(h2, annual, expected):
    row = dict.fromkeys(H2_CORE, "")
    row.update(h1_total_points="20", h2_total_points=h2, year_total_points=annual)
    assert total_observation(row) == expected
    assert row["h2_total_points"] == h2


def test_missing_core_with_signature_is_reported_without_exposing_signature():
    row = dict.fromkeys(HEADERS["officer_firearms_expertise.csv"], "")
    row.update(h2_supervisor_police_signature="TEST PRIVATE SIGNATURE", record_status="PRIVATE STATUS", h1_total_points="20", year_total_points="20")
    counts = {name: Counter() for name in ("rank_labels", "accused_text_labels", "h2_block_shapes",
        "h2_signature_context", "h2_status_context", "reported_total_relationships")}
    observe("officer_firearms_expertise.csv", row, counts)
    assert counts["h2_signature_context"] == {"ALL_CORE_MISSING:PRESENT": 1}
    assert counts["h2_status_context"] == {"ALL_CORE_MISSING:OTHER_REPORTED_STATUS": 1}
    assert "PRIVATE" not in str(counts)


def test_review_scope_matches_completed_inspection():
    assert sum(EXPECTED_ROWS.values()) == 36265
    assert status_label("PERSON NAME") == "OTHER_REPORTED_STATUS"
