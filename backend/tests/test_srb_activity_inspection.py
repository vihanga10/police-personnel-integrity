"""Check conservative SRB activity shape observations and fixed source contracts."""
import pytest
from app.identity.inspect_srb_activity_sources import (
    HEADERS, ACTOR_FIELDS, DATES, NUMERIC_FIELDS, REFERENCE_FIELDS,
    SOURCE_KEYS, RANK_FIELDS, BOOLEAN_FIELDS, numeric_shape, presence_shape,
)

@pytest.mark.parametrize("text,expected", [
    ("", "MISSING"), ("  ", "MISSING"), ("0", "ZERO"), ("-0.01", "NEGATIVE"),
    ("0012", "POSITIVE"), ("12.50", "POSITIVE"), ("NaN", "NONFINITE"),
    ("Infinity", "NONFINITE"), ("-Infinity", "NONFINITE"), ("person name", "NONNUMERIC_TEXT"),
    ("12,500", "NONNUMERIC_TEXT"),
])
def test_numeric_shapes_never_echo_text_or_interpret_units(text, expected):
    assert numeric_shape(text) == expected

@pytest.mark.parametrize("text,expected", [("", "MISSING"), ("  ", "MISSING"),
    ("signature image reference", "PRESENT"), ("TEST-PAPER", "PRESENT")])
def test_presence_does_not_claim_authenticity(text, expected):
    assert presence_shape(text) == expected

@pytest.mark.parametrize("filename,count", [
    ("officer_duty_periods.csv", 17), ("officer_firearms_expertise.csv", 41),
    ("good_conduct_register.csv", 33), ("bad_conduct_register.csv", 31),
])
def test_exact_contract_coverage(filename, count):
    header = HEADERS[filename]
    assert len(header) == len(set(header)) == count
    assert "officer_nic_no" in header and SOURCE_KEYS[filename] in header
    for mapping in (ACTOR_FIELDS, DATES, NUMERIC_FIELDS, REFERENCE_FIELDS, RANK_FIELDS, BOOLEAN_FIELDS):
        assert set(mapping[filename]) <= set(header)
    assert "officer_nic_no" not in ACTOR_FIELDS[filename]


def test_sensitive_free_text_not_used_as_output_categories():
    for mapping in (RANK_FIELDS, BOOLEAN_FIELDS, NUMERIC_FIELDS):
        for fields in mapping.values():
            assert not any(name.endswith("_name") or name in {"reason", "nature_of_offence", "punishment_imposed"} for name in fields)
    assert "period_recorded_by_authority_nic" in ACTOR_FIELDS["officer_duty_periods.csv"]
    assert "annual_supervisor_nic" in ACTOR_FIELDS["officer_firearms_expertise.csv"]
    assert "sanctioning_authority_nic" in ACTOR_FIELDS["good_conduct_register.csv"]
