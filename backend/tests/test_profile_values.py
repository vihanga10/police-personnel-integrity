"""Test source-label distinctions and strict birth-date interpretation."""

from datetime import date, datetime

import pytest

from app.identity.profile_values import map_category, parse_birth_date


@pytest.mark.parametrize("field,supplied,expected", [
    ("gender", "Female", "FEMALE"),
    ("gender", "Male", "MALE"),
    ("nationality", "Sri Lankan", "SRI_LANKAN"),
    ("religion", "Buddhism", "BUDDHISM"),
    ("religion", "Christianity", "CHRISTIANITY"),
    ("religion", "Hinduism", "HINDUISM"),
    ("religion", "Islam", "ISLAM"),
    ("religion", "Roman Catholic", "ROMAN_CATHOLIC"),
    ("marital_status", "Married", "MARRIED"),
    ("marital_status", "Single", "SINGLE"),
    *[("blood_group", value, value) for value in
      ("A+", "A-", "AB+", "AB-", "B+", "B-", "O+", "O-")],
])
def test_documented_categories(field, supplied, expected):
    result = map_category(field, supplied)
    assert result.value == expected
    assert result.status == "PARSED" and result.issues == ()
    assert result.policy_version == "PF_PROFILE_VALUES_V1"


def test_unknown_and_altered_labels_remain_reviewable():
    for supplied in ("female", "F", "Unknown", "Roman  Catholic"):
        result = map_category("gender", supplied)
        assert result.value is None
        assert result.status == "REVIEW_REQUIRED"
        assert result.issues == ("UNMAPPED_CATEGORY",)


def test_only_outer_whitespace_is_trimmed():
    assert map_category("religion", " Roman Catholic ").value == "ROMAN_CATHOLIC"
    assert map_category("religion", "Roman  Catholic").status == "REVIEW_REQUIRED"


def test_missing_values_are_not_inferred():
    for supplied in (None, "", "  "):
        assert map_category("gender", supplied).status == "MISSING"
        assert parse_birth_date(supplied).status == "MISSING"


def test_wrong_types_are_flagged_without_source_values():
    assert map_category("gender", 42).issues == ("INVALID_TEXT_TYPE",)
    assert parse_birth_date(42).issues == ("INVALID_TEXT_TYPE",)
    with pytest.raises(ValueError):
        map_category("unknown_field", "Male")


def test_calendar_date_without_snapshot_is_explicitly_limited():
    result = parse_birth_date("2000-02-29")
    assert result.value == date(2000, 2, 29)
    assert result.status == "PARSED"
    assert result.issues == ("SNAPSHOT_DATE_UNAVAILABLE",)


def test_invalid_calendar_date_is_rejected():
    assert parse_birth_date("2001-02-29").issues == ("INVALID_CALENDAR_DATE",)


def test_ambiguous_and_noncanonical_dates_are_rejected():
    for supplied in ("01/02/2000", "2000-2-01", "20000201", "2000-02-01T00:00:00"):
        result = parse_birth_date(supplied)
        assert result.value is None
        assert result.issues == ("UNSUPPORTED_DATE_FORMAT",)


def test_documented_snapshot_controls_chronology():
    snapshot = date(2020, 1, 1)
    assert parse_birth_date("2000-01-01", snapshot_date=snapshot).issues == ()
    assert parse_birth_date("2020-01-01", snapshot_date=snapshot).issues == ()
    result = parse_birth_date("2020-01-02", snapshot_date=snapshot)
    assert result.value is None and result.issues == ("BIRTH_AFTER_SNAPSHOT",)


def test_datetime_is_not_silently_used_as_snapshot_date():
    with pytest.raises(ValueError):
        parse_birth_date("2000-01-01", snapshot_date=datetime(2020, 1, 1))
