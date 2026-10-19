"""Versioned category and birth-date rules for reported PF profile values.

These rules interpret supplied values; they do not establish source truth.
The caller must preserve original values in encrypted source assertions.
"""

import re
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType

PROFILE_VALUE_POLICY = "PF_PROFILE_VALUES_V1"

# These are application codes, not claims of an external coding standard.
CATEGORY_MAPS = MappingProxyType({
    "gender": MappingProxyType({"Female": "FEMALE", "Male": "MALE"}),
    "nationality": MappingProxyType({"Sri Lankan": "SRI_LANKAN"}),
    "religion": MappingProxyType({
        "Buddhism": "BUDDHISM", "Christianity": "CHRISTIANITY",
        "Hinduism": "HINDUISM", "Islam": "ISLAM",
        "Roman Catholic": "ROMAN_CATHOLIC",
    }),
    "marital_status": MappingProxyType({"Married": "MARRIED", "Single": "SINGLE"}),
    "blood_group": MappingProxyType({
        value: value for value in ("A+", "A-", "AB+", "AB-", "B+", "B-", "O+", "O-")
    }),
})


@dataclass(frozen=True)
class ProfileValue:
    """A parsed value and safe issue codes, with no original source text."""

    value: str | date | None
    status: str
    issues: tuple[str, ...] = ()
    policy_version: str = PROFILE_VALUE_POLICY


def map_category(field: str, supplied: str | None) -> ProfileValue:
    """Map exact documented labels after trimming outer whitespace only."""
    if field not in CATEGORY_MAPS:
        raise ValueError("Unsupported profile category field.")
    if supplied is None:
        return ProfileValue(None, "MISSING")
    if not isinstance(supplied, str):
        return ProfileValue(None, "REVIEW_REQUIRED", ("INVALID_TEXT_TYPE",))
    label = supplied.strip()
    if not label:
        return ProfileValue(None, "MISSING")
    code = CATEGORY_MAPS[field].get(label)
    if code is None:
        # Never infer a category from spelling similarity or partial matches.
        return ProfileValue(None, "REVIEW_REQUIRED", ("UNMAPPED_CATEGORY",))
    return ProfileValue(code, "PARSED")


def parse_birth_date(supplied: str | None, *, snapshot_date: date | None = None) -> ProfileValue:
    """Parse calendar dates; check chronology only against a documented snapshot.

A missing snapshot does not prevent storing a syntactically valid date, but
chronology remains explicitly unassessed. Import time is never substituted.
    """
    if snapshot_date is not None and type(snapshot_date) is not date:
        raise ValueError("Snapshot date must be a date without a time component.")
    if supplied is None:
        return ProfileValue(None, "MISSING")
    if not isinstance(supplied, str):
        return ProfileValue(None, "REVIEW_REQUIRED", ("INVALID_TEXT_TYPE",))
    value = supplied.strip()
    if not value:
        return ProfileValue(None, "MISSING")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        return ProfileValue(None, "REVIEW_REQUIRED", ("UNSUPPORTED_DATE_FORMAT",))
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return ProfileValue(None, "REVIEW_REQUIRED", ("INVALID_CALENDAR_DATE",))
    if snapshot_date is None:
        return ProfileValue(parsed, "PARSED", ("SNAPSHOT_DATE_UNAVAILABLE",))
    if parsed > snapshot_date:
        return ProfileValue(None, "REVIEW_REQUIRED", ("BIRTH_AFTER_SNAPSHOT",))
    return ProfileValue(parsed, "PARSED")
