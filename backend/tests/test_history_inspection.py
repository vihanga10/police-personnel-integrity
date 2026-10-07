"""Date observations must not conceal invalid calendars or resolve ambiguous order."""
import pytest
from app.identity.inspect_history_sources import HEADERS, date_shape


@pytest.mark.parametrize("value,expected", [
    ("", "MISSING"), ("  ", "MISSING"),
    ("2024-02-29", "ISO_CALENDAR_DATE"),
    ("2023-02-29", "INVALID_ISO_CALENDAR_DATE"),
    ("2026-13-01", "INVALID_ISO_CALENDAR_DATE"),
    ("01/02/2020", "SLASH_DATE_ORDER_AMBIGUOUS"),
    ("02/02/2020", "SLASH_DATE_ORDER_UNCONFIRMED"),
    ("29/02/2024", "SLASH_DAY_FIRST_ONLY"),
    ("02/29/2024", "SLASH_MONTH_FIRST_ONLY"),
    ("29/02/2023", "INVALID_SLASH_CALENDAR_DATE"),
    ("31/04/2020", "INVALID_SLASH_CALENDAR_DATE"),
    ("0000-01-01", "INVALID_ISO_CALENDAR_DATE"),
    ("01-02-2020", "OTHER_DATE_TEXT"),
    ("2020-01-01T00:00:00Z", "OTHER_DATE_TEXT"),
])
def test_conservative_date_shape(value, expected):
    assert date_shape(value) == expected


def test_inspection_contract_contains_both_history_sources():
    assert set(HEADERS) == {"transfer_history.csv", "promotion_history.csv"}
    assert len(HEADERS["transfer_history.csv"]) == 35
    assert len(HEADERS["promotion_history.csv"]) == 21
    for header in HEADERS.values():
        assert len(header) == len(set(header))
        assert {"officer_nic_no", "from_rank", "to_rank", "effective_date"}.issubset(header)
