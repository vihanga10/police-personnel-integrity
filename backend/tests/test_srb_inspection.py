"""SRB date observations stay conservative and aggregate contracts stay fixed."""
import pytest
from app.identity.inspect_srb_sources import HEADERS, interval_observation


@pytest.mark.parametrize("start,end,expected", [
    ("2020-01-02", "2020-01-01", "END_BEFORE_START"),
    ("2020-01-01", "2020-01-01", "SAME_DATE"),
    ("2020-01-01", "2020-01-02", "END_AFTER_START"),
    ("2020-01-01", "", "ENDPOINT_MISSING_OR_NON_ISO"),
    ("01/02/2020", "2020-03-01", "ENDPOINT_MISSING_OR_NON_ISO"),
    ("2023-02-29", "2023-03-01", "ENDPOINT_MISSING_OR_NON_ISO"),
])
def test_interval_does_not_infer_periods_from_unconfirmed_dates(start, end, expected):
    assert interval_observation(start, end) == expected


def test_source_contracts_match_received_inventory():
    assert {name: len(header) for name, header in HEADERS.items()} == {
        "officer_police_numbers.csv": 9,
        "officer_restrictions.csv": 24,
        "restriction_overrides.csv": 10,
    }
    for header in HEADERS.values():
        assert len(header) == len(set(header))
        assert "officer_nic_no" in header
