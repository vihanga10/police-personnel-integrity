"""Test conservative matching rules and preservation of identifier text."""

import pytest

from app.identity.normalization import (
    IdentifierInputError,
    NORMALIZATION_PROFILE,
    normalize_identifier,
)


def test_trims_outer_whitespace_and_preserves_leading_zeros():
    result = normalize_identifier(
        "  00123  ", identifier_type="POLICE_ID"
    )
    assert result.value == "00123"
    assert result.normalization_profile == NORMALIZATION_PROFILE


def test_preserves_internal_punctuation_spaces_and_case():
    result = normalize_identifier(
        "  Ab-01 23  ", identifier_type="REGIMENTAL_NUMBER"
    )
    assert result.value == "Ab-01 23"


def test_does_not_guess_case_equivalence():
    first = normalize_identifier("examplev", identifier_type="NIC")
    second = normalize_identifier("exampleV", identifier_type="NIC")
    assert first.value != second.value


def test_missing_identifier_is_rejected():
    with pytest.raises(IdentifierInputError, match="missing"):
        normalize_identifier(None, identifier_type="NIC")


def test_empty_identifier_is_rejected():
    with pytest.raises(IdentifierInputError, match="empty"):
        normalize_identifier("   ", identifier_type="NIC")


def test_numeric_input_is_rejected():
    with pytest.raises(IdentifierInputError, match="text"):
        normalize_identifier(123, identifier_type="POLICE_ID")


def test_internal_control_character_is_rejected():
    with pytest.raises(IdentifierInputError, match="control character"):
        normalize_identifier("12\x0034", identifier_type="TIN")


def test_unsupported_identifier_type_is_rejected():
    with pytest.raises(IdentifierInputError, match="Unsupported"):
        normalize_identifier("example", identifier_type="UNKNOWN")


def test_default_representation_does_not_expose_identifier():
    result = normalize_identifier(
        "PRIVATE-TEST-VALUE", identifier_type="POLICE_ID"
    )
    assert "PRIVATE-TEST-VALUE" not in repr(result)