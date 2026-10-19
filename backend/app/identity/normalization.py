"""Conservative identifier normalization for protected exact matching."""

from dataclasses import dataclass, field


NORMALIZATION_PROFILE = "IDENTIFIER_EXACT_TEXT_V1"
SUPPORTED_TYPES = frozenset({
    "NIC",
    "POLICE_ID",
    "REGIMENTAL_NUMBER",
    "TIN",
})


class IdentifierInputError(ValueError):
    """An identifier cannot be used by this normalization profile."""


@dataclass(frozen=True)
class NormalizedIdentifier:
    """A normalized value that must remain inside the protected boundary."""

    identifier_type: str
    # Exclude the personal value from default object representations.
    value: str = field(repr=False)
    normalization_profile: str = NORMALIZATION_PROFILE


def normalize_identifier(
    value: str | None,
    *,
    identifier_type: str,
) -> NormalizedIdentifier:
    """Trim surrounding whitespace without guessing identifier equivalence."""
    if identifier_type not in SUPPORTED_TYPES:
        raise IdentifierInputError("Unsupported identifier type.")

    if value is None:
        raise IdentifierInputError("Identifier is missing.")

    # Reject numeric input: converting it might conceal lost leading zeros.
    if not isinstance(value, str):
        raise IdentifierInputError("Identifier must be supplied as text.")

    normalized = value.strip()
    if not normalized:
        raise IdentifierInputError("Identifier is empty.")

    # Reject remaining control characters rather than silently removing them.
    if any(ord(character) < 32 or ord(character) == 127
           for character in normalized):
        raise IdentifierInputError("Identifier contains a control character.")

    # Do not change case, remove punctuation, convert formats or infer identity.
    return NormalizedIdentifier(
        identifier_type=identifier_type,
        value=normalized,
    )