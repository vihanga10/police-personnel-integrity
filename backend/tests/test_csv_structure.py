"""Test exact headers, encoding and logical CSV record validation."""

from io import BytesIO

import pytest

from app.intake.csv_structure import (
    CsvStructureError,
    validate_csv_structure,
)


def validate(data, *, columns=None, rows=1, encoding="UTF-8"):
    """Validate test bytes with explicit expectations."""
    return validate_csv_structure(
        BytesIO(data),
        declared_encoding=encoding,
        delimiter=",",
        expected_columns=columns if columns is not None else ["id", "note"],
        expected_row_count=rows,
    )


def test_quoted_multiline_record():
    """A quoted newline belongs to one logical record."""
    result = validate(b'id,note\r\n1,"first\nsecond"\r\n')
    assert result.row_count == 1


def test_sinhala_bom_and_header_space():
    """Decode the BOM while preserving the trailing header space."""
    data = "Province ,Station\nබස්නාහිර,Example\n".encode("utf-8-sig")
    result = validate(
        data,
        columns=["Province ", "Station"],
        encoding="UTF-8-BOM",
    )
    assert result.columns[0] == "Province "


def test_header_space_mismatch():
    """Header normalization must not hide a source difference."""
    with pytest.raises(CsvStructureError, match="header differs"):
        validate(b"id ,note\n1,example\n")


def test_wrong_row_width():
    """Reject an extra field without printing its contents."""
    with pytest.raises(CsvStructureError, match="expected 2 fields; found 3"):
        validate(b"id,note\n1,example,extra\n")


def test_wrong_row_count():
    """Compare actual logical records with the manifest count."""
    with pytest.raises(CsvStructureError, match="Row count differs"):
        validate(b"id,note\n1,example\n", rows=2)


def test_invalid_utf8():
    """Reject invalid bytes instead of replacing characters."""
    with pytest.raises(CsvStructureError, match="cannot be decoded"):
        validate(b"id,note\n1,\xff\n")


def test_missing_declared_bom():
    """A declared BOM must actually exist."""
    with pytest.raises(CsvStructureError, match="BOM"):
        validate(b"id,note\n1,example\n", encoding="UTF-8-BOM")


def test_unclosed_quoted_field():
    """Reject an unfinished quoted field."""
    with pytest.raises(CsvStructureError, match="parsing failed"):
        validate(b'id,note\n1,"unfinished\n')