"""Validate CSV structure without retaining or displaying personnel values."""

import codecs
import csv
import io
from dataclasses import dataclass
from typing import BinaryIO


class CsvStructureError(ValueError):
    """Raised when CSV bytes do not match the declared structural contract."""


@dataclass(frozen=True)
class CsvStructureResult:
    """Counts and headers from a successfully validated CSV."""

    columns: tuple[str, ...]
    row_count: int
    encoding: str


def validate_csv_structure(
    stream: BinaryIO,
    *,
    declared_encoding: str,
    delimiter: str,
    expected_columns: list[str],
    expected_row_count: int,
) -> CsvStructureResult:
    """Read a CSV from its beginning, checking every logical data record."""
    # Explicitly support the encoding labels used by this intake package.
    encodings = {
        "UTF-8": "utf-8",
        "UTF-8-BOM": "utf-8-sig",
    }
    if declared_encoding not in encodings:
        raise ValueError("Unsupported declared CSV encoding.")

    if delimiter != ",":
        raise ValueError("This CSV contract currently supports comma delimiters.")

    if (
        not expected_columns
        or any(not isinstance(name, str) or not name.strip()
               for name in expected_columns)
        or len(expected_columns) != len(set(expected_columns))
    ):
        raise ValueError("Expected headers must be nonempty and unique.")

    if type(expected_row_count) is not int or expected_row_count < 0:
        raise ValueError("Expected row count must be a nonnegative integer.")

    # Peek at the BOM without consuming it. The wrapper owns no caller resources.
    buffered = io.BufferedReader(stream)
    text_stream = None
    try:
        has_bom = buffered.peek(3).startswith(codecs.BOM_UTF8)
        expects_bom = declared_encoding == "UTF-8-BOM"
        if has_bom != expects_bom:
            raise CsvStructureError("BOM does not match the declared encoding.")

        # newline="" preserves CSV handling of quoted multiline fields.
        text_stream = io.TextIOWrapper(
            buffered,
            encoding=encodings[declared_encoding],
            errors="strict",
            newline="",
        )
        reader = csv.reader(
            text_stream,
            delimiter=delimiter,
            quotechar='"',
            doublequote=True,
            strict=True,
        )

        try:
            header = next(reader, None)
            if header is None:
                raise CsvStructureError("CSV is empty; header is missing.")

            # Compare exact spelling, order and spaces; do not trim headers.
            if header != expected_columns:
                raise CsvStructureError("CSV header differs from the contract.")

            row_count = 0
            for row in reader:
                row_count += 1

                # Count logical CSV records, not physical text lines.
                if len(row) != len(expected_columns):
                    raise CsvStructureError(
                        f"Data record {row_count}, ending at physical line "
                        f"{reader.line_num}: expected {len(expected_columns)} "
                        f"fields; found {len(row)}."
                    )

                if any("\x00" in value for value in row):
                    raise CsvStructureError(
                        f"Data record {row_count} contains a NUL character."
                    )

            if row_count != expected_row_count:
                raise CsvStructureError(
                    f"Row count differs: expected {expected_row_count}; "
                    f"found {row_count}."
                )

        except UnicodeError:
            # Do not expose invalid source bytes in an error message.
            raise CsvStructureError(
                "CSV cannot be decoded using its declared encoding."
            ) from None
        except csv.Error:
            # This also catches fields exceeding Python's CSV parser limit.
            raise CsvStructureError(
                f"CSV parsing failed near physical line {reader.line_num}; "
                "check quoting or parser field-size limits."
            ) from None

        return CsvStructureResult(
            columns=tuple(header),
            row_count=row_count,
            encoding=declared_encoding,
        )

    finally:
        # Detach wrappers so the caller remains responsible for the input stream.
        if text_stream is not None:
            text_stream.detach()
        buffered.detach()