"""Validate reported supplying sources without upgrading their evidence status."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path


class SourceConfirmationError(ValueError):
    """The confirmation cannot safely be used for this intake."""


@dataclass(frozen=True)
class ConfirmedFileSource:
    file_name: str
    source_system_code: str


@dataclass(frozen=True)
class SourceConfirmation:
    confirmation_id: str
    batch_id: str
    archive_sha256: str
    confirmation_sha256: str
    files: tuple[ConfirmedFileSource, ...]
    source_independence: str = "UNVERIFIED"

    def source_for(self, file_name: str) -> str:
        """Require an explicit assignment; never guess a source."""
        for entry in self.files:
            if entry.file_name == file_name:
                return entry.source_system_code
        raise SourceConfirmationError("File has no confirmed source assignment.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys instead of silently keeping the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise SourceConfirmationError("Duplicate JSON key.")
        result[key] = value
    return result


def _required_text(data: dict, field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SourceConfirmationError("Required confirmation text is missing.")
    return value


def load_source_confirmation(
    path: Path,
    *,
    expected_batch_id: str,
    expected_archive_sha256: str,
    expected_filenames: set[str],
    allowed_source_codes: set[str],
) -> SourceConfirmation:
    """Bind a reported source assignment to one verified archive and file set."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256):
        raise SourceConfirmationError("Expected archive fingerprint is invalid.")
    if not expected_batch_id.strip() or not expected_filenames:
        raise SourceConfirmationError("Expected intake identity is incomplete.")
    if not allowed_source_codes:
        raise SourceConfirmationError("Allowed source codes are required.")

    # Bound the read and fingerprint exactly the bytes that are validated.
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise SourceConfirmationError("Confirmation exceeds the size limit.")

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SourceConfirmationError("Confirmation is not valid UTF-8 JSON.") from exc

    if not isinstance(data, dict):
        raise SourceConfirmationError("Confirmation must be a JSON object.")
    if data.get("schema_version") != "1.0":
        raise SourceConfirmationError("Unsupported confirmation schema.")
    if data.get("batch_id") != expected_batch_id:
        raise SourceConfirmationError("Confirmation belongs to another batch.")
    if data.get("archive_sha256") != expected_archive_sha256:
        raise SourceConfirmationError("Confirmation belongs to another archive.")

    confirmation_id = _required_text(data, "confirmation_id")
    for field in ("confirmed_by", "confirmation_basis", "scope"):
        _required_text(data, field)

    # Require an explicit calendar date for the reported confirmation.
    confirmed_on = _required_text(data, "confirmed_on")
    try:
        parsed_date = date.fromisoformat(confirmed_on)
    except ValueError as exc:
        raise SourceConfirmationError("Confirmation date is invalid.") from exc
    if parsed_date.isoformat() != confirmed_on:
        raise SourceConfirmationError("Confirmation date must use YYYY-MM-DD.")

    # This loader supports reported attribution, not verified authenticity.
    required_limits = {
        "independent_custodian_verification": "NOT_ESTABLISHED",
        "source_independence": "UNVERIFIED",
        "source_truth": "NOT_ASSESSED",
    }
    for field, expected in required_limits.items():
        if data.get(field) != expected:
            raise SourceConfirmationError("Unsupported evidence-status claim.")
    if data.get("original_archive_modified") is not False:
        raise SourceConfirmationError("Original archive must remain unchanged.")

    entries = data.get("files")
    if not isinstance(entries, list) or not entries:
        raise SourceConfirmationError("File assignments are required.")

    assignments = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SourceConfirmationError("Invalid file assignment.")

        filename = _required_text(entry, "file_name")
        source = _required_text(entry, "reported_source_system_code")

        # Check membership before allowing any assignment into the result.
        if filename not in expected_filenames:
            raise SourceConfirmationError("Unregistered file assignment.")
        if filename in assignments:
            raise SourceConfirmationError("Duplicate file assignment.")
        if source not in allowed_source_codes:
            raise SourceConfirmationError("Unknown source system code.")
        assignments[filename] = source

    if set(assignments) != expected_filenames:
        raise SourceConfirmationError("Source assignments are incomplete.")

    # Retain the confirmation fingerprint for subsequent import provenance.
    return SourceConfirmation(
        confirmation_id=confirmation_id,
        batch_id=expected_batch_id,
        archive_sha256=expected_archive_sha256,
        confirmation_sha256=hashlib.sha256(raw).hexdigest(),
        files=tuple(
            ConfirmedFileSource(filename, assignments[filename])
            for filename in sorted(assignments)
        ),
    )