"""Persist intake progress without recording personnel values or secrets."""

import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.intake.registration_receipt import save_receipt


class AttemptJournal:
    """Write separate, non-overwriting JSON events for one import attempt."""

    EVENTS = {
        "STARTED",
        "FILE_STARTED",
        "FILE_COMPLETED",
        "COMPLETED",
        "FAILED",
    }

    def __init__(
        self,
        root: Path,
        *,
        batch_id: str,
        expected_archive_sha256: str,
        write_enabled: bool,
        code_revision: str,
    ):
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise ValueError("Batch ID is required.")
        if re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256) is None:
            raise ValueError("Expected archive fingerprint is invalid.")
        if re.fullmatch(r"[0-9a-f]{40}", code_revision) is None:
            raise ValueError("A full Git revision is required.")

        # Use a dedicated protected directory outside the source repository.
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.is_symlink() or root.stat().st_mode & 0o077:
            raise PermissionError("Attempt root must be private and not a symlink.")

        self.attempt_id = str(uuid4())
        self.directory = root / self.attempt_id
        self.directory.mkdir(mode=0o700)

        self.batch_id = batch_id
        self.expected_archive_sha256 = expected_archive_sha256
        self.write_enabled = write_enabled
        self.code_revision = code_revision
        self.sequence = 0
        self.finished = False
        self.broken = False

        # Failure to persist STARTED prevents the caller from beginning work.
        self.record("STARTED")

    def record(
        self,
        event: str,
        *,
        filename: str | None = None,
        row_count: int | None = None,
        outcome: str | None = None,
        error_type: str | None = None,
    ) -> Path:
        """Persist only approved metadata; propagate storage failures."""
        if self.finished or self.broken:
            raise RuntimeError("Attempt journal is closed or unavailable.")
        if event not in self.EVENTS:
            raise ValueError("Unknown attempt event.")
        if event == "STARTED" and self.sequence != 0:
            raise ValueError("STARTED can only be recorded once.")

        if event in {"FILE_STARTED", "FILE_COMPLETED"}:
            if (
                not isinstance(filename, str)
                or not filename
                or filename in {".", ".."}
                or any(character in filename for character in "/\\\x00")
            ):
                raise ValueError("A plain source filename is required.")
        elif filename is not None:
            raise ValueError("Filename is only allowed on file events.")

        if event == "FILE_COMPLETED":
            if type(row_count) is not int or row_count < 0:
                raise ValueError("A nonnegative row count is required.")
            if outcome not in {"IMPORTED", "VERIFIED_EXISTING"}:
                raise ValueError("Unexpected file outcome.")
        elif row_count is not None or outcome is not None:
            raise ValueError("Row count and outcome require FILE_COMPLETED.")

        if event == "FAILED":
            if (
                not isinstance(error_type, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", error_type)
                is None
            ):
                raise ValueError("A safe exception class name is required.")
        elif error_type is not None:
            raise ValueError("Error type is only allowed on FAILED.")

        number = self.sequence + 1
        document = {
            "event_schema_version": "1.0",
            "attempt_id": self.attempt_id,
            "sequence": number,
            "event": event,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "batch_id": self.batch_id,
            "expected_archive_sha256": self.expected_archive_sha256,
            "write_enabled": self.write_enabled,
            "code_revision": self.code_revision,
        }

        if filename is not None:
            document["filename"] = filename
        if row_count is not None:
            document["row_count"] = row_count
            document["outcome"] = outcome
        if error_type is not None:
            # Never save str(exception), SQL parameters or source cell values.
            document["error_type"] = error_type

        destination = self.directory / f"{number:06d}-{event.lower()}.json"

        try:
            save_receipt(document, destination)
        except Exception:
            # Stop further recording after an uncertain filesystem write.
            self.broken = True
            raise

        self.sequence = number
        self.finished = event in {"COMPLETED", "FAILED"}
        return destination