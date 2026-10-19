"""Persist identity registration progress without personnel values or secrets."""

import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.intake.registration_receipt import save_receipt


def _digest(value: str, length: int) -> str:
    """Reject malformed fingerprints before writing an audit event."""
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError("Invalid fingerprint or revision.")
    return value


class RegistrationJournal:
    """Track one sequential registration attempt with durable row boundaries.

A ROW_COMPLETED event must be written only after register_personal_row returns,
which means its database transaction has committed. An unfinished ROW_STARTED
is an uncertain outcome: a retry must query the saved decision, never assume
that the row was rolled back.
    """

    def __init__(
        self, root: Path, *, batch_id: str, archive_sha256: str,
        confirmation_sha256: str, code_revision: str, write_enabled: bool,
    ) -> None:
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise ValueError("Batch ID is required.")
        if type(write_enabled) is not bool:
            raise ValueError("Write mode must be boolean.")
        self.metadata = {
            "batch_id": batch_id,
            "archive_sha256": _digest(archive_sha256, 64),
            "confirmation_sha256": _digest(confirmation_sha256, 64),
            "code_revision": _digest(code_revision, 40),
            "write_enabled": write_enabled,
        }
        # Refuse symlink components and shared attempt directories.
        root = Path(root).absolute()
        if any(part.is_symlink() for part in (root, *root.parents)):
            raise PermissionError("Attempt path must not contain symlinks.")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.stat().st_mode & 0o077:
            raise PermissionError("Attempt root must have owner-only permissions.")
        self.attempt_id = str(uuid4())
        self.directory = root / self.attempt_id
        self.directory.mkdir(mode=0o700)
        self.sequence = 0
        self.finished = False
        self.broken = False
        self.pending = None
        self.completed_rows = 0
        self.last_row_number = 0
        self.counts = {"CREATED": 0, "MATCHED": 0, "REVIEW_REQUIRED": 0,
                       "VERIFIED_EXISTING": 0}
        self._record("STARTED")

    def _record(self, event: str, **details) -> Path:
        """Stop permanently after any uncertain filesystem write."""
        if self.finished or self.broken:
            raise RuntimeError("Registration journal is closed or unavailable.")
        number = self.sequence + 1
        document = {
            "event_schema_version": "1.0",
            "attempt_kind": "IDENTITY_REGISTRATION",
            "attempt_id": self.attempt_id,
            "sequence": number,
            "event": event,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            **self.metadata, **details,
        }
        destination = self.directory / f"{number:06d}-{event.lower()}.json"
        try:
            save_receipt(document, destination)
        except Exception:
            self.broken = True
            raise
        self.sequence = number
        return destination

    def start_row(self, *, raw_record_id: str, source_row_number: int) -> None:
        """Persist intent before invoking the database registration service."""
        if not self.metadata["write_enabled"]:
            raise RuntimeError("Validation-only attempts cannot register rows.")
        if self.pending is not None:
            raise RuntimeError("The previous row has no completion event.")
        _digest(raw_record_id, 64)
        if type(source_row_number) is not int or source_row_number <= self.last_row_number:
            raise ValueError("Source row numbers must be positive and increasing.")
        details = {"raw_record_id": raw_record_id,
                   "source_row_number": source_row_number}
        self._record("ROW_STARTED", **details)
        self.pending = details

    def complete_row(self, result) -> None:
        """Record safe decision metadata after the service has committed."""
        if self.pending is None or result.raw_record_id != self.pending["raw_record_id"]:
            raise ValueError("Result does not match the pending row.")
        if result.outcome not in {"CREATED", "MATCHED", "REVIEW_REQUIRED"}:
            raise ValueError("Invalid registration outcome.")
        if type(result.replayed) is not bool:
            raise ValueError("Replay status must be boolean.")
        if type(result.identifier_count) is not int or result.identifier_count < 0:
            raise ValueError("Invalid identifier count.")
        if not isinstance(result.reason_code, str) or re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,79}", result.reason_code
        ) is None:
            raise ValueError("Invalid reason code.")
        decision_id = str(UUID(str(result.decision_id)))
        status = "VERIFIED_EXISTING" if result.replayed else result.outcome
        # Officer identifiers and decrypted evidence are deliberately omitted.
        self._record(
            "ROW_COMPLETED", **self.pending, decision_id=decision_id,
            outcome=result.outcome, status=status, reason_code=result.reason_code,
            identifier_count=result.identifier_count, replayed=result.replayed,
        )
        self.completed_rows += 1
        self.counts[status] += 1
        self.last_row_number = self.pending["source_row_number"]
        self.pending = None

    def complete(self, *, expected_rows: int) -> None:
        """Finish only when every selected row has a persisted result."""
        if type(expected_rows) is not int or expected_rows < 0:
            raise ValueError("Expected row count must be nonnegative.")
        if self.pending is not None or self.completed_rows != expected_rows:
            raise RuntimeError("Registration attempt is incomplete.")
        self._record("COMPLETED", completed_rows=self.completed_rows,
                     counts=dict(self.counts))
        self.finished = True

    def fail(self, error: BaseException) -> None:
        """Log the exception class only; messages can contain sensitive data."""
        error_type = type(error).__name__
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", error_type) is None:
            error_type = "Exception"
        self._record(
            "FAILED", error_type=error_type, completed_rows=self.completed_rows,
            counts=dict(self.counts), pending_row=self.pending,
            pending_row_outcome="UNKNOWN" if self.pending else None,
        )
        self.finished = True
