"""Test protected attempt events using temporary directories."""

import json

import pytest

from app.intake import attempt_journal
from app.intake.attempt_journal import AttemptJournal


def new_journal(tmp_path):
    """Create an attempt containing metadata only."""
    return AttemptJournal(
        tmp_path / "attempts",
        batch_id="TEST-BATCH",
        expected_archive_sha256="a" * 64,
        write_enabled=True,
        code_revision="b" * 40,
    )


def test_successful_attempt_preserves_all_events(tmp_path):
    journal = new_journal(tmp_path)
    journal.record("FILE_STARTED", filename="example.csv")
    journal.record(
        "FILE_COMPLETED",
        filename="example.csv",
        row_count=2,
        outcome="IMPORTED",
    )
    journal.record("COMPLETED")

    paths = sorted(journal.directory.glob("*.json"))
    documents = [
        json.loads(path.read_text(encoding="utf-8")) for path in paths
    ]

    assert [item["event"] for item in documents] == [
        "STARTED", "FILE_STARTED", "FILE_COMPLETED", "COMPLETED"
    ]
    assert [item["sequence"] for item in documents] == [1, 2, 3, 4]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)

    # A completed attempt cannot acquire additional events.
    with pytest.raises(RuntimeError, match="closed"):
        journal.record("COMPLETED")


def test_failed_attempt_records_only_safe_error_metadata(tmp_path):
    journal = new_journal(tmp_path)
    path = journal.record("FAILED", error_type="StagingConflict")
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["error_type"] == "StagingConflict"
    assert "error_message" not in document
    assert journal.finished is True


def test_recording_failure_stops_the_journal(tmp_path, monkeypatch):
    journal = new_journal(tmp_path)

    def fail_write(*args, **kwargs):
        raise OSError("Simulated storage failure")

    monkeypatch.setattr(attempt_journal, "save_receipt", fail_write)

    # Logging failures must propagate so the importer can stop.
    with pytest.raises(OSError):
        journal.record("FILE_STARTED", filename="example.csv")

    assert journal.broken is True
    with pytest.raises(RuntimeError, match="unavailable"):
        journal.record("COMPLETED")