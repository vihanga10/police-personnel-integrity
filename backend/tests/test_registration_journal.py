"""Test durable identity progress and failure handling without a database."""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.identity import registration_journal as module


def journal(tmp_path, **changes):
    arguments = dict(batch_id="TEST-BATCH", archive_sha256="a" * 64,
                     confirmation_sha256="b" * 64, code_revision="c" * 40,
                     write_enabled=True)
    arguments.update(changes)
    return module.RegistrationJournal(tmp_path / "attempts", **arguments)


def result(raw_record_id="d" * 64, replayed=False):
    # Use fictional decision metadata, never real identifiers.
    return SimpleNamespace(raw_record_id=raw_record_id, decision_id=uuid4(),
                           outcome="CREATED", reason_code="TEST_NO_CANDIDATE",
                           identifier_count=3, replayed=replayed)


def events(instance):
    return [json.loads(path.read_text()) for path in sorted(instance.directory.glob("*.json"))]


def test_completed_attempt_records_creation_and_replay(tmp_path):
    instance = journal(tmp_path)
    for number, raw_id, replay in [(1, "d" * 64, False), (2, "e" * 64, True)]:
        instance.start_row(raw_record_id=raw_id, source_row_number=number)
        instance.complete_row(result(raw_id, replay))
    instance.complete(expected_rows=2)
    records = events(instance)
    assert [record["event"] for record in records] == [
        "STARTED", "ROW_STARTED", "ROW_COMPLETED", "ROW_STARTED", "ROW_COMPLETED", "COMPLETED"]
    assert [record["sequence"] for record in records] == list(range(1, 7))
    assert records[-1]["counts"] == {"CREATED": 1, "MATCHED": 0,
                                   "REVIEW_REQUIRED": 0, "VERIFIED_EXISTING": 1}
    assert all(record["confirmation_sha256"] == "b" * 64 for record in records)
    assert instance.directory.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in instance.directory.glob("*.json"))
    with pytest.raises(RuntimeError):
        instance.complete(expected_rows=2)


def test_failure_omits_exception_message_and_preserves_uncertainty(tmp_path):
    instance = journal(tmp_path)
    instance.start_row(raw_record_id="d" * 64, source_row_number=1)
    instance.fail(ValueError("PRIVATE-PERSONNEL-VALUE"))
    record = events(instance)[-1]
    assert record["error_type"] == "ValueError"
    assert record["pending_row_outcome"] == "UNKNOWN"
    assert record["pending_row"]["raw_record_id"] == "d" * 64
    assert "PRIVATE-PERSONNEL-VALUE" not in json.dumps(events(instance))


def test_incomplete_or_mismatched_results_are_rejected(tmp_path):
    instance = journal(tmp_path)
    instance.start_row(raw_record_id="d" * 64, source_row_number=1)
    with pytest.raises(RuntimeError):
        instance.complete(expected_rows=1)
    with pytest.raises(ValueError):
        instance.complete_row(result("e" * 64))
    assert len(events(instance)) == 2
    instance.complete_row(result())
    with pytest.raises(ValueError):
        instance.start_row(raw_record_id="e" * 64, source_row_number=1)


def test_failed_start_write_stops_registration_boundary(tmp_path, monkeypatch):
    instance = journal(tmp_path)
    def broken(*args, **kwargs):
        raise OSError("Disk unavailable")
    monkeypatch.setattr(module, "save_receipt", broken)
    with pytest.raises(OSError):
        instance.start_row(raw_record_id="d" * 64, source_row_number=1)
    assert instance.broken and instance.pending is None
    with pytest.raises(RuntimeError):
        instance.fail(RuntimeError())


def test_failed_completion_write_retains_pending_row(tmp_path, monkeypatch):
    instance = journal(tmp_path)
    instance.start_row(raw_record_id="d" * 64, source_row_number=1)
    def broken(*args, **kwargs):
        raise OSError("Disk unavailable")
    monkeypatch.setattr(module, "save_receipt", broken)
    with pytest.raises(OSError):
        instance.complete_row(result())
    assert instance.broken and instance.pending["raw_record_id"] == "d" * 64
    assert instance.completed_rows == 0
    assert events(instance)[-1]["event"] == "ROW_STARTED"


def test_validation_only_cannot_start_registration(tmp_path):
    instance = journal(tmp_path, write_enabled=False)
    with pytest.raises(RuntimeError):
        instance.start_row(raw_record_id="d" * 64, source_row_number=1)


def test_shared_directory_rejected(tmp_path):
    root = tmp_path / "attempts"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(PermissionError):
        journal(tmp_path)


def test_malformed_fingerprint_rejected_before_writing(tmp_path):
    with pytest.raises(ValueError):
        journal(tmp_path, confirmation_sha256="invalid")
    assert not (tmp_path / "attempts").exists()
