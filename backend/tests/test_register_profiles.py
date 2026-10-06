"""Check batch write boundaries and audit behavior without database writes."""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.identity import register_profiles as module


@pytest.fixture
def setup(tmp_path, monkeypatch):
    args = SimpleNamespace(
        batch_id="TEST-BATCH", expected_archive_sha256="a" * 64,
        expected_confirmation_sha256="b" * 64, expected_rows=2,
        confirmation=tmp_path / "confirmation.json",
        attempt_root=tmp_path / "attempts", write=True,
        db_host="127.0.0.1", db_port=55432,
    )
    monkeypatch.setattr(module, "verify_recovery", lambda *args: None)
    monkeypatch.setattr(module, "preflight", lambda *args: [("d" * 64, 1), ("e" * 64, 2)])
    calls = []
    def register(*args, **kwargs):
        calls.append(kwargs["raw_record_id"])
        return SimpleNamespace(
            raw_record_id=kwargs["raw_record_id"], decision_id=uuid4(),
            outcome="CREATED", reason_code="TEST_NO_CANDIDATE",
            replayed=len(calls) == 1, identifier_count=3,
        )
    monkeypatch.setattr(module, "register_personal_row", register)
    return args, calls


def run(args):
    return module.run_batch(None, None, None, args, code_revision="c" * 40)


def events(args):
    directory = next(args.attempt_root.iterdir())
    return [json.loads(path.read_text()) for path in sorted(directory.glob("[0-9]*.json"))]


def test_validation_mode_never_invokes_registration(setup):
    args, calls = setup
    args.write = False
    assert all(value == 0 for value in run(args).values())
    assert calls == []
    assert [item["event"] for item in events(args)] == ["STARTED", "COMPLETED"]


def test_write_records_each_committed_result_and_replay(setup):
    args, calls = setup
    counts = run(args)
    assert calls == ["d" * 64, "e" * 64]
    assert counts["CREATED"] == 1 and counts["VERIFIED_EXISTING"] == 1
    assert [item["event"] for item in events(args)] == [
        "STARTED", "ROW_STARTED", "ROW_COMPLETED", "ROW_STARTED", "ROW_COMPLETED", "COMPLETED"]


def test_preflight_failure_prevents_all_registration(setup, monkeypatch):
    args, calls = setup
    def broken(*unused):
        raise ValueError("CONFIDENTIAL-VALUE")
    monkeypatch.setattr(module, "preflight", broken)
    with pytest.raises(ValueError):
        run(args)
    assert calls == []
    assert events(args)[-1]["event"] == "FAILED"
    assert "CONFIDENTIAL-VALUE" not in json.dumps(events(args))


def test_backup_failure_prevents_all_registration(setup, monkeypatch):
    args, calls = setup
    def broken(*unused):
        raise ValueError("Backup unavailable")
    monkeypatch.setattr(module, "verify_recovery", broken)
    with pytest.raises(ValueError):
        run(args)
    assert calls == []


def test_start_event_failure_prevents_first_database_call(setup, monkeypatch):
    args, calls = setup
    def broken(*unused, **kwargs):
        raise OSError("Disk unavailable")
    monkeypatch.setattr(module.RegistrationJournal, "start_row", broken)
    with pytest.raises(OSError):
        run(args)
    assert calls == []


def test_completion_event_failure_stops_before_next_row(setup, monkeypatch):
    args, calls = setup
    def broken(*unused, **kwargs):
        raise OSError("Disk unavailable")
    monkeypatch.setattr(module.RegistrationJournal, "complete_row", broken)
    with pytest.raises(OSError):
        run(args)
    assert calls == ["d" * 64]
    assert events(args)[-1]["pending_row_outcome"] == "UNKNOWN"


def test_service_failure_preserves_earlier_completion(setup, monkeypatch):
    args, calls = setup
    original = module.register_personal_row
    def register(*parameters, **kwargs):
        if calls:
            raise RuntimeError("PRIVATE-PAYLOAD")
        return original(*parameters, **kwargs)
    monkeypatch.setattr(module, "register_personal_row", register)
    with pytest.raises(RuntimeError):
        run(args)
    final = events(args)[-1]
    assert final["completed_rows"] == 1
    assert final["pending_row"]["raw_record_id"] == "e" * 64
    assert "PRIVATE-PAYLOAD" not in json.dumps(events(args))


def test_recovery_rejects_missing_lookup_key():
    primary = SimpleNamespace(encryption_keys={"enc": b"a" * 32}, lookup_keys={"lookup": b"b" * 32})
    backup = SimpleNamespace(encryption_keys={"enc": b"a" * 32}, lookup_keys={})
    with pytest.raises(module.BatchRegistrationError):
        module.verify_recovery(primary, backup)
