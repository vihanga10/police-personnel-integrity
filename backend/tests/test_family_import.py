"""Guard CLI modes and independently durable SQL commit recovery."""
from contextlib import contextmanager
from unittest.mock import patch
import pytest
from app.identity import import_families as importer
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION


def args(extra=()):
    return ["import_families", "--batch-id", BATCH, "--expected-archive-sha256", ARCHIVE,
        "--expected-confirmation-sha256", CONFIRMATION, "--expected-rows", "6596", "--confirmation", "confirm.json",
        "--key-file", "primary.json", "--backup-key-file", "backup.json", "--attempt-root", "/private/attempts", *extra]


@pytest.mark.parametrize("mode", [(), ("--write",), ("--reconcile",)])
def test_explicit_modes(mode):
    with patch("sys.argv", args(mode)):
        parsed = importer.arguments()
        assert parsed.write == (mode == ("--write",))
        assert parsed.reconcile == (mode == ("--reconcile",))


def test_modes_mutually_exclusive():
    with patch("sys.argv", args(("--write", "--reconcile"))), pytest.raises(SystemExit): importer.arguments()


def test_wrong_batch_rows_rejected():
    arguments = args(); arguments[arguments.index("6596")] = "1"
    with patch("sys.argv", arguments), pytest.raises(SystemExit): importer.arguments()


class Connection:
    def execute(self, statement):
        assert "READ ONLY" in str(statement)
    @contextmanager
    def begin(self): yield self
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Engine:
    def __init__(self, lost=False): self.lost, self.connections = lost, 0
    @contextmanager
    def begin(self):
        yield Connection()
        if self.lost: raise OSError("Lost commit acknowledgement")
    def connect(self): self.connections += 1; return Connection()


@pytest.mark.parametrize("lost", [False, True])
def test_commit_uses_fresh_connection_for_recovery(lost):
    engine = Engine(lost)
    with patch.object(importer, "transform", side_effect=[("CREATED", 3), ("VERIFIED_EXISTING", 3)]) as transform:
        result = importer.commit_row(engine, None, None, None, {})
        assert result == ("VERIFIED_EXISTING" if lost else "CREATED", 3)
        assert engine.connections == 1
        assert transform.call_args_list[0].kwargs["allow_write"] is True
        assert "allow_write" not in transform.call_args_list[1].kwargs


def test_failed_commit_without_receipt_is_not_claimed_complete():
    with patch.object(importer, "transform", side_effect=[("CREATED", 3), ("PLANNED", 3)]), pytest.raises(OSError):
        importer.commit_row(Engine(True), None, None, None, {})


def test_durable_readback_mismatch_rejected():
    with patch.object(importer, "transform", side_effect=[("CREATED", 3), ("VERIFIED_EXISTING", 2)]), pytest.raises(ValueError):
        importer.commit_row(Engine(), None, None, None, {})
