"""Test receipt scope, storage permissions and overwrite protection."""

import json

import pytest

from app.intake.archive_verifier import VerifiedArchive, VerifiedFile
from app.intake.checksums import FileFingerprint
from app.intake.registration_receipt import build_receipt, save_receipt


def example_receipt():
    """Use test fingerprints without loading any personnel data."""
    result = VerifiedArchive(
        batch_id="TEST-BATCH",
        archive_fingerprint=FileFingerprint("a" * 64, 100),
        files=(
            VerifiedFile(
                filename="example.csv",
                archive_path="package/TEST-BATCH/original/example.csv",
                fingerprint=FileFingerprint("b" * 64, 20),
            ),
        ),
    )
    return build_receipt(result, verifier_git_commit="c" * 40)


def test_receipt_records_scope():
    """Integrity success must not imply truth or authority verification."""
    receipt = example_receipt()

    assert receipt["integrity_status"] == "PASSED"
    assert receipt["file_count"] == 1
    assert receipt["files"][0]["sha256"] == "b" * 64
    assert "source_truth" in receipt["not_assessed"]
    assert "authority_validity" in receipt["not_assessed"]


def test_receipt_saved_with_private_permissions(tmp_path):
    """Persist the full receipt in an owner-only directory and file."""
    receipt = example_receipt()
    destination = tmp_path / "receipts" / "registration.json"

    save_receipt(receipt, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == receipt
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700


def test_existing_receipt_cannot_be_overwritten(tmp_path):
    """A second write must preserve the original receipt exactly."""
    destination = tmp_path / "receipts" / "registration.json"
    save_receipt(example_receipt(), destination)
    original = destination.read_bytes()

    with pytest.raises(FileExistsError):
        save_receipt(example_receipt(), destination)

    assert destination.read_bytes() == original
    assert not list(destination.parent.glob(".receipt-*.tmp"))


def test_public_receipt_directory_rejected(tmp_path):
    """Reject an existing directory accessible to other local accounts."""
    folder = tmp_path / "receipts"
    folder.mkdir()
    folder.chmod(0o755)

    with pytest.raises(PermissionError, match="owner-only"):
        save_receipt(example_receipt(), folder / "registration.json")

    assert not (folder / "registration.json").exists()