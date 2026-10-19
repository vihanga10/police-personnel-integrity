"""Exercise archive verification using temporary test evidence."""

import hashlib
import json
from zipfile import ZipFile

import pytest

from app.intake.archive_verifier import verify_archive
from app.intake.checksums import IntegrityError


def make_package(tmp_path, *, changed_csv=False, extra_csv=False):
    """Create a package with a known manifest and optional inconsistencies."""
    root = "test-package"
    relative = "TEST-BATCH/original/example.csv"
    original = b"record_id,value\n1,example\n"
    digest = hashlib.sha256(original).hexdigest()

    manifest = {
        "import_batch": {
            "import_batch_id": "TEST-BATCH",
            "file_count": 1,
        },
        "files": [{
            "file_name": "example.csv",
            "package_path": relative,
            "sha256": digest,
            "size_bytes": len(original),
        }],
    }

    path = tmp_path / "package.zip"
    with ZipFile(path, "w") as bundle:
        # Keep manifest expectations unchanged when testing altered CSV bytes.
        bundle.writestr(
            f"{root}/{relative}",
            original + b"2,changed\n" if changed_csv else original,
        )
        bundle.writestr(
            f"{root}/batch_manifest.json", json.dumps(manifest)
        )
        bundle.writestr(
            f"{root}/original_files.sha256", f"{digest}  {relative}\n"
        )
        if extra_csv:
            bundle.writestr(f"{root}/unexpected.csv", b"id\n1\n")

    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def check_package(path, digest, *, batch="TEST-BATCH"):
    """Supply expectations from outside the package being verified."""
    return verify_archive(
        path,
        expected_sha256=digest,
        expected_batch_id=batch,
        package_root="test-package",
        expected_filenames={"example.csv"},
    )


def test_valid_archive(tmp_path):
    """A consistent package produces structured file evidence."""
    path, digest = make_package(tmp_path)
    result = check_package(path, digest)

    assert result.batch_id == "TEST-BATCH"
    assert result.archive_fingerprint.sha256 == digest
    assert len(result.files) == 1
    assert result.files[0].filename == "example.csv"


def test_wrong_archive_fingerprint(tmp_path):
    """Reject an archive that differs from the external expectation."""
    path, _ = make_package(tmp_path)
    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        check_package(path, "0" * 64)


def test_changed_csv(tmp_path):
    """Check internal evidence even when the outer ZIP hash matches."""
    path, digest = make_package(tmp_path, changed_csv=True)
    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        check_package(path, digest)


def test_unexpected_csv(tmp_path):
    """Reject an extra CSV absent from the registered file set."""
    path, digest = make_package(tmp_path, extra_csv=True)
    with pytest.raises(IntegrityError, match="Archive CSV membership"):
        check_package(path, digest)


def test_wrong_batch(tmp_path):
    """Reject a package belonging to another expected batch."""
    path, digest = make_package(tmp_path)
    with pytest.raises(IntegrityError, match="batch identifier"):
        check_package(path, digest, batch="OTHER-BATCH")