"""Build and save intake integrity receipts without overwriting evidence."""

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.intake.archive_verifier import VerifiedArchive


RECEIPT_SCHEMA_VERSION = "1.0"
VERIFIER_VERSION = "1.0"


def build_receipt(
    result: VerifiedArchive,
    *,
    verifier_git_commit: str,
) -> dict:
    """Describe a completed verification without claiming source authenticity."""
    if re.fullmatch(r"[0-9a-f]{40}", verifier_git_commit) is None:
        raise ValueError("Provide the full 40-character verifier Git commit.")

    return {
        "receipt_schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": str(uuid4()),
        "batch_id": result.batch_id,
        # This is the receipt creation time, not the original source capture time.
        "receipt_created_at": datetime.now(timezone.utc).isoformat(),
        "verifier": {
            "version": VERIFIER_VERSION,
            "git_commit": verifier_git_commit,
        },
        "integrity_status": "PASSED",
        "verification_scope": [
            "archive_sha256_matches_external_expectation",
            "manifest_batch_and_csv_membership",
            "checksum_list_csv_membership",
            "csv_sha256_matches_manifest_and_checksum_list",
            "csv_sizes_match_manifest",
        ],
        # Keep unperformed checks explicit for later audit stages.
        "not_assessed": [
            "source_authenticity",
            "source_truth",
            "independent_source_capture",
            "csv_row_structure_and_values",
            "authority_validity",
        ],
        "archive": {
            "sha256": result.archive_fingerprint.sha256,
            "size_bytes": result.archive_fingerprint.size_bytes,
        },
        "file_count": len(result.files),
        "files": [
            {
                "filename": item.filename,
                "archive_path": item.archive_path,
                "sha256": item.fingerprint.sha256,
                "size_bytes": item.fingerprint.size_bytes,
            }
            for item in result.files
        ],
    }


def save_receipt(receipt: dict, destination: Path) -> Path:
    """Publish a complete receipt atomically without replacing an existing file."""
    # Serialize before creating files so invalid values leave no partial receipt.
    payload = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")

    # The caller supplies the protected receipt directory.
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if destination.parent.stat().st_mode & 0o077:
        raise PermissionError(
            "Receipt directory must have owner-only permissions (chmod 700)."
        )

    temporary_path = None
    try:
        # Create a private temporary file in the destination filesystem.
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".receipt-",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

        # A hard link publishes complete bytes and fails if the name exists.
        os.link(temporary_path, destination)

        # Flush the directory entry for local filesystem durability.
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    finally:
        # Remove the temporary name; a successfully published receipt remains.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return destination