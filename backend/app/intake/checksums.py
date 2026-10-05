"""Calculate and verify fingerprints without modifying input evidence."""

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class IntegrityError(ValueError):
    """Raised when received evidence differs from its expected fingerprint."""


@dataclass(frozen=True)
class FileFingerprint:
    """The SHA-256 digest and exact number of bytes read."""

    sha256: str
    size_bytes: int


def fingerprint_stream(stream: BinaryIO) -> FileFingerprint:
    """Hash bytes from the stream's current position through its end."""
    digest = hashlib.sha256()
    size_bytes = 0

    # Process chunks so large files do not need to fit entirely in memory.
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break

        digest.update(chunk)
        size_bytes += len(chunk)

    # The caller owns the stream and remains responsible for closing it.
    return FileFingerprint(
        sha256=digest.hexdigest(),
        size_bytes=size_bytes,
    )


def fingerprint_file(path: Path) -> FileFingerprint:
    """Read a local file in binary mode without changing its contents."""
    with path.open("rb") as stream:
        return fingerprint_stream(stream)


def verify_fingerprint(
    actual: FileFingerprint,
    *,
    expected_sha256: str,
    expected_size_bytes: int | None = None,
) -> None:
    """Reject malformed expectations or mismatching file evidence."""
    if not isinstance(expected_sha256, str) or re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_sha256
    ) is None:
        raise ValueError("Expected SHA-256 must contain 64 hexadecimal characters.")

    # Reject booleans as sizes even though Python treats bool as an int subtype.
    if expected_size_bytes is not None:
        if type(expected_size_bytes) is not int or expected_size_bytes < 0:
            raise ValueError("Expected size must be a nonnegative integer.")

    if not hmac.compare_digest(actual.sha256, expected_sha256.lower()):
        raise IntegrityError("SHA-256 mismatch.")

    if (
        expected_size_bytes is not None
        and actual.size_bytes != expected_size_bytes
    ):
        raise IntegrityError("File size mismatch.")