"""Test fingerprints against known values and changed evidence."""

from io import BytesIO

import pytest

from app.intake.checksums import (
    IntegrityError,
    fingerprint_file,
    fingerprint_stream,
    verify_fingerprint,
)


# Published SHA-256 test vector for the exact bytes b"abc".
ABC_SHA256 = (
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad"
)


def test_known_fingerprint():
    """Check the algorithm against a fixed expected result."""
    result = fingerprint_stream(BytesIO(b"abc"))

    assert result.sha256 == ABC_SHA256
    assert result.size_bytes == 3

    verify_fingerprint(
        result,
        expected_sha256=ABC_SHA256,
        expected_size_bytes=3,
    )


def test_changed_evidence_is_rejected():
    """A one-byte change must invalidate the expected fingerprint."""
    result = fingerprint_stream(BytesIO(b"abd"))

    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        verify_fingerprint(result, expected_sha256=ABC_SHA256)


def test_incorrect_size_is_rejected():
    """A correct digest must not hide an incorrect manifest size."""
    result = fingerprint_stream(BytesIO(b"abc"))

    with pytest.raises(IntegrityError, match="File size mismatch"):
        verify_fingerprint(
            result,
            expected_sha256=ABC_SHA256,
            expected_size_bytes=4,
        )


def test_reading_preserves_file_bytes(tmp_path):
    """Fingerprinting must leave the original bytes unchanged."""
    path = tmp_path / "evidence.csv"
    original = b"record_id,value\r\n1,example\r\n"
    path.write_bytes(original)

    result = fingerprint_file(path)

    assert result.size_bytes == len(original)
    assert path.read_bytes() == original


def test_malformed_expected_digest_is_rejected():
    """An invalid expectation must fail rather than be accepted."""
    result = fingerprint_stream(BytesIO(b"abc"))

    with pytest.raises(ValueError, match="64 hexadecimal"):
        verify_fingerprint(result, expected_sha256="not-a-checksum")