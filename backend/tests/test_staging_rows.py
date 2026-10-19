"""Test source binding and exact preservation of parsed CSV values."""

import base64
import json
import os
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag

from app.intake.staging_rows import open_row, seal_row
from app.security.identity_crypto import IdentityCrypto


@pytest.fixture
def crypto(tmp_path):
    """Generate disposable keys; never read the project's real key file."""
    path = tmp_path / "test-keys.json"
    data = {
        "active_encryption_key_version": "test-enc-v1",
        "encryption_keys": {
            "test-enc-v1": base64.b64encode(os.urandom(32)).decode("ascii")
        },
        "active_lookup_key_version": "test-lookup-v1",
        "lookup_keys": {
            "test-lookup-v1": base64.b64encode(os.urandom(32)).decode("ascii")
        },
    }

    # Set private permissions when creating the temporary key file.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(data, stream)

    return IdentityCrypto(path)


def example_row(crypto, number=1):
    """Prepare test data containing Unicode, whitespace and an empty cell."""
    return seal_row(
        crypto,
        batch_id="TEST-BATCH",
        archive_path="package/TEST-BATCH/original/example.csv",
        source_file_sha256="a" * 64,
        source_row_number=number,
        columns=["identifier", "Province ", "note", "optional"],
        values=["00123", "බස්නාහිර", " first\nsecond ", ""],
    )


def test_preserves_exact_parsed_values(crypto):
    """Decryption must preserve leading zeros, spaces, Unicode and empties."""
    payload = open_row(crypto, example_row(crypto))

    assert payload["columns"] == ["identifier", "Province ", "note", "optional"]
    assert payload["values"] == ["00123", "බස්නාහිර", " first\nsecond ", ""]


def test_stable_id_with_fresh_ciphertext(crypto):
    """Repeated preparation has the same reference but a fresh encryption nonce."""
    first = example_row(crypto)
    second = example_row(crypto)

    assert first.raw_record_id == second.raw_record_id
    assert first.payload_ciphertext != second.payload_ciphertext
    assert open_row(crypto, first) == open_row(crypto, second)


def test_different_rows_have_different_ids(crypto):
    """Identical values on different source rows remain distinct evidence."""
    assert example_row(crypto, 1).raw_record_id != example_row(crypto, 2).raw_record_id


def test_ciphertext_cannot_be_moved_between_rows(crypto):
    """Even valid ciphertext must fail when attached to another row's context."""
    first = example_row(crypto, 1)
    second = example_row(crypto, 2)
    swapped = replace(second, payload_ciphertext=first.payload_ciphertext)

    with pytest.raises(InvalidTag):
        open_row(crypto, swapped)


def test_changed_ciphertext_is_rejected(crypto):
    """A changed ciphertext byte must fail authentication."""
    row = example_row(crypto)
    damaged = bytearray(row.payload_ciphertext)
    damaged[-1] ^= 1

    with pytest.raises(InvalidTag):
        open_row(crypto, replace(row, payload_ciphertext=bytes(damaged)))


def test_invalid_row_width_is_rejected(crypto):
    """Do not encrypt a row that does not match its headers."""
    with pytest.raises(ValueError, match="Row width"):
        seal_row(
            crypto,
            batch_id="TEST-BATCH",
            archive_path="package/example.csv",
            source_file_sha256="a" * 64,
            source_row_number=1,
            columns=["one", "two"],
            values=["only-one"],
        )