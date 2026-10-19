import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from app.security.identity_crypto import IdentityCrypto


@pytest.fixture
def crypto(tmp_path: Path) -> IdentityCrypto:
    def new_key() -> str:
        return base64.b64encode(os.urandom(32)).decode("ascii")

    key_file = tmp_path / "test-keys.json"
    key_file.write_text(
        json.dumps(
            {
                "active_encryption_key_version": "enc-v1",
                "encryption_keys": {
                    "enc-v1": new_key(),
                    "enc-v2": new_key(),
                },
                "active_lookup_key_version": "lookup-v1",
                "lookup_keys": {
                    "lookup-v1": new_key(),
                    "lookup-v2": new_key(),
                },
            }
        ),
        encoding="utf-8",
    )
    return IdentityCrypto(key_file)


def test_assertion_round_trip(crypto: IdentityCrypto) -> None:
    payload = {"full_name": "Test Officer", "nationality": "TEST"}

    ciphertext, version = crypto.encrypt_assertion(
        payload, context="officer-1/assertion-1"
    )

    assert crypto.decrypt_assertion(
        ciphertext,
        key_version=version,
        context="officer-1/assertion-1",
    ) == payload


def test_repeated_encryption_produces_different_ciphertext(
    crypto: IdentityCrypto,
) -> None:
    first, _ = crypto.encrypt(b"test value", context="record-1")
    second, _ = crypto.encrypt(b"test value", context="record-1")

    assert first != second


def test_modified_ciphertext_is_rejected(
    crypto: IdentityCrypto,
) -> None:
    ciphertext, version = crypto.encrypt(b"test value", context="record-1")
    modified = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(InvalidTag):
        crypto.decrypt(
            modified, key_version=version, context="record-1"
        )


def test_wrong_record_context_is_rejected(
    crypto: IdentityCrypto,
) -> None:
    ciphertext, version = crypto.encrypt(b"test value", context="record-1")

    with pytest.raises(InvalidTag):
        crypto.decrypt(
            ciphertext, key_version=version, context="record-2"
        )


def test_wrong_encryption_key_is_rejected(
    crypto: IdentityCrypto,
) -> None:
    ciphertext, _ = crypto.encrypt(b"test value", context="record-1")

    with pytest.raises(InvalidTag):
        crypto.decrypt(
            ciphertext, key_version="enc-v2", context="record-1"
        )


def test_unknown_key_version_is_rejected(
    crypto: IdentityCrypto,
) -> None:
    ciphertext, _ = crypto.encrypt(b"test value", context="record-1")

    with pytest.raises(ValueError):
        crypto.decrypt(
            ciphertext, key_version="missing", context="record-1"
        )


def test_lookup_is_repeatable_and_separated_by_type_and_key(
    crypto: IdentityCrypto,
) -> None:
    first = crypto.lookup_hmac("TEST123", identifier_type="NIC")
    repeated = crypto.lookup_hmac("TEST123", identifier_type="NIC")
    different_type = crypto.lookup_hmac(
        "TEST123", identifier_type="POLICE_ID"
    )
    different_key = crypto.lookup_hmac(
        "TEST123", identifier_type="NIC", key_version="lookup-v2"
    )

    assert first == repeated
    assert first[0] != different_type[0]
    assert first[0] != different_key[0]


def test_old_ciphertext_remains_readable_after_key_rotation(
    crypto: IdentityCrypto,
) -> None:
    ciphertext, version = crypto.encrypt(b"test value", context="record-1")
    crypto.active_encryption_version = "enc-v2"

    assert crypto.decrypt(
        ciphertext, key_version=version, context="record-1"
    ) == b"test value"


def test_empty_assertion_is_rejected(crypto: IdentityCrypto) -> None:
    with pytest.raises(ValueError):
        crypto.encrypt_assertion({}, context="record-1")


def test_non_finite_assertion_number_is_rejected(
    crypto: IdentityCrypto,
) -> None:
    with pytest.raises(ValueError):
        crypto.encrypt_assertion(
            {"height_cm": float("nan")}, context="record-1"
        )