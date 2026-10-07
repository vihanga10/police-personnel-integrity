"""Test ciphertext binding and private credential handling without a Mongo server."""
import json
import os
from datetime import timedelta
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.storage.check_mongo import fixture
from app.storage.mongo_contract import encryption_context
from app.storage.mongo_connection import load_credentials


@pytest.mark.parametrize("field,value", [
    ("_id", "00000000-0000-0000-0000-000000000000"),
    ("officer_uid", "00000000-0000-0000-0000-000000000000"),
    ("source_assertion_uid", "00000000-0000-0000-0000-000000000000"),
    ("raw_record_id", "0" * 64),
    ("classification", "ORDINARY"),
    ("writer_policy", "CHANGED_POLICY"),
    ("schema_version", 2),
    ("payload_key_version", "REPLACED_KEY_VERSION"),
])
def test_copied_ciphertext_cannot_be_rebound(field, value):
    # Prevent a valid encrypted payload being reassigned to a different identity/source.
    document, key = fixture()
    cipher = bytes(document["payload_ciphertext"])
    assert AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(document).encode()) == b'{"synthetic":true}'
    document[field] = value
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(document).encode())


def test_timestamp_binding_survives_bson_roundtrip_but_rejects_changes():
    from bson import BSON
    from bson.codec_options import CodecOptions
    document, key = fixture()
    recovered = BSON.encode(document).decode(codec_options=CodecOptions(tz_aware=True))
    cipher = bytes(recovered["payload_ciphertext"])
    assert AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(recovered).encode()) == b'{"synthetic":true}'
    recovered["recorded_at"] += timedelta(milliseconds=1)
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cipher[:12], cipher[12:], encryption_context(recovered).encode())


def private_credentials(tmp_path):
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    (target / "credentials.json").write_text(json.dumps({"app_password": "a" * 48}))
    (target / "root-password.txt").write_text("r" * 48 + "\n")
    for path in target.iterdir():
        path.chmod(0o600)
    return target


def test_private_files_load_without_uri_or_secret_output(tmp_path):
    assert load_credentials(private_credentials(tmp_path)) == ("r" * 48, "a" * 48)


@pytest.mark.parametrize("name", ["credentials.json", "root-password.txt"])
def test_world_readable_secret_rejected(tmp_path, name):
    target = private_credentials(tmp_path)
    (target / name).chmod(0o644)
    with pytest.raises(ValueError, match="not private"):
        load_credentials(target)


def test_symlinked_secret_rejected(tmp_path):
    target = private_credentials(tmp_path)
    (target / "root-password.txt").rename(target / "original")
    os.symlink(target / "original", target / "root-password.txt")
    with pytest.raises(ValueError, match="not private"):
        load_credentials(target)
