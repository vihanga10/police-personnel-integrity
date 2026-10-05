import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IdentityCrypto:
    """Encryption and protected lookup for identity data."""

    def __init__(self, key_file: Path) -> None:
        data = json.loads(key_file.read_text(encoding="utf-8"))

        self.active_encryption_version = data[
            "active_encryption_key_version"
        ]
        self.active_lookup_version = data[
            "active_lookup_key_version"
        ]

        self.encryption_keys = self._decode_keys(
            data["encryption_keys"]
        )
        self.lookup_keys = self._decode_keys(
            data["lookup_keys"]
        )

        if self.active_encryption_version not in self.encryption_keys:
            raise ValueError("Active encryption key is unavailable.")

        if self.active_lookup_version not in self.lookup_keys:
            raise ValueError("Active lookup key is unavailable.")

    @staticmethod
    def _decode_keys(values: dict[str, str]) -> dict[str, bytes]:
        result = {}

        for version, encoded in values.items():
            key = base64.b64decode(encoded, validate=True)

            if len(key) != 32:
                raise ValueError("Each key must contain 32 bytes.")

            result[version] = key

        return result

    @staticmethod
    def _context_bytes(context: str, key_version: str) -> bytes:
        if not context.strip():
            raise ValueError("Encryption context is required.")

        return json.dumps(
            ["IDENTITY_ENCRYPTION_V1", key_version, context],
            separators=(",", ":"),
        ).encode("utf-8")

    def encrypt(
        self,
        plaintext: bytes,
        *,
        context: str,
    ) -> tuple[bytes, str]:
        if not plaintext:
            raise ValueError("Cannot encrypt an empty value.")

        version = self.active_encryption_version
        nonce = os.urandom(12)

        ciphertext = AESGCM(self.encryption_keys[version]).encrypt(
            nonce,
            plaintext,
            self._context_bytes(context, version),
        )

        return nonce + ciphertext, version

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        key_version: str,
        context: str,
    ) -> bytes:
        if len(ciphertext) < 29:
            raise ValueError("Invalid encrypted value.")

        if key_version not in self.encryption_keys:
            raise ValueError("Encryption key version is unavailable.")

        nonce = ciphertext[:12]
        encrypted_payload = ciphertext[12:]

        return AESGCM(self.encryption_keys[key_version]).decrypt(
            nonce,
            encrypted_payload,
            self._context_bytes(context, key_version),
        )

    def lookup_hmac(
        self,
        normalized_value: str,
        *,
        identifier_type: str,
        key_version: str | None = None,
    ) -> tuple[str, str]:
        if not normalized_value.strip() or not identifier_type.strip():
            raise ValueError("Lookup value and identifier type are required.")

        version = (
            self.active_lookup_version
            if key_version is None
            else key_version
        )

        if version not in self.lookup_keys:
            raise ValueError("Lookup key version is unavailable.")

        message = json.dumps(
            ["IDENTITY_LOOKUP_V1", identifier_type, normalized_value],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        digest = hmac.new(
            self.lookup_keys[version],
            message,
            hashlib.sha256,
        ).hexdigest()

        return digest, version

    def encrypt_assertion(
        self,
        payload: dict[str, object],
        *,
        context: str,
    ) -> tuple[bytes, str]:
        if not isinstance(payload, dict) or not payload:
            raise ValueError("Assertion must be a non-empty dictionary.")

        plaintext = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        return self.encrypt(plaintext, context=context)

    def decrypt_assertion(
        self,
        ciphertext: bytes,
        *,
        key_version: str,
        context: str,
    ) -> dict[str, object]:
        plaintext = self.decrypt(
            ciphertext,
            key_version=key_version,
            context=context,
        )
        payload = json.loads(plaintext)

        if not isinstance(payload, dict) or not payload:
            raise ValueError("Decrypted assertion is invalid.")

        return payload