"""Explicitly enabled PostgreSQL tests for protected candidate discovery."""

import base64
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import insert, text

from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.normalization import (
    NORMALIZATION_PROFILE,
    normalize_identifier,
)
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.security.identity_crypto import IdentityCrypto
from database import create_identity_engine
from settings import Settings


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_IDENTITY_DB_TESTS") != "1",
    reason="Set RUN_IDENTITY_DB_TESTS=1 to run identity database tests.",
)


@pytest.fixture
def lookup_case(tmp_path):
    """Create isolated test evidence using the restricted application account."""
    key_file = tmp_path / "lookup-test-keys.json"

    def random_key():
        return base64.b64encode(os.urandom(32)).decode("ascii")

    # Retain an old lookup key while making the new key active.
    descriptor = os.open(
        key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({
            "active_encryption_key_version": "enc-test",
            "encryption_keys": {"enc-test": random_key()},
            "active_lookup_key_version": "lookup-v2",
            "lookup_keys": {
                "lookup-v1": random_key(),
                "lookup-v2": random_key(),
            },
        }, stream)

    crypto = IdentityCrypto(key_file)
    identifier = normalize_identifier(
        "TEST-" + str(uuid4()),
        identifier_type="POLICE_ID",
    )
    engine = create_identity_engine(Settings())

    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                assert connection.execute(
                    text("SELECT current_user")
                ).scalar_one() == "police_identity_app"

                source_id = uuid4()
                connection.execute(
                    insert(SourceSystem.__table__).values(
                        source_system_id=source_id,
                        source_system_code="TEST-" + str(source_id),
                        source_name="Temporary identity lookup test",
                    )
                )

                def add_evidence(
                    *,
                    officer_uid=None,
                    profile=NORMALIZATION_PROFILE,
                    stored_key_version="lookup-v1",
                    digest_key_version=None,
                    record_state="ASSERTED",
                ):
                    # Supplying an officer UID reuses an officer created earlier.
                    if officer_uid is None:
                        officer_uid = uuid4()
                        connection.execute(
                            insert(Officer.__table__).values(
                                officer_uid=officer_uid
                            )
                        )

                    assertion_id = uuid4()
                    assertion_ciphertext, encryption_version = (
                        crypto.encrypt_assertion(
                            {"test_identifier": identifier.value},
                            context=f"TEST_ASSERTION:{assertion_id}",
                        )
                    )
                    connection.execute(
                        insert(SourceAssertion.__table__).values(
                            source_assertion_id=assertion_id,
                            officer_uid=officer_uid,
                            source_system_id=source_id,
                            assertion_type="IDENTIFIER_TEST",
                            asserted_value_ciphertext=assertion_ciphertext,
                            encryption_key_version=encryption_version,
                            intake_batch_id="TEST-BATCH",
                            import_file_id="TEST-FILE",
                            raw_record_id=str(uuid4()),
                            source_file_name="test-identifiers.csv",
                            source_file_sha256="a" * 64,
                            source_row_number=1,
                        )
                    )

                    version_id = uuid4()
                    ciphertext, encryption_version = crypto.encrypt(
                        identifier.value.encode("utf-8"),
                        context=f"TEST_IDENTIFIER:{version_id}",
                    )
                    digest, _ = crypto.lookup_hmac(
                        identifier.value,
                        identifier_type=identifier.identifier_type,
                        key_version=(
                            digest_key_version
                            if digest_key_version is not None
                            else stored_key_version
                        ),
                    )

                    connection.execute(
                        insert(OfficerIdentifierVersion.__table__).values(
                            identifier_version_id=version_id,
                            identifier_chain_uid=uuid4(),
                            officer_uid=officer_uid,
                            source_assertion_id=assertion_id,
                            identifier_type=identifier.identifier_type,
                            identifier_value_ciphertext=ciphertext,
                            identifier_lookup_hmac=digest,
                            normalization_profile=profile,
                            encryption_key_version=encryption_version,
                            lookup_key_version=stored_key_version,
                            version_number=1,
                            record_state=record_state,
                        )
                    )
                    return officer_uid

                yield connection, crypto, identifier, add_evidence
            finally:
                # Remove all officers, assertions and identifiers from this test.
                transaction.rollback()
    finally:
        engine.dispose()


def test_old_and_new_lookup_keys_find_one_officer(lookup_case):
    """Retained keys must find evidence created before lookup-key rotation."""
    connection, crypto, identifier, add = lookup_case

    officer_uid = add(stored_key_version="lookup-v1")
    add(officer_uid=officer_uid, stored_key_version="lookup-v2")

    result = find_identifier_candidates(connection, crypto, identifier)

    assert result.status == "SINGLE_CANDIDATE"
    assert result.officer_uids == (officer_uid,)
    assert len(result.evidence) == 2
    assert result.searched_lookup_key_versions == ("lookup-v1", "lookup-v2")


def test_different_normalization_profile_is_excluded(lookup_case):
    """Equal digests must not silently cross normalization-profile boundaries."""
    connection, crypto, identifier, add = lookup_case
    add(profile="OTHER_PROFILE_V1")

    result = find_identifier_candidates(connection, crypto, identifier)

    assert result.status == "NO_CANDIDATE_FOUND"
    assert result.evidence == ()


def test_digest_must_match_its_recorded_key_version(lookup_case):
    """A digest generated with v1 must not match a row labelled as v2."""
    connection, crypto, identifier, add = lookup_case
    add(
        stored_key_version="lookup-v2",
        digest_key_version="lookup-v1",
    )

    result = find_identifier_candidates(connection, crypto, identifier)

    assert result.status == "NO_CANDIDATE_FOUND"


def test_multiple_officers_and_disputed_evidence_remain_visible(lookup_case):
    """The query must retain conflicting candidates for review."""
    connection, crypto, identifier, add = lookup_case
    first = add()
    second = add(record_state="DISPUTED")

    result = find_identifier_candidates(connection, crypto, identifier)

    assert result.status == "MULTIPLE_CANDIDATES"
    assert set(result.officer_uids) == {first, second}
    assert {item.record_state for item in result.evidence} == {
        "ASSERTED", "DISPUTED"
    }