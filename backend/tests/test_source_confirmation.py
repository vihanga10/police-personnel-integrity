"""Tests use metadata fixtures and never read personnel values."""

import hashlib
import json

import pytest

from app.intake.source_confirmation import (
    SourceConfirmationError,
    load_source_confirmation,
)


@pytest.fixture
def document():
    return {
        "schema_version": "1.0",
        "confirmation_id": "TEST-CONFIRMATION-001",
        "batch_id": "TEST-BATCH",
        "archive_sha256": "a" * 64,
        "confirmed_on": "2026-10-05",
        "confirmed_by": "Test reviewer",
        "confirmation_basis": "Explicit source declaration",
        "scope": "Reported supplying source",
        "original_archive_modified": False,
        "independent_custodian_verification": "NOT_ESTABLISHED",
        "source_independence": "UNVERIFIED",
        "source_truth": "NOT_ASSESSED",
        "files": [
            {
                "file_name": "personal.csv",
                "reported_source_system_code": "PF_REGISTRY",
            }
        ],
    }


def load(path):
    # Expected values come from the verified intake, not the document itself.
    return load_source_confirmation(
        path,
        expected_batch_id="TEST-BATCH",
        expected_archive_sha256="a" * 64,
        expected_filenames={"personal.csv"},
        allowed_source_codes={"PF_REGISTRY"},
    )


def save(tmp_path, document):
    path = tmp_path / "confirmation.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_valid_assignment_preserves_limits_and_fingerprint(tmp_path, document):
    path = save(tmp_path, document)
    result = load(path)

    assert result.source_for("personal.csv") == "PF_REGISTRY"
    assert result.source_independence == "UNVERIFIED"
    assert result.confirmation_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()

    # A missing assignment must not silently fall back to PF.
    with pytest.raises(SourceConfirmationError):
        result.source_for("unknown.csv")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("batch_id", "OTHER-BATCH"),
        ("archive_sha256", "b" * 64),
        ("source_independence", "INDEPENDENT"),
        ("source_truth", "VERIFIED"),
        ("independent_custodian_verification", "VERIFIED"),
        ("original_archive_modified", True),
        ("confirmed_by", ""),
        ("confirmed_on", "2026-02-30"),
    ],
)
def test_rejects_wrong_binding_or_unsupported_claims(
    tmp_path, document, field, value
):
    document[field] = value
    with pytest.raises(SourceConfirmationError):
        load(save(tmp_path, document))


@pytest.mark.parametrize("problem", ["missing", "duplicate", "extra", "source"])
def test_rejects_invalid_file_assignments(tmp_path, document, problem):
    if problem == "missing":
        document["files"] = []
    elif problem == "duplicate":
        document["files"].append(dict(document["files"][0]))
    elif problem == "extra":
        document["files"].append(
            {
                "file_name": "unexpected.csv",
                "reported_source_system_code": "PF_REGISTRY",
            }
        )
    else:
        document["files"][0]["reported_source_system_code"] = "UNKNOWN"

    with pytest.raises(SourceConfirmationError):
        load(save(tmp_path, document))


def test_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "confirmation.json"
    path.write_text('{"batch_id":"A","batch_id":"B"}', encoding="utf-8")

    with pytest.raises(SourceConfirmationError, match="Duplicate JSON key"):
        load(path)