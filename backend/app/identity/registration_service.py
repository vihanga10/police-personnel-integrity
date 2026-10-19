"""Register one PF profile atomically, preserving source claims and decisions."""

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from sqlalchemy import Engine, func, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.normalization import (
    NORMALIZATION_PROFILE,
    IdentifierInputError,
    normalize_identifier,
)
from app.identity.registration_policy import POLICY_VERSION, plan_registration
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, SourceSystem
from app.security.identity_crypto import IdentityCrypto
from app.staging.identity_decision import IdentityRegistrationDecision
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


PROFILE_FILENAME = "officer_personal_information.csv"
IDENTIFIER_FIELDS = {
    "officer_nic_no": "NIC",
    "police_id": "POLICE_ID",
    "regimental_no": "REGIMENTAL_NUMBER",
    "officer_tin_number": "TIN",
}
DECISIONS = IdentityRegistrationDecision.__table__
IDENTIFIERS = OfficerIdentifierVersion.__table__
ASSERTIONS = SourceAssertion.__table__
SOURCES = SourceSystem.__table__

# All registrations through this service share one lock, across batches and keys.
# Other future identity-writing services must use this same coordination rule.
REGISTRATION_LOCK = int.from_bytes(
    hashlib.sha256(b"POLICE_IDENTITY_REGISTRATION_V1").digest()[:8],
    "big",
    signed=True,
)


class RegistrationError(ValueError):
    """Registration could not safely complete; the transaction is rolled back."""


@dataclass(frozen=True)
class RegistrationResult:
    decision_id: UUID
    raw_record_id: str
    outcome: str
    reason_code: str
    officer_uid: UUID | None
    identifier_count: int
    replayed: bool


def evidence_context(kind: str, record_id: UUID) -> str:
    """Bind ciphertext to its purpose and immutable record identifier."""
    if kind not in {"DECISION", "ASSERTION", "IDENTIFIER"}:
        raise RegistrationError("Unknown encryption context purpose.")
    return json.dumps(
        ["IDENTITY_REGISTRATION_EVIDENCE_V1", kind, str(record_id)],
        separators=(",", ":"),
    )


def _json_default(value):
    """Serialize evidence metadata explicitly, without a catch-all string cast."""
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError("Unsupported evidence metadata type.")


def _json_safe(value):
    return json.loads(json.dumps(value, default=_json_default, allow_nan=False))


def _binding(decision):
    """Protect important readable decision metadata inside its ciphertext too."""
    fields = (
        "decision_id", "raw_record_id", "version_number",
        "previous_decision_id", "previous_version_number", "outcome",
        "reason_code", "officer_uid", "source_system_id",
        "source_confirmation_id", "source_confirmation_sha256",
        "policy_version", "normalization_profile", "code_revision",
    )
    return _json_safe({field: decision[field] for field in fields})


def _source(connection):
    """Register the reported PF source without asserting verified custodianship."""
    row = connection.execute(
        select(SOURCES).where(SOURCES.c.source_system_code == "PF_REGISTRY")
    ).mappings().one_or_none()
    if row is None:
        connection.execute(
            pg_insert(SOURCES).values(
                source_system_id=uuid4(),
                source_system_code="PF_REGISTRY",
                source_name="Personal File Registry",
                source_description=(
                    "Reported supplying source; independent custodianship "
                    "and source truth have not been established."
                ),
                is_active=True,
            ).on_conflict_do_nothing(index_elements=["source_system_code"])
        )
        row = connection.execute(
            select(SOURCES).where(SOURCES.c.source_system_code == "PF_REGISTRY")
        ).mappings().one()
    if row["is_active"] is not True:
        raise RegistrationError("The PF source is inactive.")
    return row["source_system_id"]


def _claim_payload(field, normalized, value, raw, confirmation):
    """Keep the received value, normalization and attribution in protected form."""
    return {
        "schema_version": "1.0",
        "source_column": field,
        "reported_value": value,
        "normalized_value": normalized.value,
        "identifier_type": normalized.identifier_type,
        "normalization_profile": NORMALIZATION_PROFILE,
        "raw_record_id": raw["raw_record_id"],
        "source_confirmation_id": confirmation.confirmation_id,
        "source_confirmation_sha256": confirmation.confirmation_sha256,
        "source_independence": "UNVERIFIED",
    }


def _create_identifier(connection, crypto, *, officer_uid, source_id,
                       field, normalized, value, raw, confirmation, recorded_at):
    assertion_id, identifier_id = uuid4(), uuid4()
    assertion_ciphertext, assertion_key = crypto.encrypt_assertion(
        _claim_payload(field, normalized, value, raw, confirmation),
        context=evidence_context("ASSERTION", assertion_id),
    )
    connection.execute(insert(ASSERTIONS), {
        "source_assertion_id": assertion_id,
        "officer_uid": officer_uid,
        "source_system_id": source_id,
        "assertion_type": f"IDENTIFIER_{normalized.identifier_type}",
        "asserted_value_ciphertext": assertion_ciphertext,
        "encryption_key_version": assertion_key,
        "intake_batch_id": raw["batch_id"],
        "import_file_id": str(raw["import_file_id"]),
        "raw_record_id": raw["raw_record_id"],
        "source_file_name": PROFILE_FILENAME,
        "source_file_sha256": raw["source_file_sha256"],
        "source_row_number": raw["source_row_number"],
        "assertion_state": "ACTIVE",
        "independence_status": "UNVERIFIED",
        "transaction_start": recorded_at,
    })

    # Unknown historical dates remain NULL; import time is transaction time only.
    ciphertext, encryption_version = crypto.encrypt(
        normalized.value.encode("utf-8"),
        context=evidence_context("IDENTIFIER", identifier_id),
    )
    lookup_hash, lookup_version = crypto.lookup_hmac(
        normalized.value, identifier_type=normalized.identifier_type,
    )
    connection.execute(insert(IDENTIFIERS), {
        "identifier_version_id": identifier_id,
        "identifier_chain_uid": uuid4(),
        "officer_uid": officer_uid,
        "source_assertion_id": assertion_id,
        "identifier_type": normalized.identifier_type,
        "identifier_value_ciphertext": ciphertext,
        "identifier_lookup_hmac": lookup_hash,
        "normalization_profile": NORMALIZATION_PROFILE,
        "encryption_key_version": encryption_version,
        "lookup_key_version": lookup_version,
        "version_number": 1,
        "record_state": "ASSERTED",
        "transaction_start": recorded_at,
    })
    return {
        "identifier_type": normalized.identifier_type,
        "identifier_version_id": str(identifier_id),
        "source_assertion_id": str(assertion_id),
    }


def _verify_created_outputs(connection, crypto, decision, outputs,
                            normalized, values, raw, confirmation):
    """A retry verifies saved evidence instead of merely trusting a row count."""
    if len(outputs) != len(normalized):
        raise RegistrationError("Saved identifier output count does not match.")
    seen = set()
    fields_by_type = {kind: field for field, kind in IDENTIFIER_FIELDS.items()}
    for output in outputs:
        kind = output["identifier_type"]
        if kind not in normalized or kind in seen:
            raise RegistrationError("Saved identifier outputs are inconsistent.")
        seen.add(kind)
        identifier_id = UUID(output["identifier_version_id"])
        assertion_id = UUID(output["source_assertion_id"])
        identifier = connection.execute(
            select(IDENTIFIERS).where(
                IDENTIFIERS.c.identifier_version_id == identifier_id
            )
        ).mappings().one()
        assertion = connection.execute(
            select(ASSERTIONS).where(ASSERTIONS.c.source_assertion_id == assertion_id)
        ).mappings().one()

        # Historical closure is permitted; original content and links must agree.
        expected_identifier = {
            "officer_uid": decision["officer_uid"],
            "source_assertion_id": assertion_id,
            "identifier_type": kind,
            "normalization_profile": NORMALIZATION_PROFILE,
        }
        expected_assertion = {
            "officer_uid": decision["officer_uid"],
            "source_system_id": decision["source_system_id"],
            "raw_record_id": raw["raw_record_id"],
            "intake_batch_id": raw["batch_id"],
            "import_file_id": str(raw["import_file_id"]),
            "source_file_name": PROFILE_FILENAME,
            "source_file_sha256": raw["source_file_sha256"],
            "source_row_number": raw["source_row_number"],
        }
        if any(identifier[k] != v for k, v in expected_identifier.items()):
            raise RegistrationError("Saved identifier binding does not match.")
        if any(assertion[k] != v for k, v in expected_assertion.items()):
            raise RegistrationError("Saved assertion binding does not match.")

        plaintext = crypto.decrypt(
            identifier["identifier_value_ciphertext"],
            key_version=identifier["encryption_key_version"],
            context=evidence_context("IDENTIFIER", identifier_id),
        )
        expected_hash, _ = crypto.lookup_hmac(
            normalized[kind].value,
            identifier_type=kind,
            key_version=identifier["lookup_key_version"],
        )
        if (plaintext != normalized[kind].value.encode("utf-8")
                or identifier["identifier_lookup_hmac"] != expected_hash):
            raise RegistrationError("Saved identifier evidence does not match.")
        field = fields_by_type[kind]
        payload = crypto.decrypt_assertion(
            assertion["asserted_value_ciphertext"],
            key_version=assertion["encryption_key_version"],
            context=evidence_context("ASSERTION", assertion_id),
        )
        if payload != _claim_payload(field, normalized[kind], values[field], raw, confirmation):
            raise RegistrationError("Saved source claim does not match.")


def _result(decision, outputs, replayed):
    return RegistrationResult(
        decision_id=decision["decision_id"],
        raw_record_id=decision["raw_record_id"],
        outcome=decision["outcome"],
        reason_code=decision["reason_code"],
        officer_uid=decision["officer_uid"],
        identifier_count=len(outputs),
        replayed=replayed,
    )


def _scope_is_usable(connection, crypto, scope):
    """Check both coverage and a stored key-material witness for each scope.

    Key versions must identify immutable key material. A witness catches a
    misconfigured keyring with a correct version label but different bytes;
    this is not a full integrity scan of every historical identifier.
    """
    if (scope["identifier_type"] not in IDENTIFIER_FIELDS.values()
            or scope["normalization_profile"] != NORMALIZATION_PROFILE
            or scope["lookup_key_version"] not in crypto.lookup_keys):
        return False
    sample = connection.execute(select(IDENTIFIERS).where(
        IDENTIFIERS.c.identifier_type == scope["identifier_type"],
        IDENTIFIERS.c.normalization_profile == scope["normalization_profile"],
        IDENTIFIERS.c.lookup_key_version == scope["lookup_key_version"],
    ).order_by(IDENTIFIERS.c.identifier_version_id).limit(1)).mappings().one()
    try:
        plaintext = crypto.decrypt(
            sample["identifier_value_ciphertext"],
            key_version=sample["encryption_key_version"],
            context=evidence_context("IDENTIFIER", sample["identifier_version_id"]),
        ).decode("utf-8")
        digest, _ = crypto.lookup_hmac(
            plaintext,
            identifier_type=scope["identifier_type"],
            key_version=scope["lookup_key_version"],
        )
    except (ValueError, InvalidTag):
        # Missing encryption keys or unsupported older contexts cannot prove coverage.
        return False
    return hmac.compare_digest(digest, sample["identifier_lookup_hmac"])


def register_personal_row(
    engine: Engine,
    crypto: IdentityCrypto,
    *,
    raw_record_id: str,
    confirmation_path: Path,
    expected_confirmation_sha256: str,
    code_revision: str,
) -> RegistrationResult:
    """Save an initial decision atomically or verify and reuse its saved result.

    Existing candidates require review under policy V1. This function never
    resolves reviews automatically, merges officers, or imports profile fields
    beyond the four supported identifier types.
    """
    for value, pattern in (
        (raw_record_id, r"[0-9a-f]{64}"),
        (expected_confirmation_sha256, r"[0-9a-f]{64}"),
        (code_revision, r"[0-9a-f]{40}"),
    ):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise RegistrationError("Invalid registration fingerprint or revision.")

    with engine.begin() as connection:
        # Fail before writes if the wrong account or database is configured.
        account, database = connection.execute(
            text("SELECT current_user, current_database()")
        ).one()
        if account != "police_identity_app" or database != "police_identity":
            raise RegistrationError("Use the restricted identity application connection.")
        if connection.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
            raise RegistrationError("Registration requires READ COMMITTED isolation.")

        # Acquire before lookup so a waiter sees its predecessor's committed inserts.
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": REGISTRATION_LOCK},
        )
        raw = connection.execute(
            select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_record_id)
        ).mappings().one()
        file = connection.execute(
            select(IntakeFile.__table__).where(IntakeFile.import_file_id == raw["import_file_id"])
        ).mappings().one()
        batch = connection.execute(
            select(IntakeBatch.__table__).where(IntakeBatch.batch_id == raw["batch_id"])
        ).mappings().one()
        if PurePosixPath(raw["archive_path"]).name != PROFILE_FILENAME:
            raise RegistrationError("This service accepts personal-information rows only.")
        if raw["source_row_number"] > file["expected_row_count"]:
            raise RegistrationError("Source row exceeds the registered file count.")

        paths = connection.execute(
            select(IntakeFile.archive_path).where(IntakeFile.batch_id == batch["batch_id"])
        ).scalars().all()
        names = {PurePosixPath(path).name for path in paths}
        if len(paths) != batch["expected_file_count"] or len(names) != len(paths):
            raise RegistrationError("Batch file registration is incomplete or ambiguous.")
        confirmation = load_source_confirmation(
            confirmation_path,
            expected_batch_id=batch["batch_id"],
            expected_archive_sha256=batch["archive_sha256"],
            expected_filenames=names,
            allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"},
        )
        if confirmation.confirmation_sha256 != expected_confirmation_sha256:
            raise RegistrationError("Source confirmation fingerprint changed.")
        if confirmation.source_for(PROFILE_FILENAME) != "PF_REGISTRY":
            raise RegistrationError("This policy requires a reported PF source.")

        payload = open_row(crypto, stored_row(raw))
        if payload["columns"] != file["columns"]:
            raise RegistrationError("Decrypted headers differ from file registration.")
        values = dict(zip(payload["columns"], payload["values"], strict=True))
        if not set(IDENTIFIER_FIELDS).issubset(values):
            raise RegistrationError("Required profile columns are missing.")
        normalized, invalid_fields = {}, []
        for field, kind in IDENTIFIER_FIELDS.items():
            value = values[field]
            if value is None or (isinstance(value, str) and not value.strip()):
                continue
            try:
                normalized[kind] = normalize_identifier(value, identifier_type=kind)
            except IdentifierInputError:
                invalid_fields.append(field)

        source_id = _source(connection)
        existing = connection.execute(
            select(DECISIONS).where(DECISIONS.c.raw_record_id == raw_record_id)
            .order_by(DECISIONS.c.version_number.desc()).limit(1)
        ).mappings().one_or_none()
        if existing is not None:
            # Re-evaluation is a separate future review operation, never a retry.
            if (existing["version_number"] != 1
                    or existing["policy_version"] != POLICY_VERSION
                    or existing["normalization_profile"] != NORMALIZATION_PROFILE
                    or existing["source_system_id"] != source_id
                    or existing["source_confirmation_id"] != confirmation.confirmation_id
                    or existing["source_confirmation_sha256"] != expected_confirmation_sha256):
                raise RegistrationError("Saved decision requires an explicit review workflow.")
            saved = crypto.decrypt_assertion(
                existing["evidence_ciphertext"],
                key_version=existing["encryption_key_version"],
                context=evidence_context("DECISION", existing["decision_id"]),
            )
            if saved.get("schema_version") != "1.0" or saved.get("binding") != _binding(existing):
                raise RegistrationError("Saved decision evidence binding does not match.")
            outputs = saved["outputs"]
            if existing["outcome"] == "CREATED":
                _verify_created_outputs(
                    connection, crypto, existing, outputs, normalized, values, raw, confirmation,
                )
            elif existing["outcome"] != "REVIEW_REQUIRED" or outputs:
                raise RegistrationError("Unsupported saved initial decision.")
            result = _result(existing, outputs, True)
        else:
            # Inspect every retained identifier scope, including closed/disputed rows.
            scopes = [dict(row) for row in connection.execute(select(
                IDENTIFIERS.c.identifier_type,
                IDENTIFIERS.c.normalization_profile,
                IDENTIFIERS.c.lookup_key_version,
            ).distinct()).mappings()]
            for scope in scopes:
                scope["key_material_checked"] = _scope_is_usable(connection, crypto, scope)
            complete = bool(crypto.lookup_keys) and all(
                scope["key_material_checked"] for scope in scopes
            )
            candidates = {
                kind: find_identifier_candidates(connection, crypto, identifier)
                for kind, identifier in normalized.items()
            }
            plan = plan_registration(
                source_code="PF_REGISTRY",
                identifiers=normalized,
                candidates=candidates,
                lookup_scope_complete=complete,
                invalid_identifier_fields=tuple(invalid_fields),
            )
            # Use database time after waiting for the registration lock.
            recorded_at = connection.execute(select(func.clock_timestamp())).scalar_one()
            officer_uid, outputs = None, []
            if plan.action == "CREATE_NEW":
                officer_uid = uuid4()
                connection.execute(insert(Officer.__table__), {"officer_uid": officer_uid})
                for field, kind in IDENTIFIER_FIELDS.items():
                    if kind in normalized:
                        outputs.append(_create_identifier(
                            connection, crypto, officer_uid=officer_uid, source_id=source_id,
                            field=field, normalized=normalized[kind], value=values[field],
                            raw=raw, confirmation=confirmation, recorded_at=recorded_at,
                        ))
            decision = {
                "decision_id": uuid4(), "raw_record_id": raw_record_id,
                "version_number": 1, "previous_decision_id": None,
                "previous_version_number": None,
                "outcome": "CREATED" if officer_uid is not None else "REVIEW_REQUIRED",
                "reason_code": plan.reason_code, "officer_uid": officer_uid,
                "source_system_id": source_id,
                "source_confirmation_id": confirmation.confirmation_id,
                "source_confirmation_sha256": confirmation.confirmation_sha256,
                "policy_version": POLICY_VERSION, "normalization_profile": NORMALIZATION_PROFILE,
                "code_revision": code_revision, "recorded_at": recorded_at,
            }
            evidence = {
                "schema_version": "1.0", "binding": _binding(decision),
                "source_independence": "UNVERIFIED",
                "lookup_scope_complete": complete, "stored_lookup_scopes": scopes,
                "searched_lookup_key_versions": sorted(crypto.lookup_keys),
                "invalid_identifier_fields": invalid_fields,
                "missing_identifier_types": sorted(set(IDENTIFIER_FIELDS.values()) - set(normalized)),
                "candidates": _json_safe({kind: asdict(value) for kind, value in candidates.items()}),
                "outputs": outputs,
            }
            ciphertext, key_version = crypto.encrypt_assertion(
                evidence, context=evidence_context("DECISION", decision["decision_id"]),
            )
            connection.execute(insert(DECISIONS), {
                **decision, "evidence_ciphertext": ciphertext,
                "encryption_key_version": key_version,
            })
            result = _result(decision, outputs, False)

    # Report success only after the transaction commits; failures roll back all writes.
    return result
