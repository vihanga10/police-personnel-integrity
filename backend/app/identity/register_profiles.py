"""Validate staged PF profiles, then optionally register them with durable progress."""

import argparse
import hashlib
import hmac
import re
import subprocess
from pathlib import Path, PurePosixPath

from sqlalchemy import select, text

from database import create_identity_engine
from settings import Settings
from app.identity.registration_journal import RegistrationJournal
from app.identity.registration_service import IDENTIFIER_FIELDS, PROFILE_FILENAME, register_personal_row
from app.intake.registration_receipt import save_receipt
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.security.identity_crypto import IdentityCrypto
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


class BatchRegistrationError(ValueError):
    """A batch precondition failed; messages contain no personnel values."""


def private_key_file(path):
    """Require an existing private regular key file before reading secrets."""
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise BatchRegistrationError("Key files must be private regular files.")
    return IdentityCrypto(path)


def verify_recovery(primary, backup):
    """Require backup coverage for every currently configured key version."""
    for name in ("encryption_keys", "lookup_keys"):
        original = getattr(primary, name)
        recovered = getattr(backup, name)
        if not original or any(
            version not in recovered or not hmac.compare_digest(key, recovered[version])
            for version, key in original.items()
        ):
            raise BatchRegistrationError("Backup key coverage differs from active configuration.")
    # Exercise the active encryption key and the backup decryption path.
    ciphertext, version = primary.encrypt(b"registration-preflight", context="REGISTRATION_PREFLIGHT_V1")
    if backup.decrypt(ciphertext, key_version=version, context="REGISTRATION_PREFLIGHT_V1") != b"registration-preflight":
        raise BatchRegistrationError("Backup encryption recovery failed.")


def preflight(engine, crypto, backup, args):
    """Check all selected encrypted rows in one read-only snapshot before writes."""
    plan = []
    with engine.connect() as connection:
        with connection.begin():
            connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            account, database = connection.execute(text("SELECT current_user, current_database()")).one()
            if (account, database) != ("police_identity_app", "police_identity"):
                raise BatchRegistrationError("Use the restricted application database account.")
            batch = connection.execute(select(IntakeBatch.__table__).where(
                IntakeBatch.batch_id == args.batch_id
            )).mappings().one()
            if batch["archive_sha256"] != args.expected_archive_sha256:
                raise BatchRegistrationError("Registered archive fingerprint differs.")
            files = connection.execute(select(IntakeFile.__table__).where(
                IntakeFile.batch_id == args.batch_id
            )).mappings().all()
            names = {PurePosixPath(item["archive_path"]).name for item in files}
            if len(files) != batch["expected_file_count"] or len(names) != len(files):
                raise BatchRegistrationError("Registered file membership is incomplete or ambiguous.")
            confirmation = load_source_confirmation(
                args.confirmation,
                expected_batch_id=args.batch_id,
                expected_archive_sha256=args.expected_archive_sha256,
                expected_filenames=names,
                allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"},
            )
            if confirmation.confirmation_sha256 != args.expected_confirmation_sha256:
                raise BatchRegistrationError("Source confirmation fingerprint differs.")
            if confirmation.source_for(PROFILE_FILENAME) != "PF_REGISTRY":
                raise BatchRegistrationError("Personal-information supplier must be PF_REGISTRY.")
            selected = [item for item in files if PurePosixPath(item["archive_path"]).name == PROFILE_FILENAME]
            if len(selected) != 1:
                raise BatchRegistrationError("Expected exactly one personal-information file.")
            file = selected[0]
            if file["expected_row_count"] != args.expected_rows:
                raise BatchRegistrationError("Registered profile count differs from expectation.")
            if not set(IDENTIFIER_FIELDS).issubset(file["columns"]):
                raise BatchRegistrationError("Required identifier columns are missing.")
            query = select(RawRecord.__table__).where(
                RawRecord.import_file_id == file["import_file_id"]
            ).order_by(RawRecord.source_row_number)
            for number, raw in enumerate(connection.execute(query).mappings(), 1):
                if raw["source_row_number"] != number:
                    raise BatchRegistrationError("Staged row sequence contains a gap.")
                for name in ("batch_id", "archive_path", "source_file_sha256"):
                    if raw[name] != file[name]:
                        raise BatchRegistrationError("Staged source binding differs from registered file.")
                row = stored_row(raw)
                payload = open_row(crypto, row)
                if payload["columns"] != file["columns"]:
                    raise BatchRegistrationError("Decrypted headers differ from registration.")
                # Demonstrate backup-key recovery for every selected stored row.
                if open_row(backup, row) != payload:
                    raise BatchRegistrationError("Backup decryption differs.")
                plan.append((raw["raw_record_id"], number))
            if len(plan) != args.expected_rows:
                raise BatchRegistrationError("Staged row count differs from expectation.")
    # Only opaque source references leave this validation routine.
    return plan


def run_batch(engine, crypto, backup, args, *, code_revision):
    """Persist intent, validate the full selection, then commit one row at a time."""
    journal = RegistrationJournal(
        args.attempt_root, batch_id=args.batch_id,
        archive_sha256=args.expected_archive_sha256,
        confirmation_sha256=args.expected_confirmation_sha256,
        code_revision=code_revision, write_enabled=args.write,
    )
    print(f"Attempt directory: {journal.directory}", flush=True)
    try:
        verify_recovery(crypto, backup)
        plan = preflight(engine, crypto, backup, args)
        # Bind the ordered selection and connection target into the preflight evidence.
        selection_hash = hashlib.sha256(
            "".join(f"{number}:{raw_id}\n" for raw_id, number in plan).encode("ascii")
        ).hexdigest()
        save_receipt({
            "report_schema_version": "1.0", "attempt_id": journal.attempt_id,
            "code_revision": code_revision, "validated_rows": len(plan),
            "source_file": PROFILE_FILENAME, "selection_sha256": selection_hash,
            "archive_sha256": args.expected_archive_sha256,
            "confirmation_sha256": args.expected_confirmation_sha256,
            "database_host": args.db_host, "database_port": args.db_port,
            "backup_recovery": "PASSED", "source_independence": "UNVERIFIED",
            "scope": "Staged source binding, headers, row sequence and decryption",
            "not_assessed": ["identifier_truth", "authority", "historical_state"],
        }, journal.directory / "preflight.json")
        print(f"Staged-profile and backup recovery validation: PASSED | rows={len(plan)}", flush=True)
        if not args.write:
            journal.complete(expected_rows=0)
            print("Mode: VALIDATION ONLY — no database writes", flush=True)
            return dict(journal.counts)
        for raw_id, number in plan:
            # A durable start event is required before each database transaction.
            journal.start_row(raw_record_id=raw_id, source_row_number=number)
            result = register_personal_row(
                engine, crypto, raw_record_id=raw_id,
                confirmation_path=args.confirmation,
                expected_confirmation_sha256=args.expected_confirmation_sha256,
                code_revision=code_revision,
            )
            journal.complete_row(result)
            if number % 100 == 0 or number == len(plan):
                print(f"Registration progress: {number}/{len(plan)}", flush=True)
        journal.complete(expected_rows=len(plan))
        print(f"Completed decision counts: {journal.counts}", flush=True)
        return dict(journal.counts)
    except BaseException as error:
        # A failed post-commit journal write leaves a pending row, never a false rollback claim.
        if not journal.broken and not journal.finished:
            try:
                journal.fail(error)
            except Exception:
                print("Failure event could not be saved; inspect the last durable event.", flush=True)
        raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--confirmation", type=Path, required=True)
    parser.add_argument("--expected-confirmation-sha256", required=True)
    parser.add_argument("--expected-rows", type=int, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--backup-key-file", type=Path, required=True)
    parser.add_argument("--attempt-root", type=Path, required=True)
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    if args.expected_rows <= 0 or not 1 <= args.db_port <= 65535:
        parser.error("Expected rows and database port must be positive and valid.")
    for value in (args.expected_archive_sha256, args.expected_confirmation_sha256):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            parser.error("Expected fingerprints must be lowercase SHA-256 values.")
    return args


def main(argv=None):
    args = parse_args(argv)
    engine = None
    try:
        repository = Path(__file__).resolve().parents[3]
        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()
        if git("status", "--porcelain"):
            raise BatchRegistrationError("Commit reviewed code before running the batch command.")
        revision = git("rev-parse", "HEAD")
        attempt_root = args.attempt_root.expanduser().resolve()
        if attempt_root.is_relative_to(repository):
            raise BatchRegistrationError("Attempt evidence must be outside the source repository.")
        # Keep the un-resolved path for the journal's symlink checks.
        args.attempt_root = args.attempt_root.expanduser()
        if args.key_file.resolve() == args.backup_key_file.resolve():
            raise BatchRegistrationError("Use a separate backup key file.")
        crypto = private_key_file(args.key_file)
        backup = private_key_file(args.backup_key_file)
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != (
            args.db_host, args.db_port, "police_identity", "police_identity_app"
        ):
            raise BatchRegistrationError("Configured database differs from the requested target.")
        print(f"Database target: {settings.host}:{settings.port}/{settings.name}", flush=True)
        engine = create_identity_engine(settings)
        run_batch(engine, crypto, backup, args, code_revision=revision)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Avoid tracebacks or SQL parameters containing confidential source values.
        print(f"Registration stopped: {type(error).__name__}. Completed commits remain saved.", flush=True)
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
