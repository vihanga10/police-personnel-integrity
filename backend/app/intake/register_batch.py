"""Validate a registered archive and optionally stage its encrypted CSV rows."""

import argparse
import csv
import hashlib
import io
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from uuid import UUID
from zipfile import ZipFile

from sqlalchemy import text

from app.intake.archive_verifier import verify_archive
from app.intake.csv_structure import validate_csv_structure
from app.intake.staging_store import stage_file
from app.security.identity_crypto import IdentityCrypto
from database import create_identity_engine
from settings import Settings
from app.intake.attempt_journal import AttemptJournal


def require(condition: bool, message: str) -> None:
    """Stop before proceeding with inconsistent registration evidence."""
    if not condition:
        raise ValueError(message)


def read_json(path: Path):
    """Return parsed metadata and the fingerprint of the exact bytes read."""
    content = path.read_bytes()
    return json.loads(content), hashlib.sha256(content).hexdigest()


def csv_rows(bundle, member, encoding, delimiter):
    """Yield original parsed strings while keeping the member stream open."""
    codec = {"UTF-8": "utf-8", "UTF-8-BOM": "utf-8-sig"}[encoding]
    with bundle.open(member) as binary:
        with io.TextIOWrapper(binary, encoding=codec, newline="") as stream:
            reader = csv.reader(
                stream,
                delimiter=delimiter,
                quotechar='"',
                doublequote=True,
                strict=True,
            )
            next(reader)  # The exact header was validated before any writes.
            yield from reader


def run(args, journal=None):
    """Validate all files before optionally importing selected files."""
    inventory, inventory_hash = read_json(args.inventory)
    receipt, receipt_hash = read_json(args.receipt)

    entries = inventory["files"]
    headers = {item["filename"]: item["columns"] for item in entries}
    require(
        bool(headers) and len(headers) == len(entries),
        "Inventory filenames must be nonempty and unique.",
    )
    require(inventory.get("batch_id") == args.batch_id, "Inventory batch differs.")
    require(receipt.get("batch_id") == args.batch_id, "Receipt batch differs.")
    require(receipt.get("integrity_status") == "PASSED", "Receipt is not passed.")
    require(
        receipt["archive"]["sha256"] == args.expected_sha256,
        "Receipt archive fingerprint differs.",
    )

    inputs = receipt["verification_inputs"]
    require(
        inputs["expected_archive_sha256"] == args.expected_sha256,
        "Receipt external fingerprint expectation differs.",
    )
    require(
        inputs["inventory_sha256"] == inventory_hash,
        "Inventory differs from the registered version.",
    )
    require(
        inputs["package_root"] == args.package_root,
        "Receipt package root differs.",
    )
    require(
        sorted(inputs["expected_filenames"]) == sorted(headers),
        "Receipt expected filenames differ.",
    )
    receipt_id = UUID(receipt["receipt_id"])

    selected = set(args.only_file or headers)
    require(
        selected <= set(headers),
        "A selected filename is absent from the registered inventory.",
    )

    # Require private key-file permissions without displaying key material.
    require(not args.key_file.is_symlink(), "Key file must not be a symlink.")
    require(args.key_file.is_file(), "Key file is missing.")
    require(
        args.key_file.stat().st_mode & 0o077 == 0,
        "Key file must have owner-only permissions.",
    )
    require(
        args.key_file.parent.stat().st_mode & 0o077 == 0,
        "Key directory must have owner-only permissions.",
    )
    crypto = IdentityCrypto(args.key_file)

    # Confirm encryption and decryption work with this configured key ring.
    probe = {"purpose": "intake-preflight"}
    encrypted, version = crypto.encrypt_assertion(
        probe, context="INTAKE_PREFLIGHT_V1"
    )
    require(
        crypto.decrypt_assertion(
            encrypted,
            key_version=version,
            context="INTAKE_PREFLIGHT_V1",
        ) == probe,
        "Encryption preflight failed.",
    )

        # The private temporary directory protects the working archive copy.
    # Snapshotting before verification binds later parsing to the verified bytes.
    with tempfile.TemporaryDirectory(prefix="police-intake-") as folder:
        snapshot = Path(folder) / "archive.zip"
        with args.archive.open("rb") as source:
            with snapshot.open("xb") as target:
                snapshot.chmod(0o600)
                shutil.copyfileobj(source, target, length=1024 * 1024)

        verified = verify_archive(
            snapshot,
            expected_sha256=args.expected_sha256,
            expected_batch_id=args.batch_id,
            package_root=args.package_root,
            expected_filenames=set(headers),
        )

        # Match all registered file fingerprints, not just the archive hash.
        registered_files = {
            item["filename"]: (
                item["archive_path"], item["sha256"], item["size_bytes"]
            )
            for item in receipt["files"]
        }
        actual_files = {
            item.filename: (
                item.archive_path,
                item.fingerprint.sha256,
                item.fingerprint.size_bytes,
            )
            for item in verified.files
        }
        require(
            len(registered_files) == len(receipt["files"])
            and registered_files == actual_files
            and receipt["file_count"] == len(actual_files)
            and receipt["archive"]["size_bytes"]
            == verified.archive_fingerprint.size_bytes,
            "Receipt does not match verified archive contents.",
        )

        with ZipFile(snapshot) as bundle:
            manifest = json.loads(
                bundle.read(
                    args.package_root + "/batch_manifest.json"
                ).decode("utf-8-sig")
            )
            records = {item["file_name"]: item for item in manifest["files"]}

            # Validate the whole package before starting any file transaction.
            total_rows = 0
            for item in verified.files:
                record = records[item.filename]
                require(
                    record["columns"] == headers[item.filename]
                    and record["column_count"] == len(headers[item.filename]),
                    f"Header contracts differ: {item.filename}",
                )
                with bundle.open(item.archive_path) as stream:
                    result = validate_csv_structure(
                        stream,
                        declared_encoding=record["encoding"],
                        delimiter=record["delimiter"],
                        expected_columns=headers[item.filename],
                        expected_row_count=record["row_count_excluding_header"],
                    )
                total_rows += result.row_count

            print("Archive integrity and CSV structure: PASSED")
            print("Files validated:", len(verified.files))
            print("Total data records:", total_rows)
            print("Encryption preflight: PASSED")

            if not args.write:
                print("Mode: VALIDATION ONLY — no database writes")
                return

            batch_values = {
                "batch_id": args.batch_id,
                "archive_sha256": verified.archive_fingerprint.sha256,
                "archive_size_bytes": verified.archive_fingerprint.size_bytes,
                "expected_file_count": len(verified.files),
                "registration_receipt_id": receipt_id,
                "registration_receipt_sha256": receipt_hash,
                "schema_version": "1.0",
            }

            engine = create_identity_engine(Settings())
            try:
                # Check the actual connection account before any registration.
                with engine.connect() as connection:
                    account = connection.execute(
                        text("SELECT current_user")
                    ).scalar_one()
                    database = connection.execute(
                        text("SELECT current_database()")
                    ).scalar_one()
                require(
                    account == "police_identity_app"
                    and database == "police_identity",
                    "Unexpected staging database or account.",
                )

                for item in verified.files:
                    if item.filename not in selected:
                        continue

                    record = records[item.filename]
                                        # Persist intent before starting the file transaction.
                    if journal is not None:
                        journal.record(
                            "FILE_STARTED",
                            filename=item.filename,
                        )
                    print("Processing:", item.filename, flush=True)
                    result = stage_file(
                        engine,
                        crypto,
                        batch_values=batch_values,
                        file_values={
                            "archive_path": item.archive_path,
                            "source_file_sha256": item.fingerprint.sha256,
                            "size_bytes": item.fingerprint.size_bytes,
                            "expected_row_count": record["row_count_excluding_header"],
                            "column_count": record["column_count"],
                            "columns": record["columns"],
                            "declared_encoding": record["encoding"],
                            "delimiter": record["delimiter"],
                        },
                        rows=csv_rows(
                            bundle,
                            item.archive_path,
                            record["encoding"],
                            record["delimiter"],
                        ),
                    )
                                        # stage_file returns only after its transaction commits.
                    if journal is not None:
                        journal.record(
                            "FILE_COMPLETED",
                            filename=item.filename,
                            row_count=result.row_count,
                            outcome=result.outcome,
                        )
                    # This message appears only after the file transaction commits.
                    print(
                        f"{result.outcome}: {item.filename} | "
                        f"rows={result.row_count}",
                        flush=True,
                    )

                print("Selected-file staging completed:", len(selected))
            finally:
                engine.dispose()

def run_logged(args, *, code_revision):
    """Record the attempt lifecycle and stop if progress cannot be persisted."""
    journal = AttemptJournal(
        args.attempt_root,
        batch_id=args.batch_id,
        expected_archive_sha256=args.expected_sha256,
        write_enabled=args.write,
        code_revision=code_revision,
    )
    print("Attempt ID:", journal.attempt_id, flush=True)
    print("Attempt directory:", journal.directory, flush=True)

    try:
        run(args, journal=journal)
        journal.record("COMPLETED")
    except Exception as exc:
        # A failed journal cannot reliably accept another event.
        if not journal.broken and not journal.finished:
            journal.record("FAILED", error_type=type(exc).__name__)
        raise


def main():
    """Expose explicit paths and expectations without hard-coded credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--only-file", action="append")
    parser.add_argument("--write", action="store_true")
        # Keep attempt records in a protected directory outside the repository.
    parser.add_argument("--attempt-root", type=Path, required=True)
    args = parser.parse_args()

    try:
                # Identify the committed implementation used for this attempt.
        repo = Path(__file__).resolve().parents[3]
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
        ).strip()
        pending = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=repo,
            text=True,
        ).strip()
        require(
            not pending,
            "Commit pending changes before running the recorded command.",
        )

        # Reject attempt storage inside the source repository.
        attempt_root = args.attempt_root.resolve()
        require(
            not attempt_root.is_relative_to(repo),
            "Attempt records must be outside the source repository.",
        )
        args.attempt_root = attempt_root

        run_logged(args, code_revision=revision)
    except Exception as exc:
        # Avoid printing database parameters, source values or raw exception text.
        print(f"Intake stopped ({type(exc).__name__}).")
        print(
            "If writes were enabled, earlier successful files may remain "
            "committed. Resolve the failure and retry the same verified inputs."
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()