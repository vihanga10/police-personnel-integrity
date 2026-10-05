"""Test intake preflight without using personnel data or a real database."""

import base64
import hashlib
import json
import os
from argparse import Namespace
from uuid import uuid4
from zipfile import ZipFile

import pytest

from app.intake import register_batch
from app.intake.checksums import IntegrityError
from app.intake.csv_structure import CsvStructureError


def write_json(path, document):
    """Write predictable test metadata and return its exact fingerprint."""
    content = json.dumps(document, ensure_ascii=False).encode("utf-8")
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


@pytest.fixture
def package_factory(tmp_path):
    """Build a tiny registered package, with optional wrong row expectations."""
    def build(*, expected_rows=1):
        root = "test-package"
        batch = "TEST-BATCH"
        filename = "example.csv"
        relative = f"{batch}/original/{filename}"
        member = f"{root}/{relative}"
        columns = ["id", "value"]
        content = b"id,value\n001,example\n"
        file_hash = hashlib.sha256(content).hexdigest()

        inventory_path = tmp_path / "inventory.json"
        inventory_hash = write_json(inventory_path, {
            "batch_id": batch,
            "files": [{"filename": filename, "columns": columns}],
        })

        manifest = {
            "import_batch": {
                "import_batch_id": batch,
                "file_count": 1,
            },
            "files": [{
                "file_name": filename,
                "package_path": relative,
                "sha256": file_hash,
                "size_bytes": len(content),
                "columns": columns,
                "column_count": len(columns),
                "encoding": "UTF-8",
                "delimiter": ",",
                "row_count_excluding_header": expected_rows,
            }],
        }

        archive = tmp_path / "package.zip"
        with ZipFile(archive, "w") as bundle:
            bundle.writestr(member, content)
            bundle.writestr(
                f"{root}/batch_manifest.json", json.dumps(manifest)
            )
            bundle.writestr(
                f"{root}/original_files.sha256",
                f"{file_hash}  {relative}\n",
            )

        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        receipt_path = tmp_path / "receipt.json"
        write_json(receipt_path, {
            "receipt_id": str(uuid4()),
            "batch_id": batch,
            "integrity_status": "PASSED",
            "archive": {
                "sha256": archive_hash,
                "size_bytes": archive.stat().st_size,
            },
            "file_count": 1,
            "files": [{
                "filename": filename,
                "archive_path": member,
                "sha256": file_hash,
                "size_bytes": len(content),
            }],
            "verification_inputs": {
                "expected_archive_sha256": archive_hash,
                "inventory_sha256": inventory_hash,
                "package_root": root,
                "expected_filenames": [filename],
            },
        })

        # Disposable keys belong only to this temporary test package.
        secret_folder = tmp_path / "keys"
        secret_folder.mkdir(mode=0o700)
        key_file = secret_folder / "test-keys.json"
        descriptor = os.open(
            key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({
                "active_encryption_key_version": "test-enc",
                "encryption_keys": {
                    "test-enc": base64.b64encode(os.urandom(32)).decode("ascii")
                },
                "active_lookup_key_version": "test-lookup",
                "lookup_keys": {
                    "test-lookup": base64.b64encode(os.urandom(32)).decode("ascii")
                },
            }, stream)

        return Namespace(
            archive=archive,
            expected_sha256=archive_hash,
            batch_id=batch,
            package_root=root,
            inventory=inventory_path,
            receipt=receipt_path,
            key_file=key_file,
            only_file=None,
            write=False,
        )

    return build


@pytest.fixture(autouse=True)
def prohibit_database_access(monkeypatch):
    """Every test here must finish or fail before opening the database."""
    def forbidden(*args, **kwargs):
        pytest.fail("Unexpected database access during preflight.")

    monkeypatch.setattr(register_batch, "create_identity_engine", forbidden)


def test_validation_only_does_not_open_database(package_factory, capsys):
    """A valid package completes preflight without creating an engine."""
    register_batch.run(package_factory())

    output = capsys.readouterr().out
    assert "Files validated: 1" in output
    assert "Encryption preflight: PASSED" in output
    assert "VALIDATION ONLY" in output


def test_changed_archive_blocks_write_mode(package_factory):
    """An altered archive must stop even with database writes requested."""
    args = package_factory()
    args.write = True

    # Alter bytes after recording the archive fingerprint.
    with args.archive.open("ab") as stream:
        stream.write(b"changed")

    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        register_batch.run(args)


def test_wrong_row_count_blocks_write_mode(package_factory):
    """Matching fingerprints do not override a structural failure."""
    args = package_factory(expected_rows=2)
    args.write = True

    with pytest.raises(CsvStructureError, match="Row count differs"):
        register_batch.run(args)


def test_changed_inventory_blocks_write_mode(package_factory):
    """A different inventory must not silently replace the registered one."""
    args = package_factory()
    args.write = True
    document = json.loads(args.inventory.read_text(encoding="utf-8"))
    document["files"][0]["columns"] = ["different", "value"]
    write_json(args.inventory, document)

    with pytest.raises(ValueError, match="Inventory differs"):
        register_batch.run(args)