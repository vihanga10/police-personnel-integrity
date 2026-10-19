"""Verify a controlled intake ZIP without extracting personnel files."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from app.intake.checksums import (
    FileFingerprint,
    IntegrityError,
    fingerprint_stream,
    verify_fingerprint,
)


@dataclass(frozen=True)
class VerifiedFile:
    """A CSV whose bytes match both supplied checksum records."""

    filename: str
    archive_path: str
    fingerprint: FileFingerprint


@dataclass(frozen=True)
class VerifiedArchive:
    """Integrity results only; these do not certify source truth."""

    batch_id: str
    archive_fingerprint: FileFingerprint
    files: tuple[VerifiedFile, ...]


def require(condition: bool, message: str) -> None:
    """Reject evidence that does not satisfy the intake contract."""
    if not condition:
        raise IntegrityError(message)


def safe_relative_path(value: str) -> bool:
    """Reject ambiguous or unsafe archive paths."""
    if not isinstance(value, str) or not value:
        return False
    if "\\" in value or "\x00" in value or ":" in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def unique_json_object(pairs):
    """Reject duplicate JSON keys instead of silently choosing the last."""
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate manifest key: {key}")
        result[key] = value
    return result


def read_metadata(bundle: ZipFile, member: str) -> bytes:
    """Bound metadata reads before decoding the manifest or checksum list."""
    limit = 2 * 1024 * 1024
    require(member in bundle.namelist(), f"Missing metadata: {member}")
    require(
        bundle.getinfo(member).file_size <= limit,
        f"Metadata exceeds size limit: {member}",
    )
    with bundle.open(member) as stream:
        content = stream.read(limit + 1)
    require(len(content) <= limit, f"Metadata exceeds size limit: {member}")
    return content


def verify_archive(
    archive_path: Path,
    *,
    expected_sha256: str,
    expected_batch_id: str,
    package_root: str,
    expected_filenames: set[str],
) -> VerifiedArchive:
    """Verify a package against caller-supplied intake expectations."""
    require(
        safe_relative_path(package_root),
        "Invalid package root.",
    )
    require(
        safe_relative_path(expected_batch_id)
        and "/" not in expected_batch_id,
        "Invalid batch identifier.",
    )
    require(
        bool(expected_filenames)
        and all(
            safe_relative_path(name)
            and "/" not in name
            and name.lower().endswith(".csv")
            for name in expected_filenames
        ),
        "Expected filenames must be plain CSV filenames.",
    )

    prefix = package_root + "/"
    original_root = f"{expected_batch_id}/original/"

    try:
        # Use the same open file for fingerprinting and ZIP inspection.
        with archive_path.open("rb") as source:
            archive_fingerprint = fingerprint_stream(source)
            verify_fingerprint(
                archive_fingerprint,
                expected_sha256=expected_sha256,
            )
            source.seek(0)

            with ZipFile(source) as bundle:
                members = bundle.infolist()
                names = [item.filename for item in members]

                require(len(names) <= 1000, "Archive has too many members.")
                require(
                    len(names) == len(set(names)),
                    "Duplicate archive member names.",
                )
                require(
                    all(
                        safe_relative_path(
                            item.filename[:-1]
                            if item.is_dir()
                            else item.filename
                        )
                        for item in members
                    ),
                    "Unsafe archive member path.",
                )

                # Bound expansion for this prototype's intake packages.
                require(
                    sum(item.file_size for item in members)
                    <= 512 * 1024 * 1024,
                    "Archive uncompressed size exceeds the intake limit.",
                )
                require(
                    not any(item.flag_bits & 1 for item in members),
                    "Encrypted ZIP members are not supported.",
                )

                manifest = json.loads(
                    read_metadata(
                        bundle, prefix + "batch_manifest.json"
                    ).decode("utf-8-sig"),
                    object_pairs_hook=unique_json_object,
                )
                require(isinstance(manifest, dict), "Manifest must be an object.")

                batch = manifest.get("import_batch")
                records = manifest.get("files")
                require(isinstance(batch, dict), "Missing import_batch object.")
                require(isinstance(records, list), "Missing manifest file list.")
                require(
                    batch.get("import_batch_id") == expected_batch_id,
                    "Manifest batch identifier differs.",
                )
                require(
                    type(batch.get("file_count")) is int
                    and batch["file_count"] == len(records)
                    and len(records) == len(expected_filenames),
                    "Manifest file count differs.",
                )

                records_by_name = {}
                for record in records:
                    require(isinstance(record, dict), "Invalid manifest record.")
                    name = record.get("file_name")
                    require(
                        isinstance(name, str) and name in expected_filenames,
                        "Unexpected manifest filename.",
                    )
                    require(
                        name not in records_by_name,
                        f"Duplicate manifest filename: {name}",
                    )
                    records_by_name[name] = record

                require(
                    set(records_by_name) == expected_filenames,
                    "Manifest CSV membership differs.",
                )

                # Read exact relative paths from the supplied checksum file.
                checksum_text = read_metadata(
                    bundle, prefix + "original_files.sha256"
                ).decode("utf-8-sig")
                checksums = {}
                for line in checksum_text.splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    match = re.fullmatch(
                        r"([0-9a-fA-F]{64})[ \t]+(.+)", line
                    )
                    require(match is not None, "Invalid checksum entry.")
                    digest, relative_path = match.groups()
                    require(
                        relative_path not in checksums,
                        "Duplicate checksum path.",
                    )
                    checksums[relative_path] = digest.lower()

                expected_paths = {
                    original_root + name for name in expected_filenames
                }
                require(
                    set(checksums) == expected_paths,
                    "Checksum-list membership differs.",
                )
                require(
                    {
                        item.filename
                        for item in members
                        if not item.is_dir()
                        and item.filename.lower().endswith(".csv")
                    }
                    == {prefix + path for path in expected_paths},
                    "Archive CSV membership differs.",
                )

                verified = []
                for name in sorted(expected_filenames):
                    record = records_by_name[name]
                    relative_path = original_root + name
                    member_path = prefix + relative_path

                    require(
                        record.get("package_path")
                        in (relative_path, member_path),
                        f"Unexpected package path: {name}",
                    )
                    require(
                        type(record.get("size_bytes")) is int
                        and record["size_bytes"] >= 0,
                        f"Invalid manifest size: {name}",
                    )

                    # Read original bytes without decoding or displaying rows.
                    with bundle.open(member_path) as stream:
                        actual = fingerprint_stream(stream)

                    verify_fingerprint(
                        actual,
                        expected_sha256=checksums[relative_path],
                    )
                    verify_fingerprint(
                        actual,
                        expected_sha256=record.get("sha256"),
                        expected_size_bytes=record["size_bytes"],
                    )
                    verified.append(VerifiedFile(name, member_path, actual))

            # Detect changes to the open archive during verification.
            source.seek(0)
            require(
                fingerprint_stream(source) == archive_fingerprint,
                "Archive changed during verification.",
            )

    except (BadZipFile, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("Unreadable ZIP or intake metadata.") from exc

    return VerifiedArchive(
        batch_id=expected_batch_id,
        archive_fingerprint=archive_fingerprint,
        files=tuple(verified),
    )