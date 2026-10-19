"""Source-scoped exact station matches; no permanent or historical identity claim."""

from collections import defaultdict
from dataclasses import dataclass, field


STATION_MATCH_POLICY = "STATION_EXACT_TRIM_V1"


@dataclass(frozen=True)
class StationIndex:
    candidates: dict = field(repr=False)
    source_rows: dict = field(repr=False)


def build_station_index(rows):
    """Rows are (source_row_reference, source_value_dict) pairs.

    Reject all duplicate codes, even identical duplicates, instead of silently
    choosing provenance. Multiple codes with the same name remain ambiguous.
    """
    names = defaultdict(list)
    source_rows = {}
    seen_rows = set()
    for raw_id, values in rows:
        if not isinstance(raw_id, str) or not raw_id.strip() or raw_id in seen_rows:
            raise ValueError("Invalid or duplicate station source-row reference.")
        code, name = values.get("station_code"), values.get("station_name")
        if not isinstance(code, str) or not isinstance(name, str):
            raise ValueError("Station code and name must be text.")
        code, name = code.strip(), name.strip()
        if not code or not name or len(code) > 100 or "\x00" in code + name:
            raise ValueError("Station reference fields are invalid.")
        if code in source_rows:
            raise ValueError("Duplicate station code requires review.")
        seen_rows.add(raw_id)
        source_rows[code] = raw_id
        names[name].append(code)
    if not source_rows:
        raise ValueError("Station reference snapshot is empty.")
    return StationIndex({name: tuple(sorted(codes)) for name, codes in names.items()}, source_rows)


def load_staged_station_index(connection, crypto, backup, *, batch_id):
    """Read and validate the registered station snapshot within caller's transaction."""
    from pathlib import PurePosixPath
    from sqlalchemy import select
    from app.staging.models import IntakeFile, RawRecord
    from app.intake.staging_store import stored_row
    from app.intake.staging_rows import open_row

    files = connection.execute(select(IntakeFile.__table__).where(
        IntakeFile.batch_id == batch_id
    )).mappings().all()
    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == "station_master.csv"]
    if len(selected) != 1:
        raise ValueError("Expected exactly one registered station-master file.")
    file = selected[0]
    if not {"station_code", "station_name"}.issubset(file["columns"]):
        raise ValueError("Station-master required headers are missing.")
    rows = []
    query = select(RawRecord.__table__).where(
        RawRecord.import_file_id == file["import_file_id"]
    ).order_by(RawRecord.source_row_number)
    for number, raw in enumerate(connection.execute(query).mappings(), 1):
        if raw["source_row_number"] != number:
            raise ValueError("Station source row sequence has a gap.")
        for key in ("batch_id", "archive_path", "source_file_sha256"):
            if raw[key] != file[key]:
                raise ValueError("Station source binding differs from registration.")
        stored = stored_row(raw)
        payload = open_row(crypto, stored)
        if payload != open_row(backup, stored) or payload["columns"] != file["columns"]:
            raise ValueError("Station source headers or backup recovery differ.")
        rows.append((raw["raw_record_id"], dict(zip(payload["columns"], payload["values"], strict=True))))
    if len(rows) != file["expected_row_count"]:
        raise ValueError("Station source count differs from registration.")
    return build_station_index(rows), {
        "batch_id": batch_id, "import_file_id": str(file["import_file_id"]),
        "archive_path": file["archive_path"], "source_file_sha256": file["source_file_sha256"],
        "match_policy": STATION_MATCH_POLICY, "historical_applicability": "UNKNOWN",
        "code_scope": "REGISTERED_SOURCE_SNAPSHOT",
    }
