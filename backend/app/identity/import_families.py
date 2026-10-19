"""Guarded local HR family intake; read-only by default and no Mongo connection.

Human HQ Admin authentication and restricted viewing remain pending. Never expose
this development CLI as an unauthenticated upload endpoint.
"""
import argparse
from collections import Counter
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from uuid import UUID, uuid4
from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.models import SourceAssertion
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.normalization import normalize_identifier
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION, verified_nic_evidence
from app.identity.inspect_remaining_sources import HEADERS
from app.identity.inspect_history_sources import inspected_link
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.remaining_plan import plan_remaining, validate_remaining_routing
from app.identity.remaining_plan_crypto import seal_remaining_plan, open_remaining_plan
from app.identity.family_records import POLICY, FILENAME, check_payload, logical_records
from app.identity.family_writer import FamilyBinding, RECEIPT, transform
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.intake.registration_receipt import save_receipt


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "attempt-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-rows", required=True, type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args()
    if (args.batch_id, args.expected_archive_sha256, args.expected_confirmation_sha256, args.expected_rows) != (BATCH, ARCHIVE, CONFIRMATION, 6596):
        parser.error("Expected reviewed BATCH-RAW-001 fingerprints and 6596 family rows.")
    return args


def family_payload(connection, crypto, backup, raw, file, revision, subject_cache, actor_cache):
    """Dual-key recovery and exact NIC discovery precede every proposed write."""
    if any(raw[k] != file[k] for k in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("Family raw/file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
        raise ValueError("Family source header/recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    cache_key, _ = crypto.lookup_hmac(nic.value, identifier_type="NIC")
    if cache_key not in subject_cache:
        candidates = find_identifier_candidates(connection, crypto, nic)
        if candidates.status != "SINGLE_CANDIDATE" or len(candidates.officer_uids) != 1:
            raise ValueError("Family subject linkage requires review.")
        refs = sorted(verified_nic_evidence(connection, crypto, backup, nic, candidates), key=lambda r: r["identifier_version_id"])
        if not refs: raise ValueError("No exact encrypted family subject NIC evidence.")
        subject_cache[cache_key] = (candidates.officer_uids[0], refs)
    officer, identifiers = subject_cache[cache_key]
    state, actor = inspected_link(connection, crypto, backup, row["recorded_by_officer_nic"], actor_cache)
    identities = {"officer_nic_no": dict(candidate_state="EXACT_EVIDENCE_CANDIDATE", officer_uid=str(officer)),
        "recorded_by_officer_nic": dict(candidate_state=state, officer_uid=str(actor) if actor else None)}
    references = dict(batch_id=BATCH, archive_sha256=ARCHIVE, confirmation_sha256=CONFIRMATION,
        source_system_code="POLICE_HR_IS", raw_record_id=raw["raw_record_id"], import_file_id=str(raw["import_file_id"]),
        source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        identity_candidates=identities, identifier_evidence=identifiers,
        historical_eligibility="UNASSESSED", reference_linkage="UNASSESSED")
    plan = plan_remaining(FILENAME, row, officer_uid=officer, identity_candidates={"recorded_by_officer_nic": actor} if actor else {})
    cipher, version = seal_remaining_plan(crypto, plan, raw_record_id=raw["raw_record_id"], reference_evidence=references)
    options = dict(key_version=version, filename=FILENAME, raw_record_id=raw["raw_record_id"])
    payload = open_remaining_plan(crypto, cipher, **options)
    if open_remaining_plan(backup, cipher, **options) != payload: raise ValueError("Family plan recovery differs.")
    check_payload(payload)
    fingerprint, _ = crypto.lookup_hmac(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")), identifier_type="FAMILY_PREFLIGHT_V1")
    binding = FamilyBinding(raw["raw_record_id"], UUID(identifiers[0]["identifier_version_id"]), CONFIRMATION, revision)
    return payload, binding, fingerprint


def commit_row(engine, crypto, backup, binding, payload):
    """A fresh connection resolves a lost commit acknowledgement before retry.

    Unique raw-record receipts and advisory transaction locks serialize cooperating
    writers. A partially committed row is impossible within this SQL transaction.
    """
    try:
        with engine.begin() as connection:
            result = transform(connection, crypto, backup, binding=binding, payload=payload, allow_write=True)
    except Exception:
        # Do not delete or fabricate a receipt when the commit outcome is uncertain.
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                recovered = transform(connection, crypto, backup, binding=binding, payload=payload)
                if recovered[0] != "VERIFIED_EXISTING": raise
        return "VERIFIED_EXISTING", recovered[1]
    with engine.connect() as connection:
        with connection.begin():
            connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            durable = transform(connection, crypto, backup, binding=binding, payload=payload)
            if durable[0] != "VERIFIED_EXISTING" or durable[1] != result[1]:
                raise ValueError("Family durable commit recovery differs.")
    return result


def main():
    args = arguments()
    engine = journal = pending = None
    outcomes, sequence = Counter(), 0
    try:
        repository = Path(__file__).resolve().parents[3]
        def git(*parts): return subprocess.check_output(["git", "-C", str(repository), *parts], text=True).strip()
        if git("status", "--porcelain"): raise ValueError("Commit reviewed source before this workflow.")
        revision = git("rev-parse", "HEAD")
        if re.fullmatch("[0-9a-f]{40}", revision) is None: raise ValueError("Unsupported code revision.")
        if args.key_file.resolve() == args.backup_key_file.resolve(): raise ValueError("Separate primary/backup keys required.")
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        validate_remaining_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected family application target.")
        engine = create_identity_engine(settings)
        selection, snapshots = [], {}
        officers, statuses, destinations, warnings, reviews = set(), Counter(), Counter(), Counter(), 0
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                if tuple(connection.execute(text("SELECT current_user, current_database()")).one()) != ("police_identity_app", "police_identity"):
                    raise ValueError("Unexpected connected target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = {PurePosixPath(f["archive_path"]).name for f in files}
                if batch["archive_sha256"] != ARCHIVE or len(files) != batch["expected_file_count"] or len(names) != len(files):
                    raise ValueError("Family archive/file membership differs.")
                confirmation = load_source_confirmation(args.confirmation, expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE,
                    expected_filenames=names, allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                if confirmation.confirmation_sha256 != CONFIRMATION or confirmation.source_for(FILENAME) != "POLICE_HR_IS":
                    raise ValueError("Family source confirmation differs.")
                chosen = [f for f in files if PurePosixPath(f["archive_path"]).name == FILENAME]
                if len(chosen) != 1: raise ValueError("One registered family file required.")
                file = chosen[0]
                if file["expected_row_count"] != 6596 or tuple(file["columns"]) != HEADERS[FILENAME]:
                    raise ValueError("Family count/header differs.")
                subject_cache, actor_cache = {}, {}
                rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)).mappings()
                for number, raw in enumerate(rows, 1):
                    if raw["source_row_number"] != number: raise ValueError("Family source sequence has a gap.")
                    payload, binding, fingerprint = family_payload(connection, crypto, backup, raw, file, revision, subject_cache, actor_cache)
                    if payload["officer_uid"] in officers: raise ValueError("Repeated family subject requires review.")
                    officers.add(payload["officer_uid"])
                    status, count = transform(connection, crypto, backup, binding=binding, payload=payload)
                    if args.reconcile and status != "VERIFIED_EXISTING": raise ValueError("Family reconciliation found an incomplete row.")
                    selection.append((raw["raw_record_id"], number))
                    snapshots[raw["raw_record_id"]] = (payload["officer_uid"], binding.identifier_version_id, fingerprint)
                    statuses[status] += 1; reviews += bool(payload["needs_review"])
                    destinations.update(r.table for r in logical_records(payload))
                    for field in payload["fields"]:
                        warnings.update(field["source_column"] + ":" + issue for issue in field["issues"])
                    warnings.update(payload["uncertainties"])
                if len(selection) != 6596 or len(officers) != 6596: raise ValueError("Family row/officer coverage differs.")
                # Reject orphan receipts/assertions and evidence from an unexpected batch.
                receipts = connection.execute(select(RECEIPT.c.raw_record_id, RECEIPT.c.source_assertion_id)).all()
                selected_ids = {rid for rid, _ in selection}
                if any(rid not in selected_ids for rid, _ in receipts): raise ValueError("Family receipt outside reviewed batch.")
                assertions = set(connection.execute(select(SourceAssertion.source_assertion_id).where(SourceAssertion.assertion_type == "HR_FAMILY_EVIDENCE")).scalars())
                if assertions != {aid for _, aid in receipts}: raise ValueError("Orphan family assertion or receipt.")
        root = args.attempt_root.expanduser().absolute()
        if root.resolve().is_relative_to(repository) or any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("Keep private attempts outside Git without symlink paths.")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.stat().st_mode & 0o077: raise ValueError("Attempt root must be owner-only.")
        journal = root / str(uuid4()); journal.mkdir(mode=0o700)
        metadata = dict(batch_id=BATCH, code_revision=revision, writer_policy=POLICY, archive_sha256=ARCHIVE,
            confirmation_sha256=CONFIRMATION, mode="WRITE" if args.write else "RECONCILE" if args.reconcile else "VALIDATION",
            actor_context="LOCAL_DEVELOPMENT_INTAKE_SESSION")
        def event(kind, **extra):
            nonlocal sequence
            sequence += 1
            save_receipt(dict(metadata, sequence=sequence, event=kind, **extra), journal / f"{sequence:08d}.json")
        event("PREFLIGHT_PASSED", rows=len(selection), reviews=reviews, states=dict(statuses), destinations=dict(destinations), warnings=dict(warnings))
        print("Attempt directory:", journal, flush=True)
        print("Validated family rows:", len(selection), flush=True)
        print("Rows retaining field review:", reviews, flush=True)
        print("Destination counts:", dict(destinations), flush=True)
        print("States before execution:", dict(statuses), flush=True)
        print("Warnings:", dict(sorted(warnings.items())), flush=True)
        if args.write:
            for progress, (raw_id, number) in enumerate(selection, 1):
                pending = raw_id; event("ROW_STARTED", raw_record_id=raw_id, source_row_number=number)
                with engine.connect() as connection:
                    with connection.begin():
                        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                        raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_id)).mappings().one()
                        payload, binding, fingerprint = family_payload(connection, crypto, backup, raw, file, revision, {}, {})
                        prior = snapshots[raw_id]
                        if prior[:2] != (payload["officer_uid"], binding.identifier_version_id) or not hmac.compare_digest(prior[2], fingerprint):
                            raise ValueError("Family source/linkage changed after preflight.")
                status, _ = commit_row(engine, crypto, backup, binding, payload)
                outcomes[status] += 1; event("ROW_COMPLETED", raw_record_id=raw_id, source_row_number=number, status=status); pending = None
                if progress % 500 == 0 or progress == len(selection): print("Family progress:", progress, "/", len(selection), flush=True)
        else: outcomes.update(statuses)
        event("COMPLETED", outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("Family workflow: PASSED")
        print("Classification remains UNASSESSED; family identity, valid periods, reference linkage and authority remain unassessed.")
        print("Existing PF family evidence preserved; no user disclosure or verified-current-state claim.")
        if not args.write: print("No database writes; private attempt journal saved without personnel values.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if journal is not None:
            try:
                sequence += 1
                save_receipt(dict(sequence=sequence, event="STOPPED", error_type=type(error).__name__, pending_raw_record_id=pending,
                    outcomes=dict(outcomes)), journal / f"{sequence:08d}.json")
            except Exception: print("Stop-event persistence failed; inspect existing attempt directory.")
        print("Family workflow stopped:", type(error).__name__)
        print("Committed evidence is preserved; retry verifies atomic receipts and destinations. No deletion.")
        return 1
    finally:
        if engine is not None: engine.dispose()


if __name__ == "__main__": raise SystemExit(main())
