"""Local development intake: validate, deliver or reconcile PF historical evidence.

Not a user-facing endpoint. Human HQ Admin authentication/authorization remains
pending. Default mode is read-only; --write must be selected explicitly.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from uuid import UUID, uuid4

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.candidate_lookup import find_identifier_candidates
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION, verified_nic_evidence
from app.identity.inspect_history_sources import HEADERS
from app.identity.inspect_history_plans import EXPECTED_ROWS
from app.identity.normalization import normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.history_delivery import check_payload, deliver, make_delivery, reconcile, verify_mongo, collection_for
from app.identity.history_plan import ROUTES, plan_history, validate_history_routing
from app.identity.history_plan_crypto import open_history_plan, seal_history_plan
from app.identity.history_sql_ledger import DONE, PREP, HistorySourceBinding, SqlHistoryLedger, assert_saved
from app.identity.station_reference import load_staged_station_index
from app.intake.registration_receipt import save_receipt
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.storage.history_mongo_connection import history_client, history_password
from app.storage.history_mongo_contract import COLLECTION_POLICIES, DATABASE
from app.models import SourceAssertion


def history_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision):
    """Replan from encrypted originals with exact NIC and source-scoped station evidence."""
    if any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("Historical source/file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
        raise ValueError("Historical header or backup recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    identifier = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    candidates = find_identifier_candidates(connection, crypto, identifier)
    if candidates.status != "SINGLE_CANDIDATE" or len(candidates.officer_uids) != 1:
        raise ValueError("Historical officer linkage is unresolved or ambiguous.")
    officer = candidates.officer_uids[0]
    identifiers = sorted(verified_nic_evidence(connection, crypto, backup, identifier, candidates), key=lambda ref: ref["identifier_version_id"])
    if not identifiers:
        raise ValueError("No usable exact encrypted NIC evidence.")
    filename = PurePosixPath(file["archive_path"]).name
    plan = plan_history(filename, row, officer_uid=officer, station_candidates=stations.candidates)
    references = dict(history_source=dict(batch_id=raw["batch_id"], raw_record_id=raw["raw_record_id"],
        import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        reported_source_system_code="PF_REGISTRY", confirmation_sha256=args.expected_confirmation_sha256),
        identifier_evidence=identifiers, station_source=station_provenance, station_matches={})
    for item in plan.fields:
        if item.source_column in {"from_station_code", "to_station_code"} and item.status == "PARSED":
            references["station_matches"][item.source_column] = dict(station_code=item.value,
                raw_record_id=stations.source_rows[item.value], historical_applicability="UNKNOWN")
    kwargs = dict(filename=filename, officer_uid=officer, raw_record_id=raw["raw_record_id"])
    cipher, version = seal_history_plan(crypto, plan, reference_evidence=references, raw_record_id=raw["raw_record_id"])
    payload = open_history_plan(crypto, cipher, key_version=version, **kwargs)
    if open_history_plan(backup, cipher, key_version=version, **kwargs) != payload:
        raise ValueError("Historical plan backup differs.")
    payload = check_payload(payload)
    fingerprint, _ = crypto.lookup_hmac(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                                       identifier_type="PF_HISTORY_PREFLIGHT_V1")
    binding = HistorySourceBinding(raw["raw_record_id"], UUID(identifiers[0]["identifier_version_id"]),
                                   args.expected_confirmation_sha256, revision)
    return payload, binding, fingerprint, row["transfer_id" if filename == "transfer_history.csv" else "promotion_id"].strip()


def saved_state(connection, collection, *, crypto, backup, binding, payload):
    """Read-only classification of delivery progress, never a repair operation."""
    if collection.name != collection_for(payload):
        raise ValueError("Wrong historical Mongo destination during state inspection.")
    saved = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                PREP.c.writer_policy == COLLECTION_POLICIES[collection_for(payload)])).mappings().one_or_none()
    if saved is None:
        if collection.find_one({"raw_record_id": binding.raw_record_id, "writer_policy": COLLECTION_POLICIES[collection_for(payload)]}) is not None:
            raise ValueError("Mongo historical evidence has no SQL preparation.")
        return "PLANNED", None
    prepared = assert_saved(connection, saved, crypto, backup, binding, payload)
    document = prepared.document()
    receipt = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(document["_id"]))).scalar_one_or_none()
    if receipt is not None and receipt != prepared.document_sha256:
        raise ValueError("Historical completion digest differs.")
    exists = verify_mongo(collection, document)
    if receipt is not None and not exists:
        raise ValueError("Completed historical evidence is missing; integrity review required.")
    return ("VERIFIED_EXISTING" if receipt is not None else "PENDING_RECEIPT" if exists else "PENDING_MONGO"), prepared


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "history-credential-directory", "attempt-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-transfer-rows", required=True, type=int)
    parser.add_argument("--expected-promotion-rows", required=True, type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args()
    # This first import is intentionally pinned to the already reviewed batch.
    if (args.batch_id, args.expected_archive_sha256, args.expected_confirmation_sha256, args.expected_transfer_rows, args.expected_promotion_rows) != (BATCH, ARCHIVE, CONFIRMATION, 33316, 13974):
        parser.error("Expected reviewed BATCH-RAW-001 fingerprints, 33316 transfer rows and 13974 promotion rows.")
    return args


def validate_batch_totals(file_rows, review_rows, observations):
    if dict(file_rows) != EXPECTED_ROWS:
        raise ValueError("Historical batch coverage differs.")
    if dict(review_rows) != {"promotion_history.csv": 0, "transfer_history.csv": 30}:
        raise ValueError("Historical review counts differ from the inspected checkpoint.")
    if dict(observations) != {"SOURCE_REPORTS_CANCELLED_TRANSFER_PRESERVE_ORIGINAL": 118}:
        raise ValueError("Historical cancellation/chronology observations differ from the checkpoint.")


def main():
    args = arguments()
    engine = mongo = journal = pending = None
    sequence = 0
    outcomes = Counter()
    try:
        repository = Path(__file__).resolve().parents[3]
        def git(*parts):
            return subprocess.check_output(["git", "-C", str(repository), *parts], text=True).strip()
        if git("status", "--porcelain"):
            raise ValueError("Commit reviewed source before running this workflow.")
        revision = git("rev-parse", "HEAD")
        if re.fullmatch("[0-9a-f]{40}", revision) is None:
            raise ValueError("Unsupported code revision format.")
        if args.key_file.resolve() == args.backup_key_file.resolve():
            raise ValueError("Use separate primary and backup key files.")
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        validate_history_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        password = history_password(args.history_credential_directory)
        mongo = history_client(password)
        collections = {name: mongo[DATABASE][name] for name in COLLECTION_POLICIES}
        selection, snapshots = [], {}
        statuses, warnings = Counter(), Counter()
        file_rows, review_rows, observations = Counter(), Counter(), Counter()
        source_ids = {filename: set() for filename in ROUTES}
        file_contracts = {}
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                if tuple(connection.execute(text("SELECT current_user, current_database()")).one()) != ("police_identity_app", "police_identity"):
                    raise ValueError("Unexpected connected SQL target.")
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == args.batch_id)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == args.batch_id)).mappings().all()
                names = {PurePosixPath(f["archive_path"]).name for f in files}
                if batch["archive_sha256"] != args.expected_archive_sha256 or len(files) != batch["expected_file_count"] or len(names) != len(files):
                    raise ValueError("Registered archive/file membership differs.")
                confirmation = load_source_confirmation(args.confirmation, expected_batch_id=args.batch_id,
                    expected_archive_sha256=args.expected_archive_sha256, expected_filenames=names,
                    allowed_source_codes={"PF_REGISTRY", "POLICE_HR_IS", "SRB"})
                if confirmation.confirmation_sha256 != args.expected_confirmation_sha256:
                    raise ValueError("Historical source confirmation differs.")
                stations, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=args.batch_id)
                for filename in ROUTES:
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "PF_REGISTRY":
                        raise ValueError("Historical supplying source/file differs.")
                    file = selected[0]
                    if file["expected_row_count"] != EXPECTED_ROWS[filename] or tuple(file["columns"]) != HEADERS[filename]:
                        raise ValueError("Historical registered count/header differs.")
                    file_contracts[filename] = file
                    collection = collections["transfer_events" if filename == "transfer_history.csv" else "promotion_events"]
                    rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)).mappings()
                    for number, raw in enumerate(rows, 1):
                        if raw["source_row_number"] != number:
                            raise ValueError("Historical row sequence has a gap.")
                        payload, binding, fingerprint, source_id = history_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision)
                        if not source_id or source_id in source_ids[filename]:
                            raise ValueError("Repeated or empty historical source identifier requires review.")
                        # Repeated officer rows are legitimate history, not duplicates.
                        source_ids[filename].add(source_id)
                        state, _ = saved_state(connection, collection, crypto=crypto, backup=backup, binding=binding, payload=payload)
                        if args.reconcile and state != "VERIFIED_EXISTING":
                            raise ValueError("Reconciliation found incomplete historical delivery.")
                        selection.append((filename, raw["raw_record_id"], number))
                        snapshots[raw["raw_record_id"]] = (payload["officer_uid"], binding.identifier_version_id, fingerprint)
                        statuses[filename + ":" + state] += 1
                        file_rows[filename] += 1
                        review_rows[filename] += payload["needs_review"]
                        observations.update(payload["observations"])
                        for item in payload["fields"]:
                            for issue in item["issues"]:
                                warnings[filename + ":" + item["source_column"] + ":" + issue] += 1
                        for issue in payload["uncertainties"]:
                            warnings[filename + ":" + issue] += 1
                    if file_rows[filename] != EXPECTED_ROWS[filename]:
                        raise ValueError("Historical source row coverage differs.")
                    selected_ids = {raw_id for name, raw_id, _ in selection if name == filename}
                    policy = COLLECTION_POLICIES[collection.name]
                    preparations = {str(p["delivery_id"]): p for p in connection.execute(
                        select(PREP.c.delivery_id, PREP.c.raw_record_id, PREP.c.source_assertion_id)
                        .where(PREP.c.writer_policy == policy)).mappings()}
                    if any(p["raw_record_id"] not in selected_ids for p in preparations.values()):
                        raise ValueError("Unexpected SQL historical preparation outside the reviewed batch.")
                    for stored in collection.find({}, {"_id": 1, "raw_record_id": 1, "writer_policy": 1, "source_assertion_uid": 1}):
                        p = preparations.get(stored.get("_id"))
                        if p is None or (stored.get("raw_record_id"), stored.get("writer_policy"), stored.get("source_assertion_uid")) != (
                            p["raw_record_id"], policy, str(p["source_assertion_id"])):
                            raise ValueError("Unexpected or orphan Mongo historical evidence.")
                validate_batch_totals(file_rows, review_rows, observations)
                # Every historical assertion must have its atomic SQL preparation.
                assertion_ids = set(connection.execute(select(SourceAssertion.source_assertion_id).where(
                    SourceAssertion.assertion_type.in_(["PF_TRANSFER_EVIDENCE", "PF_PROMOTION_EVIDENCE"]))).scalars())
                prepared_assertions = set(connection.execute(select(PREP.c.source_assertion_id)).scalars())
                if assertion_ids != prepared_assertions:
                    raise ValueError("Orphan or unexpected historical source assertion.")
        # No personnel plaintext leaves preflight; fingerprints are keyed HMACs.
        root = args.attempt_root.expanduser().absolute()
        if root.resolve().is_relative_to(repository) or any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("Keep private attempts outside Git and without symlink paths.")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.stat().st_mode & 0o077:
            raise ValueError("Attempt root must be owner-only.")
        journal = root / str(uuid4())
        journal.mkdir(mode=0o700)
        metadata = dict(batch_id=args.batch_id, policy_versions=dict(COLLECTION_POLICIES), code_revision=revision,
                        archive_sha256=args.expected_archive_sha256, confirmation_sha256=args.expected_confirmation_sha256,
                        mode="WRITE" if args.write else "RECONCILE" if args.reconcile else "VALIDATION",
                        actor_context="LOCAL_DEVELOPMENT_INTAKE_SESSION")
        def event(kind, **extra):
            nonlocal sequence
            sequence += 1
            save_receipt(dict(metadata, sequence=sequence, event=kind, **extra), journal / f"{sequence:08d}.json")
        event("PREFLIGHT_PASSED", rows=len(selection), source_rows=dict(file_rows), review_rows=dict(review_rows), observations=dict(observations), delivery_states=dict(statuses), warnings=dict(warnings))
        print("Attempt directory:", journal, flush=True)
        print("Validated historical rows:", len(selection), "| sources:", dict(file_rows), flush=True)
        print("Rows retaining field review:", dict(review_rows), flush=True)
        print("Cancellation/chronology observations:", dict(observations), flush=True)
        print("Delivery states before execution:", dict(statuses), flush=True)
        print("Warnings:", dict(sorted(warnings.items())), flush=True)
        if args.write:
            for progress, (filename, raw_id, number) in enumerate(selection, 1):
                file = file_contracts[filename]
                collection = collections["transfer_events" if filename == "transfer_history.csv" else "promotion_events"]
                pending = raw_id
                event("ROW_STARTED", filename=filename, raw_record_id=raw_id, source_row_number=number)
                with engine.connect() as connection:
                    with connection.begin():
                        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                        raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_id)).mappings().one()
                        payload, binding, fingerprint, _ = history_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision)
                        expected = snapshots[raw_id]
                        if expected[:2] != (payload["officer_uid"], binding.identifier_version_id) or not hmac.compare_digest(expected[2], fingerprint):
                            raise ValueError("Source or linkage changed after preflight.")
                proposed = make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
                ledger = SqlHistoryLedger(engine, crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                status = deliver(ledger, collection, proposed, crypto=crypto, backup=backup, expected_payload=payload)
                outcomes[filename + ":" + status] += 1
                event("ROW_COMPLETED", filename=filename, raw_record_id=raw_id, source_row_number=number, status=status)
                pending = None
                if progress % 500 == 0 or progress == len(selection):
                    print("Historical progress:", progress, "/", len(selection), flush=True)
        else:
            outcomes.update(statuses)
        event("COMPLETED", rows=len(selection), outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("Historical workflow: PASSED")
        print("Classification remains UNASSESSED; historical eligibility, authority, cancellation effect and valid periods remain unassessed.")
        print("No user disclosure or verified-current-state claim.")
        if not args.write:
            print("No database writes; private attempt journal saved without personnel values.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if journal is not None:
            try:
                sequence += 1
                save_receipt(dict(sequence=sequence, event="STOPPED", error_type=type(error).__name__, pending_raw_record_id=pending,
                                  outcomes=dict(outcomes)), journal / f"{sequence:08d}.json")
            except Exception:
                print("Stop-event persistence failed; inspect the existing attempt directory.")
        print("Historical workflow stopped:", type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print("Committed evidence remains saved. Retry verifies preparation, Mongo document and completion; no deletion.")
        return 1
    finally:
        if mongo is not None:
            mongo.close()
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
