"""Local development intake: validate, deliver or reconcile HR service evidence.

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
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION, FILENAME, verified_nic_evidence
from app.identity.normalization import normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.service_delivery import WRITER_POLICY, check_payload, deliver, make_delivery, reconcile, verify_mongo
from app.identity.service_plan import ROUTES, plan_service, validate_service_routing
from app.identity.service_plan_crypto import open_service_plan, seal_service_plan
from app.identity.service_sql_ledger import DONE, PREP, ServiceSourceBinding, SqlDeliveryLedger, assert_saved
from app.identity.station_reference import load_staged_station_index
from app.intake.registration_receipt import save_receipt
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import COLLECTION, DATABASE


class DurableSqlLedger(SqlDeliveryLedger):
    """Independently recover each SQL fact through a fresh connection after commit."""

    def prepare_once(self, proposed):
        result = super().prepare_once(proposed)
        with self.engine.connect() as connection:
            saved = connection.execute(select(PREP).where(PREP.c.delivery_id == UUID(result.document()["_id"]))).mappings().one()
            recovered = assert_saved(connection, saved, self.crypto, self.backup, self.binding, self.expected)
        if recovered != result:
            raise ValueError("Committed SQL preparation recovery differs.")
        return result

    def complete_once(self, prepared):
        result = super().complete_once(prepared)
        if self.completion_digest(prepared.document()["_id"]) != result:
            raise ValueError("Committed SQL completion recovery differs.")
        return result


def service_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision):
    """Replan from encrypted originals with exact NIC and source-scoped station evidence."""
    if any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("Service source/file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
        raise ValueError("Service header or backup recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    identifier = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    candidates = find_identifier_candidates(connection, crypto, identifier)
    if candidates.status != "SINGLE_CANDIDATE" or len(candidates.officer_uids) != 1:
        raise ValueError("Service officer linkage is unresolved or ambiguous.")
    officer = candidates.officer_uids[0]
    identifiers = sorted(verified_nic_evidence(connection, crypto, backup, identifier, candidates), key=lambda ref: ref["identifier_version_id"])
    if not identifiers:
        raise ValueError("No usable exact encrypted NIC evidence.")
    plan = plan_service(row, officer_uid=officer, station_candidates=stations.candidates)
    references = dict(service_source=dict(batch_id=raw["batch_id"], raw_record_id=raw["raw_record_id"],
        import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        reported_source_system_code="POLICE_HR_IS", confirmation_sha256=args.expected_confirmation_sha256),
        identifier_evidence=identifiers, station_source=station_provenance, station_matches={})
    for item in plan.fields:
        if item.source_column in {"first_posted_police_station_code", "current_station_code"} and item.status == "PARSED":
            references["station_matches"][item.source_column] = dict(station_code=item.value,
                raw_record_id=stations.source_rows[item.value], historical_applicability="UNKNOWN")
    kwargs = dict(officer_uid=officer, raw_record_id=raw["raw_record_id"])
    cipher, version = seal_service_plan(crypto, plan, reference_evidence=references, **kwargs)
    payload = open_service_plan(crypto, cipher, key_version=version, **kwargs)
    if open_service_plan(backup, cipher, key_version=version, **kwargs) != payload:
        raise ValueError("Service plan backup differs.")
    payload = check_payload(payload)
    fingerprint, _ = crypto.lookup_hmac(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                                       identifier_type="HR_SERVICE_PREFLIGHT_V1")
    binding = ServiceSourceBinding(raw["raw_record_id"], UUID(identifiers[0]["identifier_version_id"]),
                                   args.expected_confirmation_sha256, revision)
    return payload, binding, fingerprint, row["service_id"].strip()


def saved_state(connection, collection, *, crypto, backup, binding, payload):
    """Read-only classification of delivery progress, never a repair operation."""
    saved = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                PREP.c.writer_policy == WRITER_POLICY)).mappings().one_or_none()
    if saved is None:
        if collection.find_one({"raw_record_id": binding.raw_record_id, "writer_policy": WRITER_POLICY}) is not None:
            raise ValueError("Mongo service evidence has no SQL preparation.")
        return "PLANNED", None
    prepared = assert_saved(connection, saved, crypto, backup, binding, payload)
    document = prepared.document()
    receipt = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(document["_id"]))).scalar_one_or_none()
    if receipt is not None and receipt != prepared.document_sha256:
        raise ValueError("Service completion digest differs.")
    exists = verify_mongo(collection, document)
    if receipt is not None and not exists:
        raise ValueError("Completed service evidence is missing; integrity review required.")
    return ("VERIFIED_EXISTING" if receipt is not None else "PENDING_RECEIPT" if exists else "PENDING_MONGO"), prepared


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "mongo-credential-directory", "attempt-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-rows", required=True, type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args()
    # This first import is intentionally pinned to the already reviewed batch.
    if (args.batch_id, args.expected_archive_sha256, args.expected_confirmation_sha256, args.expected_rows) != (BATCH, ARCHIVE, CONFIRMATION, 6596):
        parser.error("Expected the reviewed BATCH-RAW-001 fingerprints and 6596 service rows.")
    return args


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
        validate_service_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        _, password = load_credentials(args.mongo_credential_directory)
        mongo = client(password)
        collection = mongo[DATABASE][COLLECTION]
        selection, snapshots = [], {}
        statuses, warnings = Counter(), Counter()
        officers, source_ids = set(), set()
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
                if confirmation.confirmation_sha256 != args.expected_confirmation_sha256 or confirmation.source_for(FILENAME) != "POLICE_HR_IS":
                    raise ValueError("Service source confirmation differs.")
                selected = [f for f in files if PurePosixPath(f["archive_path"]).name == FILENAME]
                if len(selected) != 1:
                    raise ValueError("Expected one registered service file.")
                file = selected[0]
                if file["expected_row_count"] != args.expected_rows or len(file["columns"]) != len(ROUTES) or set(file["columns"]) != set(ROUTES):
                    raise ValueError("Service count or exact header contract differs.")
                stations, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=args.batch_id)
                rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)).mappings()
                for number, raw in enumerate(rows, 1):
                    if raw["source_row_number"] != number:
                        raise ValueError("Service row sequence has a gap.")
                    payload, binding, fingerprint, service_id = service_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision)
                    officer = payload["officer_uid"]
                    if officer in officers or service_id in source_ids:
                        raise ValueError("Repeated officer or source service identifier requires review.")
                    officers.add(officer); source_ids.add(service_id)
                    state, _ = saved_state(connection, collection, crypto=crypto, backup=backup, binding=binding, payload=payload)
                    if args.reconcile and state != "VERIFIED_EXISTING":
                        raise ValueError("Reconciliation found incomplete service delivery.")
                    selection.append((raw["raw_record_id"], number))
                    snapshots[raw["raw_record_id"]] = (officer, binding.identifier_version_id, fingerprint)
                    statuses[state] += 1
                    for item in payload["fields"]:
                        for issue in item["issues"]:
                            warnings[item["source_column"] + ":" + issue] += 1
                    for issue in payload["uncertainties"]:
                        warnings[issue] += 1
                if len(selection) != args.expected_rows:
                    raise ValueError("Service row coverage differs.")
                # This first-batch CLI must not ignore orphan or unexpected
                # Mongo documents simply because they are outside row queries.
                selected_ids = {raw_id for raw_id, _ in selection}
                preparations = {str(p["delivery_id"]): p for p in connection.execute(
                    select(PREP.c.delivery_id, PREP.c.raw_record_id, PREP.c.source_assertion_id)
                    .where(PREP.c.writer_policy == WRITER_POLICY)).mappings()}
                if any(p["raw_record_id"] not in selected_ids for p in preparations.values()):
                    raise ValueError("Unexpected SQL service preparation outside this reviewed batch.")
                for stored in collection.find({}, {"_id": 1, "raw_record_id": 1, "writer_policy": 1, "source_assertion_uid": 1}):
                    p = preparations.get(stored.get("_id"))
                    if p is None or (stored.get("raw_record_id"), stored.get("writer_policy"), stored.get("source_assertion_uid")) != (
                        p["raw_record_id"], WRITER_POLICY, str(p["source_assertion_id"])):
                        raise ValueError("Unexpected or orphan Mongo service evidence.")
        # No personnel plaintext leaves preflight; fingerprints are keyed HMACs.
        root = args.attempt_root.expanduser().absolute()
        if root.resolve().is_relative_to(repository) or any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("Keep private attempts outside Git and without symlink paths.")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.stat().st_mode & 0o077:
            raise ValueError("Attempt root must be owner-only.")
        journal = root / str(uuid4())
        journal.mkdir(mode=0o700)
        metadata = dict(batch_id=args.batch_id, policy_version=WRITER_POLICY, code_revision=revision,
                        archive_sha256=args.expected_archive_sha256, confirmation_sha256=args.expected_confirmation_sha256,
                        mode="WRITE" if args.write else "RECONCILE" if args.reconcile else "VALIDATION",
                        actor_context="LOCAL_DEVELOPMENT_INTAKE_SESSION")
        def event(kind, **extra):
            nonlocal sequence
            sequence += 1
            save_receipt(dict(metadata, sequence=sequence, event=kind, **extra), journal / f"{sequence:08d}.json")
        event("PREFLIGHT_PASSED", rows=len(selection), delivery_states=dict(statuses), warnings=dict(warnings))
        print("Attempt directory:", journal, flush=True)
        print("Validated service rows:", len(selection), flush=True)
        print("Delivery states before execution:", dict(statuses), flush=True)
        print("Warnings:", dict(sorted(warnings.items())), flush=True)
        if args.write:
            for raw_id, number in selection:
                pending = raw_id
                event("ROW_STARTED", raw_record_id=raw_id, source_row_number=number)
                with engine.connect() as connection:
                    with connection.begin():
                        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                        raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_id)).mappings().one()
                        payload, binding, fingerprint, _ = service_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision)
                        expected = snapshots[raw_id]
                        if expected[:2] != (payload["officer_uid"], binding.identifier_version_id) or not hmac.compare_digest(expected[2], fingerprint):
                            raise ValueError("Source or linkage changed after preflight.")
                proposed = make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
                ledger = DurableSqlLedger(engine, crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                status = deliver(ledger, collection, proposed, crypto=crypto, backup=backup, expected_payload=payload)
                outcomes[status] += 1
                event("ROW_COMPLETED", raw_record_id=raw_id, source_row_number=number, status=status)
                pending = None
                if number % 500 == 0 or number == len(selection):
                    print("Service progress:", number, "/", len(selection), flush=True)
        else:
            outcomes.update(statuses)
        event("COMPLETED", rows=len(selection), outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("Service workflow: PASSED")
        print("Classification remains UNASSESSED; historical eligibility and snapshot applicability remain unknown.")
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
        print("Service workflow stopped:", type(error).__name__)
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
