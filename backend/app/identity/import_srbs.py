"""Local development intake: validate, deliver or reconcile SRB evidence.

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
from app.identity.inspect_srb_sources import HEADERS, SOURCE_KEYS
from app.identity.inspect_srb_plans import EXPECTED_ROWS
from app.identity.inspect_history_sources import HEADERS as HISTORY_HEADERS, inspected_link
from app.identity.srb_plan import ACTORS, SourceReference, bounded_intersection_count
from datetime import date
from app.identity.normalization import normalize_identifier
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.srb_delivery import check_payload, deliver, make_delivery, verify_mongo, collection_for
from app.identity.srb_plan import ROUTES, plan_srb, validate_srb_routing
from app.identity.srb_plan_crypto import open_srb_plan, seal_srb_plan
from app.identity.srb_sql_ledger import DONE, PREP, SrbSourceBinding, SqlSrbLedger, assert_saved
from app.identity.station_reference import load_staged_station_index
from app.intake.registration_receipt import save_receipt
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.storage.srb_mongo_connection import srb_client, srb_password
from app.storage.srb_mongo_contract import COLLECTION_POLICIES, DATABASE
from app.models import SourceAssertion


def reference_indexes(connection, crypto, backup, files, confirmation):
    """Recover complete source snapshots before accepting actor and override links."""
    actor_cache = {}
    def recovered_rows(filename, expected_source, header, count):
        # Recheck file/row provenance before building any in-memory link index.
        selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
        if len(selected) != 1 or confirmation.source_for(filename) != expected_source:
            raise ValueError("Reference source contract differs.")
        file = selected[0]
        if tuple(file["columns"]) != header or file["expected_row_count"] != count:
            raise ValueError("Reference header/count differs.")
        query = select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)
        total = 0
        for number, raw in enumerate(connection.execute(query).mappings(), 1):
            if raw["source_row_number"] != number or any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
                raise ValueError("Reference row provenance differs.")
            original = open_row(crypto, stored_row(raw))
            if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
                raise ValueError("Reference backup/header recovery differs.")
            total += 1
            yield raw, dict(zip(original["columns"], original["values"], strict=True))
        if total != count:
            raise ValueError("Reference row coverage differs.")

    # Match source-qualified IDs and subject candidates, not inferred authority.
    reference_index = {"restriction_id": {}, "transfer_id": {}}
    for filename, source, key, header, count in (
        ("officer_restrictions.csv", "SRB", "restriction_id", HEADERS["officer_restrictions.csv"], 10971),
        ("transfer_history.csv", "PF_REGISTRY", "transfer_id", HISTORY_HEADERS["transfer_history.csv"], 33316),
    ):
        for raw, row in recovered_rows(filename, source, header, count):
            state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], actor_cache)
            if state != "EXACT_EVIDENCE_CANDIDATE":
                raise ValueError("Reference subject candidate requires review.")
            key_value = row[key].strip()
            if key_value:
                reference_index[key].setdefault(key_value, []).append(SourceReference(filename, raw["raw_record_id"], officer))
    override_subject_index = {}
    for raw, row in recovered_rows("restriction_overrides.csv", "SRB", HEADERS["restriction_overrides.csv"], 150):
        state, officer = inspected_link(connection, crypto, backup, row["officer_nic_no"], actor_cache)
        if state != "EXACT_EVIDENCE_CANDIDATE":
            raise ValueError("Override subject candidate requires review.")
        key = row["restriction_id"].strip()
        if key:
            override_subject_index.setdefault(key, []).append(officer)
    return reference_index, override_subject_index, actor_cache


def srb_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision,
                reference_index, override_subject_index, actor_cache):
    """Recover originals and preserve source-scoped references without approving effects."""
    if any(raw[f] != file[f] for f in ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("SRB source/file binding differs.")
    original = open_row(crypto, stored_row(raw))
    if original != open_row(backup, stored_row(raw)) or original["columns"] != file["columns"]:
        raise ValueError("SRB header or backup recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    nic = normalize_identifier(row["officer_nic_no"], identifier_type="NIC")
    candidates = find_identifier_candidates(connection, crypto, nic)
    if candidates.status != "SINGLE_CANDIDATE" or len(candidates.officer_uids) != 1:
        raise ValueError("SRB subject linkage requires review.")
    officer = candidates.officer_uids[0]
    identifier_refs = sorted(verified_nic_evidence(connection, crypto, backup, nic, candidates),
                             key=lambda ref: ref["identifier_version_id"])
    if not identifier_refs:
        raise ValueError("No usable exact encrypted NIC evidence.")
    filename = PurePosixPath(file["archive_path"]).name
    actor_candidates, actor_evidence = {}, {}
    for name in ACTORS & row.keys():
        if row[name].strip():
            state, candidate = inspected_link(connection, crypto, backup, row[name], actor_cache)
            actor_evidence[name] = dict(candidate_state=state, officer_uid=str(candidate) if candidate else None)
            if state == "EXACT_EVIDENCE_CANDIDATE":
                actor_candidates[name] = candidate
    reference_candidates = {key: tuple(reference_index[key].get(row[key].strip(), ()))
        for key in ("restriction_id", "transfer_id") if filename == "restriction_overrides.csv"}
    plan = plan_srb(filename, row, officer_uid=officer, station_candidates=stations.candidates,
        actor_candidates=actor_candidates, reference_candidates=reference_candidates,
        linked_override_subjects=override_subject_index.get(row["restriction_id"].strip(), ()) if filename == "officer_restrictions.csv" else None)
    references = dict(srb_source=dict(batch_id=BATCH, raw_record_id=raw["raw_record_id"],
        import_file_id=str(raw["import_file_id"]), source_file_sha256=raw["source_file_sha256"], source_row_number=raw["source_row_number"],
        reported_source_system_code="SRB", confirmation_sha256=CONFIRMATION),
        identifier_evidence=identifier_refs, actor_candidates=actor_evidence,
        source_reference_candidates={key: [dict(filename=r.filename, raw_record_id=r.raw_record_id, officer_uid=str(r.officer_uid)) for r in refs] for key, refs in reference_candidates.items()},
        station_source=station_provenance, station_matches={})
    for item in plan.fields:
        if item.source_column in {"restricted_station_code"} and item.status == "PARSED":
            references["station_matches"][item.source_column] = dict(station_code=item.value,
                raw_record_id=stations.source_rows[item.value], historical_applicability="UNKNOWN")
    cipher, version = seal_srb_plan(crypto, plan, raw_record_id=raw["raw_record_id"], reference_evidence=references)
    opening = dict(key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw["raw_record_id"])
    primary = open_srb_plan(crypto, cipher, **opening)
    if open_srb_plan(backup, cipher, **opening) != primary:
        raise ValueError("SRB encrypted plan backup differs.")
    # check_payload refuses all structural issues; semantic unknowns remain preserved.
    payload = check_payload(primary)
    fingerprint, _ = crypto.lookup_hmac(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                                       identifier_type="SRB_PREFLIGHT_V1")
    binding = SrbSourceBinding(raw["raw_record_id"], UUID(identifier_refs[0]["identifier_version_id"]),
                               args.expected_confirmation_sha256, revision)
    return payload, binding, fingerprint, row[SOURCE_KEYS[filename]].strip()


def saved_state(connection, collection, *, crypto, backup, binding, payload):
    """Read-only classification of delivery progress, never a repair operation."""
    if collection.name != collection_for(payload):
        raise ValueError("Wrong SRB Mongo destination during state inspection.")
    saved = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                PREP.c.writer_policy == COLLECTION_POLICIES[collection_for(payload)])).mappings().one_or_none()
    if saved is None:
        if collection.find_one({"raw_record_id": binding.raw_record_id, "writer_policy": COLLECTION_POLICIES[collection_for(payload)]}) is not None:
            raise ValueError("Mongo SRB evidence has no SQL preparation.")
        return "PLANNED", None
    prepared = assert_saved(connection, saved, crypto, backup, binding, payload)
    document = prepared.document()
    receipt = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(document["_id"]))).scalar_one_or_none()
    if receipt is not None and receipt != prepared.document_sha256:
        raise ValueError("SRB completion digest differs.")
    exists = verify_mongo(collection, document)
    if receipt is not None and not exists:
        raise ValueError("Completed SRB evidence is missing; integrity review required.")
    return ("VERIFIED_EXISTING" if receipt is not None else "PENDING_RECEIPT" if exists else "PENDING_MONGO"), prepared


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "srb-credential-directory", "attempt-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("expected-number-rows", "expected-restriction-rows", "expected-override-rows"):
        parser.add_argument("--" + name, required=True, type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args()
    # This first import is intentionally pinned to the already reviewed batch.
    if (args.batch_id, args.expected_archive_sha256, args.expected_confirmation_sha256, args.expected_number_rows, args.expected_restriction_rows, args.expected_override_rows) != (BATCH, ARCHIVE, CONFIRMATION, 15123, 10971, 150):
        parser.error("Expected reviewed BATCH-RAW-001 fingerprints, 15123 number rows, 10971 restrictions and 150 overrides.")
    return args


def validate_batch_totals(file_rows, review_rows, observations):
    if dict(file_rows) != EXPECTED_ROWS:
        raise ValueError("SRB batch coverage differs.")
    if dict(review_rows) != {filename: 0 for filename in ROUTES}:
        raise ValueError("SRB review counts differ from the inspected checkpoint.")
    if dict(observations) != {"MISSING_END_NOT_EXPLICIT_OPEN_INTERVAL": 10774, "MISSING_REMOVAL_NOT_PROOF_OF_ACTIVE_RESTRICTION": 10137, "OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED": 150}:
        raise ValueError("SRB source consistency observations differ from the checkpoint.")


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
        validate_srb_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        password = srb_password(args.srb_credential_directory)
        mongo = srb_client(password)
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
                    raise ValueError("SRB source confirmation differs.")
                stations, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=args.batch_id)
                reference_index, override_subject_index, actor_cache = reference_indexes(connection, crypto, backup, files, confirmation)
                bounded_numbers = {}
                for filename in ROUTES:
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "SRB":
                        raise ValueError("SRB supplying source/file differs.")
                    file = selected[0]
                    if file["expected_row_count"] != EXPECTED_ROWS[filename] or tuple(file["columns"]) != HEADERS[filename]:
                        raise ValueError("SRB registered count/header differs.")
                    file_contracts[filename] = file
                    collection = collections[collection_for({"filename": filename})]
                    rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)).mappings()
                    for number, raw in enumerate(rows, 1):
                        if raw["source_row_number"] != number:
                            raise ValueError("SRB row sequence has a gap.")
                        payload, binding, fingerprint, source_id = srb_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision, reference_index, override_subject_index, actor_cache)
                        if not source_id or source_id in source_ids[filename]:
                            raise ValueError("Repeated or empty SRB source identifier requires review.")
                        # Repeated officer rows are legitimate history, not duplicates.
                        source_ids[filename].add(source_id)
                        state, _ = saved_state(connection, collection, crypto=crypto, backup=backup, binding=binding, payload=payload)
                        if args.reconcile and state != "VERIFIED_EXISTING":
                            raise ValueError("Reconciliation found incomplete SRB delivery.")
                        selection.append((filename, raw["raw_record_id"], number))
                        snapshots[raw["raw_record_id"]] = (payload["officer_uid"], binding.identifier_version_id, fingerprint)
                        statuses[filename + ":" + state] += 1
                        file_rows[filename] += 1
                        review_rows[filename] += payload["needs_review"]
                        observations.update(payload["observations"])
                        if filename == "officer_police_numbers.csv":
                            values = {item["source_column"]: item["value"] for item in payload["fields"]}
                            start, end = values["valid_from"], values["valid_to"]
                            if isinstance(start, dict) and isinstance(end, dict):
                                first, last = date.fromisoformat(start["value"]), date.fromisoformat(end["value"])
                                if last > first:
                                    bounded_numbers.setdefault((payload["officer_uid"], values["number_type"]), []).append((first, last))
                        for item in payload["fields"]:
                            for issue in item["issues"]:
                                warnings[filename + ":" + item["source_column"] + ":" + issue] += 1
                        for issue in payload["uncertainties"]:
                            warnings[filename + ":" + issue] += 1
                    if file_rows[filename] != EXPECTED_ROWS[filename]:
                        raise ValueError("SRB source row coverage differs.")
                    selected_ids = {raw_id for name, raw_id, _ in selection if name == filename}
                    policy = COLLECTION_POLICIES[collection.name]
                    preparations = {str(p["delivery_id"]): p for p in connection.execute(
                        select(PREP.c.delivery_id, PREP.c.raw_record_id, PREP.c.source_assertion_id)
                        .where(PREP.c.writer_policy == policy)).mappings()}
                    if any(p["raw_record_id"] not in selected_ids for p in preparations.values()):
                        raise ValueError("Unexpected SQL SRB preparation outside the reviewed batch.")
                    for stored in collection.find({}, {"_id": 1, "raw_record_id": 1, "writer_policy": 1, "source_assertion_uid": 1}):
                        p = preparations.get(stored.get("_id"))
                        if p is None or (stored.get("raw_record_id"), stored.get("writer_policy"), stored.get("source_assertion_uid")) != (
                            p["raw_record_id"], policy, str(p["source_assertion_id"])):
                            raise ValueError("Unexpected or orphan Mongo SRB evidence.")
                # Compare only explicit bounded reports; never turn missing ends into infinity.
                for periods in bounded_numbers.values():
                    intersections = bounded_intersection_count(periods)
                    if intersections:
                        observations["REPORTED_BOUNDED_NUMBER_PERIOD_INTERSECTION"] += intersections
                validate_batch_totals(file_rows, review_rows, observations)
                # Every SRB assertion must have its atomic SQL preparation.
                assertion_ids = set(connection.execute(select(SourceAssertion.source_assertion_id).where(
                    SourceAssertion.assertion_type.in_(["SRB_POLICE_NUMBER_EVIDENCE", "SRB_RESTRICTION_EVIDENCE", "SRB_OVERRIDE_EVIDENCE"]))).scalars())
                prepared_assertions = set(connection.execute(select(PREP.c.source_assertion_id)).scalars())
                if assertion_ids != prepared_assertions:
                    raise ValueError("Orphan or unexpected SRB source assertion.")
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
        print("Validated SRB rows:", len(selection), "| sources:", dict(file_rows), flush=True)
        print("Rows retaining field review:", dict(review_rows), flush=True)
        print("Source consistency observations:", dict(observations), flush=True)
        print("Delivery states before execution:", dict(statuses), flush=True)
        print("Warnings:", dict(sorted(warnings.items())), flush=True)
        if args.write:
            for progress, (filename, raw_id, number) in enumerate(selection, 1):
                file = file_contracts[filename]
                collection = collections[collection_for({"filename": filename})]
                pending = raw_id
                event("ROW_STARTED", filename=filename, raw_record_id=raw_id, source_row_number=number)
                with engine.connect() as connection:
                    with connection.begin():
                        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                        raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_id)).mappings().one()
                        # Immutable staging and NIC evidence were validated in full preflight;
                        # referenced rows/actors are independently rechecked by SqlSrbLedger.
                        payload, binding, fingerprint, _ = srb_payload(connection, crypto, backup, raw, file, stations, station_provenance, args, revision, reference_index, override_subject_index, actor_cache)
                        expected = snapshots[raw_id]
                        if expected[:2] != (payload["officer_uid"], binding.identifier_version_id) or not hmac.compare_digest(expected[2], fingerprint):
                            raise ValueError("Source or linkage changed after preflight.")
                proposed = make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
                ledger = SqlSrbLedger(engine, crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                status = deliver(ledger, collection, proposed, crypto=crypto, backup=backup, expected_payload=payload)
                outcomes[filename + ":" + status] += 1
                event("ROW_COMPLETED", filename=filename, raw_record_id=raw_id, source_row_number=number, status=status)
                pending = None
                if progress % 500 == 0 or progress == len(selection):
                    print("SRB progress:", progress, "/", len(selection), flush=True)
        else:
            outcomes.update(statuses)
        event("COMPLETED", rows=len(selection), outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("SRB workflow: PASSED")
        print("Classification remains UNASSESSED; SRB eligibility, authority, restriction/override effects and valid periods remain unassessed.")
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
        print("SRB workflow stopped:", type(error).__name__)
        print("Committed evidence remains saved. Retry verifies preparation, Mongo document and completion; no deletion.")
        return 1
    finally:
        if mongo is not None:
            mongo.close()
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
