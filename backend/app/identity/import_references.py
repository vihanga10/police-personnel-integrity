"""Guarded local station reference intake: validate, deliver or reconcile.

Default is read-only. Explicit --write imports encrypted source evidence only;
human authentication/authorization and accepted station mappings remain pending.
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
from app.identity.inspect_service_plans import ARCHIVE,BATCH,CONFIRMATION
from app.identity.register_profiles import private_key_file,verify_recovery
from app.identity.reference_delivery import check_payload,deliver,make_delivery,verify_mongo,collection_for
from app.identity.reference_plan import ReferenceCandidates,plan_reference,validate_routing
from app.identity.reference_plan_crypto import open_reference_plan,seal_reference_plan
from app.identity.reference_sql_ledger import DONE,PREP,ReferenceSourceBinding,SqlReferenceLedger,assert_saved,recovered_row,ASSERTION_TYPES
from app.identity.station_vocabulary import HEADERS,MASTER,SINHALA,MODES
from app.intake.registration_receipt import save_receipt
from app.intake.source_confirmation import load_source_confirmation
from app.staging.models import IntakeBatch,IntakeFile,RawRecord
from app.storage.reference_mongo_connection import reference_client,reference_password
from app.storage.reference_mongo_contract import COLLECTION_POLICIES,DATABASE
from app.models import ReferenceSourceAssertion

EXPECTED_ROWS={MASTER:607,SINHALA:607}
ROUTES=HEADERS


def master_snapshot(connection,crypto,backup,master):
    """Recover the entire registered master; do not accept its candidate links."""
    if master['expected_row_count']!=EXPECTED_ROWS[MASTER] or tuple(master['columns'])!=HEADERS[MASTER]:
        raise ValueError('Reference master count/header differs.')
    rows=connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id==master['import_file_id']).order_by(RawRecord.source_row_number)).mappings().all()
    if len(rows)!=EXPECTED_ROWS[MASTER] or [r['source_row_number'] for r in rows]!=list(range(1,len(rows)+1)):
        raise ValueError('Reference master row coverage differs.')
    return ReferenceCandidates([(r['raw_record_id'],recovered_row(crypto,backup,r,master,MASTER)) for r in rows])


def reference_payload(crypto,backup,raw,file,args,revision,master,candidates):
    """Bind exact original cells and candidate evidence to the reviewed snapshot."""
    filename=PurePosixPath(file['archive_path']).name
    row=recovered_row(crypto,backup,raw,file,filename)
    plan=plan_reference(filename,row,raw_record_id=raw['raw_record_id'],candidates=candidates)
    evidence=dict(batch_id=args.batch_id,archive_sha256=args.expected_archive_sha256,
        confirmation_sha256=args.expected_confirmation_sha256,source_system_code='POLICE_HR_IS',import_file_id=str(raw['import_file_id']),
        source_file_sha256=raw['source_file_sha256'],source_row_number=raw['source_row_number'],master_import_file_id=str(master['import_file_id']),
        master_file_sha256=master['source_file_sha256'],master_rows=master['expected_row_count'])
    cipher,version=seal_reference_plan(crypto,plan,evidence=evidence)
    opening=dict(key_version=version,filename=filename,raw_record_id=raw['raw_record_id'],evidence=evidence)
    payload=open_reference_plan(crypto,cipher,**opening)
    if open_reference_plan(backup,cipher,**opening)!=payload:raise ValueError('Reference plan backup differs.')
    payload=check_payload(payload)
    fingerprint,_=crypto.lookup_hmac(json.dumps(payload,sort_keys=True,ensure_ascii=False,separators=(',',':')),identifier_type='REFERENCE_PREFLIGHT_V1')
    binding=ReferenceSourceBinding(raw['raw_record_id'],master['import_file_id'],master['source_file_sha256'],master['expected_row_count'],args.expected_confirmation_sha256,revision)
    return payload,binding,fingerprint


def saved_state(connection, collection, *, crypto, backup, binding, payload):
    """Read-only classification of delivery progress, never a repair operation."""
    if collection.name != collection_for(payload):
        raise ValueError("Wrong reference Mongo destination during state inspection.")
    saved = connection.execute(select(PREP).where(PREP.c.raw_record_id == binding.raw_record_id,
                                                PREP.c.writer_policy == COLLECTION_POLICIES[collection_for(payload)])).mappings().one_or_none()
    if saved is None:
        if collection.find_one({"raw_record_id": binding.raw_record_id, "writer_policy": COLLECTION_POLICIES[collection_for(payload)]}) is not None:
            raise ValueError("Mongo reference evidence has no SQL preparation.")
        return "PLANNED", None
    prepared = assert_saved(connection, saved, crypto, backup, binding, payload)
    document = prepared.document()
    receipt = connection.execute(select(DONE.c.document_sha256).where(DONE.c.delivery_id == UUID(document["_id"]))).scalar_one_or_none()
    if receipt is not None and receipt != prepared.document_sha256:
        raise ValueError("Reference completion digest differs.")
    exists = verify_mongo(collection, document)
    if receipt is not None and not exists:
        raise ValueError("Completed reference evidence is missing; integrity review required.")
    return ("VERIFIED_EXISTING" if receipt is not None else "PENDING_RECEIPT" if exists else "PENDING_MONGO"), prepared


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "reference-credential-directory", "attempt-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ('expected-master-rows','expected-sinhala-rows'):
        parser.add_argument('--'+name,required=True,type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args()
    # This first import is intentionally pinned to the already reviewed batch.
    if (args.batch_id,args.expected_archive_sha256,args.expected_confirmation_sha256,args.expected_master_rows,args.expected_sinhala_rows)!=(BATCH,ARCHIVE,CONFIRMATION,607,607):
        parser.error('Expected reviewed BATCH-RAW-001 fingerprints and 607/607 rows.')
    return args


def validate_batch_totals(file_rows,review_rows,observations):
    """Pin the inspected checkpoint without converting candidates to mappings."""
    if dict(file_rows)!=EXPECTED_ROWS or dict(review_rows)!={MASTER:2,SINHALA:2}:
        raise ValueError('Reference coverage or retained review counts differ.')
    expected={'MASTER:REPEATED_SINHALA_LABEL':2}
    for mode in MODES:
        expected[mode+':SINGLE_JOINT_CANDIDATE']=605
        expected[mode+':STRUCTURE_REVIEW_REQUIRED']=2
    if +Counter(observations)!=Counter(expected):
        raise ValueError('Reference candidate/source observations differ from reviewed checkpoint.')


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
        validate_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ("127.0.0.1", 5432, "police_identity", "police_identity_app"):
            raise ValueError("Unexpected SQL application target.")
        engine = create_identity_engine(settings)
        password = reference_password(args.reference_credential_directory)
        mongo = reference_client(password)
        collections = {name: mongo[DATABASE][name] for name in COLLECTION_POLICIES}
        selection, snapshots = [], {}
        statuses, warnings = Counter(), Counter()
        file_rows, review_rows, observations = Counter(), Counter(), Counter()
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
                    raise ValueError("reference source confirmation differs.")
                masters=[f for f in files if PurePosixPath(f['archive_path']).name==MASTER]
                if len(masters)!=1:raise ValueError('Registered master file differs.')
                master=masters[0]
                candidates=master_snapshot(connection,crypto,backup,master)
                for filename in ROUTES:
                    selected = [f for f in files if PurePosixPath(f["archive_path"]).name == filename]
                    if len(selected) != 1 or confirmation.source_for(filename) != "POLICE_HR_IS":
                        raise ValueError("reference supplying source/file differs.")
                    file = selected[0]
                    if file["expected_row_count"] != EXPECTED_ROWS[filename] or tuple(file["columns"]) != HEADERS[filename]:
                        raise ValueError("reference registered count/header differs.")
                    file_contracts[filename] = file
                    collection = collections[collection_for({"plan":{"filename":filename}})]
                    rows = connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id == file["import_file_id"]).order_by(RawRecord.source_row_number)).mappings()
                    for number, raw in enumerate(rows, 1):
                        if raw["source_row_number"] != number:
                            raise ValueError("reference-source row sequence has a gap.")
                        payload,binding,fingerprint=reference_payload(crypto,backup,raw,file,args,revision,master,candidates)
                        state, _ = saved_state(connection, collection, crypto=crypto, backup=backup, binding=binding, payload=payload)
                        if args.reconcile and state != "VERIFIED_EXISTING":
                            raise ValueError("Reconciliation found incomplete reference-source delivery.")
                        selection.append((filename, raw["raw_record_id"], number))
                        snapshots[raw["raw_record_id"]] = fingerprint
                        statuses[filename + ":" + state] += 1
                        file_rows[filename] += 1
                        review_rows[filename] += payload["plan"]["needs_review"]
                        plan=payload['plan']
                        if filename==MASTER:
                            for name,value in plan['source_observations'].items():
                                if value:observations['MASTER:'+name.upper()]+=1
                        else:
                            observations.update(c['mode']+':'+c['state'] for c in plan['candidate_evidence'])
                        for item in payload["plan"]["fields"]:
                            for issue in item["issues"]:
                                warnings[filename + ":" + item["source_column"] + ":" + issue] += 1
                        for issue in payload["plan"]["uncertainties"]:
                            warnings[filename + ":" + issue] += 1
                    if file_rows[filename] != EXPECTED_ROWS[filename]:
                        raise ValueError("reference source row coverage differs.")
                    selected_ids = {raw_id for name, raw_id, _ in selection if name == filename}
                    policy = COLLECTION_POLICIES[collection.name]
                    preparations = {str(p["delivery_id"]): p for p in connection.execute(
                        select(PREP.c.delivery_id, PREP.c.raw_record_id, PREP.c.source_assertion_id)
                        .where(PREP.c.writer_policy == policy)).mappings()}
                    if any(p["raw_record_id"] not in selected_ids for p in preparations.values()):
                        raise ValueError("Unexpected SQL reference preparation outside the reviewed batch.")
                    for stored in collection.find({}, {"_id": 1, "raw_record_id": 1, "writer_policy": 1, "source_assertion_uid": 1}):
                        p = preparations.get(stored.get("_id"))
                        if p is None or (stored.get("raw_record_id"), stored.get("writer_policy"), stored.get("source_assertion_uid")) != (
                            p["raw_record_id"], policy, str(p["source_assertion_id"])):
                            raise ValueError("Unexpected or orphan Mongo reference evidence.")
                validate_batch_totals(file_rows, review_rows, observations)
                # Every reference-source assertion must have its atomic SQL preparation.
                assertion_ids = set(connection.execute(select(ReferenceSourceAssertion.source_assertion_id).where(
                    ReferenceSourceAssertion.assertion_type.in_(list(ASSERTION_TYPES.values())))).scalars())
                prepared_assertions = set(connection.execute(select(PREP.c.source_assertion_id)).scalars())
                if assertion_ids != prepared_assertions:
                    raise ValueError("Orphan or unexpected reference source assertion.")
        # No source plaintext leaves preflight; fingerprints are keyed HMACs.
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
        print("Validated reference rows:", len(selection), "| sources:", dict(file_rows), flush=True)
        print("Rows retaining structural review:", dict(review_rows), flush=True)
        print("Source consistency observations:", dict(observations), flush=True)
        print("Delivery states before execution:", dict(statuses), flush=True)
        print("Warnings:", dict(sorted(warnings.items())), flush=True)
        if args.write:
            for progress, (filename, raw_id, number) in enumerate(selection, 1):
                file = file_contracts[filename]
                collection = collections[collection_for({"plan":{"filename":filename}})]
                pending = raw_id
                event("ROW_STARTED", filename=filename, raw_record_id=raw_id, source_row_number=number)
                with engine.connect() as connection:
                    with connection.begin():
                        connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                        raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == raw_id)).mappings().one()
                        # Staging is immutable. The SQL adapter independently recovers
                        # the registered master again before each preparation/receipt.
                        payload,binding,fingerprint=reference_payload(crypto,backup,raw,file,args,revision,master,candidates)
                        if not hmac.compare_digest(snapshots[raw_id],fingerprint):
                            raise ValueError('Reference source changed after preflight.')
                proposed = make_delivery(crypto, backup, payload, event_id=uuid4(), assertion_id=uuid4(), recorded_at=datetime.now(timezone.utc))
                ledger = SqlReferenceLedger(engine, crypto=crypto, backup=backup, binding=binding, expected_payload=payload)
                status = deliver(ledger, collection, proposed, crypto=crypto, backup=backup, expected_payload=payload)
                outcomes[filename + ":" + status] += 1
                event("ROW_COMPLETED", filename=filename, raw_record_id=raw_id, source_row_number=number, status=status)
                pending = None
                if progress % 500 == 0 or progress == len(selection):
                    print("Reference progress:", progress, "/", len(selection), flush=True)
        else:
            outcomes.update(statuses)
        event("COMPLETED", rows=len(selection), outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("Reference workflow: PASSED")
        print("Classification remains UNASSESSED; station identity, historical hierarchy, coordinates, authority and valid periods remain unassessed.")
        print("Candidate mappings remain unaccepted; no human disclosure or verified station-state claim.")
        if not args.write:
            print("No database writes; private attempt journal saved without source values.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if journal is not None:
            try:
                sequence += 1
                save_receipt(dict(sequence=sequence, event="STOPPED", error_type=type(error).__name__, pending_raw_record_id=pending,
                                  outcomes=dict(outcomes)), journal / f"{sequence:08d}.json")
            except Exception:
                print("Stop-event persistence failed; inspect the existing attempt directory.")
        print("Reference workflow stopped:", type(error).__name__)
        print("Committed evidence remains saved. Retry verifies preparation, Mongo document and completion; no deletion.")
        return 1
    finally:
        if mongo is not None:
            mongo.close()
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
