"""Development CLI: validate, atomically import, or reconcile protected PF profiles.

This is a local intake workflow, not an authenticated application endpoint.
Do not expose it to users until HQ Admin authentication and authorization exist.
"""

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.register_profiles import private_key_file, preflight, verify_recovery
from app.identity.registration_service import REGISTRATION_LOCK
from app.identity.profile_plan import plan_profile, validate_routing
from app.identity.profile_plan_crypto import seal_plan, open_plan
from app.identity.profile_records import WRITER_POLICY, logical_records
from app.identity.profile_writer import transform_row
from app.identity.station_reference import load_staged_station_index
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.intake.registration_receipt import save_receipt
from app.staging.models import RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision


def _profile(connection, crypto, backup, raw_id, station_index, station_provenance, args):
    raw = connection.execute(select(RawRecord.__table__).where(
        RawRecord.raw_record_id == raw_id
    )).mappings().one()
    decision = connection.execute(select(IdentityRegistrationDecision.__table__).where(
        IdentityRegistrationDecision.raw_record_id == raw_id
    ).order_by(IdentityRegistrationDecision.version_number.desc()).limit(1)).mappings().one()
    if decision["outcome"] not in {"CREATED", "MATCHED"} or decision["officer_uid"] is None:
        raise ValueError("Unresolved registered officer identity.")
    if decision["source_confirmation_sha256"] != args.expected_confirmation_sha256:
        raise ValueError("Identity registration source confirmation differs.")
    payload = open_row(crypto, stored_row(raw))
    plan = plan_profile(dict(zip(payload["columns"], payload["values"], strict=True)),
                        phone_region=args.phone_region, station_candidates=station_index.candidates)
    logical_records(plan)  # Reject review-required plans before any writes.
    station = next(f for f in plan.fields if f.source_column == "present_address_local_police_station_name")
    references = {}
    if station.status == "PARSED":
        references["address_station"] = dict(station_provenance, station_code=station.value,
                                             raw_record_id=station_index.source_rows[station.value])
    binding = dict(officer_uid=decision["officer_uid"], raw_record_id=raw_id)
    ciphertext, version = seal_plan(crypto, plan, reference_evidence=references, **binding)
    evidence = open_plan(backup, ciphertext, key_version=version, **binding)
    fingerprint, _ = crypto.lookup_hmac(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        identifier_type="PF_PROFILE_PREFLIGHT_V1",
    )
    return raw, decision, plan, references, fingerprint


def _args():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("batch-id", "expected-archive-sha256", "expected-confirmation-sha256"):
        p.add_argument("--" + name, required=True)
    for name in ("confirmation", "key-file", "backup-key-file", "attempt-root"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--expected-rows", required=True, type=int)
    p.add_argument("--phone-region", choices=["LK"], required=True)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = p.parse_args()
    if args.expected_rows <= 0 or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (
        args.expected_archive_sha256, args.expected_confirmation_sha256
    )):
        p.error("Invalid expected count or fingerprints.")
    return args


def main():
    args = _args()
    engine = None
    journal = None
    pending = None
    sequence = 0
    outcomes = Counter()
    try:
        repository = Path(__file__).resolve().parents[3]
        def git(*parts):
            return subprocess.check_output(["git", "-C", str(repository), *parts], text=True).strip()
        if git("status", "--porcelain"):
            raise ValueError("Commit reviewed code before running this intake workflow.")
        code_revision = git("rev-parse", "HEAD")
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        if args.key_file.resolve() == args.backup_key_file.resolve():
            raise ValueError("Use separate primary and backup key files.")
        verify_recovery(crypto, backup)
        validate_routing(json.loads((repository / "docs/field-routing.json").read_text()))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != (
            "127.0.0.1", 5432, "police_identity", "police_identity_app"
        ):
            raise ValueError("Unexpected application database target.")
        engine = create_identity_engine(settings)
        # Existing intake integrity and independent backup-recovery preflight.
        selection = preflight(engine, crypto, backup, args)
        snapshots, counts, issue_counts = {}, Counter(), Counter()
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                station_index, station_provenance = load_staged_station_index(connection, crypto, backup, batch_id=args.batch_id)
                for raw_id, number in selection:
                    raw, decision, plan, refs, digest = _profile(connection, crypto, backup, raw_id, station_index, station_provenance, args)
                    # Include registration binding in addition to normalized-source fingerprint.
                    snapshots[raw_id] = (decision["decision_id"], decision["officer_uid"], digest)
                    for record in logical_records(plan):
                        counts[record.table] += 1
                    for item in plan.fields:
                        for code in item.issues:
                            issue_counts[item.source_column + ":" + code] += 1
                    status, _ = transform_row(connection, crypto, backup, raw=raw, decision=decision,
                        plan=plan, references=refs, code_revision=code_revision, allow_write=False)
                    if not args.write:
                        outcomes[status] += 1
                if args.reconcile and outcomes.get("PLANNED", 0):
                    raise ValueError("Reconciliation found missing profile receipts.")
        root = args.attempt_root.expanduser().absolute()
        if root.resolve().is_relative_to(repository):
            raise ValueError("Keep intake evidence outside the source repository.")
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Attempt paths must not contain symlinks.")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.stat().st_mode & 0o077:
            raise ValueError("Attempt root must have owner-only permissions.")
        journal = root / str(uuid4())
        journal.mkdir(mode=0o700)
        metadata = dict(batch_id=args.batch_id, policy_version=WRITER_POLICY, code_revision=code_revision,
                        archive_sha256=args.expected_archive_sha256, confirmation_sha256=args.expected_confirmation_sha256,
                        mode="WRITE" if args.write else "RECONCILE" if args.reconcile else "VALIDATION",
                        actor_context="LOCAL_DEVELOPMENT_INTAKE_SESSION")
        def event(kind, **extra):
            nonlocal sequence
            sequence += 1
            save_receipt(dict(metadata, sequence=sequence, event=kind, **extra), journal / f"{sequence:08d}.json")
        event("PREFLIGHT_PASSED", rows=len(selection), expected_destination_counts=dict(counts), warnings=dict(issue_counts))
        print("Attempt directory:", journal, flush=True)
        print("Validated profiles:", len(selection), flush=True)
        print("Destination counts:", dict(sorted(counts.items())), flush=True)
        print("Warnings:", dict(sorted(issue_counts.items())), flush=True)
        if args.write:
            for raw_id, number in selection:
                pending = raw_id
                event("ROW_STARTED", raw_record_id=raw_id, source_row_number=number)
                with engine.begin() as connection:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": REGISTRATION_LOCK})
                    raw, decision, plan, refs, digest = _profile(connection, crypto, backup, raw_id, station_index, station_provenance, args)
                    if snapshots[raw_id] != (decision["decision_id"], decision["officer_uid"], digest):
                        raise ValueError("Source or identity changed after preflight.")
                    status, saved_count = transform_row(connection, crypto, backup, raw=raw, decision=decision,
                        plan=plan, references=refs, code_revision=code_revision, allow_write=True)
                # Commit completed before journaling success; interrupted journal
                # writes remain uncertain until the persisted receipt is verified.
                outcomes[status] += 1
                event("ROW_COMPLETED", raw_record_id=raw_id, source_row_number=number,
                      status=status, destination_records=saved_count)
                pending = None
                if number % 500 == 0 or number == len(selection):
                    print("Profile progress:", number, "/", len(selection), flush=True)
        event("COMPLETED", rows=len(selection), outcomes=dict(outcomes))
        print("Outcomes:", dict(outcomes))
        print("Profile workflow: PASSED")
        print("Security classification remains UNASSESSED; no user disclosure is enabled.")
        if not args.write:
            print("No database writes; encrypted receipt/destination recovery checked for existing imports.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if journal is not None:
            try:
                sequence += 1
                save_receipt(dict(sequence=sequence, event="STOPPED", error_type=type(error).__name__,
                                  pending_raw_record_id=pending, outcomes=dict(outcomes)), journal / f"{sequence:08d}.json")
            except Exception:
                print("Stop-event persistence failed; inspect existing journal.")
        print("Profile workflow stopped:", type(error).__name__)
        if isinstance(error, ValueError):
            print(str(error))
        print("Previously committed rows, if any, remain saved; verify receipts on retry.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
