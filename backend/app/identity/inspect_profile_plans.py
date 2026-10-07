"""Read-only staged profile planning and encryption/backup recovery exercise."""

import argparse
import json
from collections import Counter
from pathlib import Path

from sqlalchemy import select, text

from database import create_identity_engine
from settings import Settings
from app.identity.register_profiles import private_key_file, preflight, verify_recovery
from app.identity.profile_plan import plan_profile, validate_routing
from app.identity.profile_plan_crypto import seal_plan, open_plan
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--batch-id", required=True)
    p.add_argument("--expected-archive-sha256", required=True)
    p.add_argument("--confirmation", type=Path, required=True)
    p.add_argument("--expected-confirmation-sha256", required=True)
    p.add_argument("--expected-rows", type=int, required=True)
    p.add_argument("--key-file", type=Path, required=True)
    p.add_argument("--backup-key-file", type=Path, required=True)
    p.add_argument("--phone-region", choices=["LK"])
    args = p.parse_args()
    engine = None
    try:
        if args.expected_rows <= 0 or args.key_file.resolve() == args.backup_key_file.resolve():
            raise ValueError("Invalid count or non-independent backup path.")
        crypto = private_key_file(args.key_file)
        backup = private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        contract = Path(__file__).resolve().parents[3] / "docs/field-routing.json"
        validate_routing(json.loads(contract.read_text(encoding="utf-8")))
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != (
            "127.0.0.1", 5432, "police_identity", "police_identity_app"
        ):
            raise ValueError("Unexpected database target.")
        engine = create_identity_engine(settings)
        selection = preflight(engine, crypto, backup, args)
        selected = {raw_id for raw_id, _ in selection}
        issues, statuses = Counter(), Counter()
        rows = reviews = fields = 0
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
                decisions = IdentityRegistrationDecision.__table__
                latest = {}
                q = select(decisions).where(decisions.c.raw_record_id.in_(selected)).order_by(decisions.c.version_number.desc())
                for decision in connection.execute(q).mappings():
                    latest.setdefault(decision["raw_record_id"], decision)
                if set(latest) != selected:
                    raise ValueError("Registration decision coverage differs.")
                q = select(RawRecord.__table__).where(RawRecord.raw_record_id.in_(selected)).order_by(RawRecord.source_row_number)
                seen = set()
                for raw in connection.execute(q).mappings():
                    decision = latest[raw["raw_record_id"]]
                    if decision["outcome"] not in ("CREATED", "MATCHED") or decision["officer_uid"] is None:
                        raise ValueError("Unresolved registered identity.")
                    if decision["source_confirmation_sha256"] != args.expected_confirmation_sha256:
                        raise ValueError("Registration confirmation differs.")
                    source = open_row(crypto, stored_row(raw))
                    values = dict(zip(source["columns"], source["values"], strict=True))
                    plan = plan_profile(values, phone_region=args.phone_region)
                    binding = dict(officer_uid=decision["officer_uid"], raw_record_id=raw["raw_record_id"])
                    ciphertext, version = seal_plan(crypto, plan, **binding)
                    if open_plan(crypto, ciphertext, key_version=version, **binding) != open_plan(backup, ciphertext, key_version=version, **binding):
                        raise ValueError("Plan backup recovery differs.")
                    seen.add(raw["raw_record_id"])
                    rows += 1
                    reviews += int(plan.needs_review)
                    fields += len(plan.fields)
                    for item in plan.fields:
                        statuses[item.status] += 1
                        for code in item.issues:
                            issues[item.source_column + ":" + code] += 1
                if seen != selected or rows != args.expected_rows:
                    raise ValueError("Planning coverage differs.")
        print("Planning and encryption recovery exercise: PASSED")
        print("Rows planned:", rows)
        print("Non-identifier fields assessed:", fields)
        print("Rows requiring field review:", reviews)
        print("Field status counts:", dict(sorted(statuses.items())))
        print("Issue counts:", dict(sorted(issues.items())))
        print("Station reference mapping and snapshot date were not supplied.")
        print("No database writes or saved plaintext plans; no personnel values displayed.")
        print("Classification remains UNASSESSED; no import readiness or source-truth claim.")
        return 0
    except Exception as error:
        print("Planning stopped:", type(error).__name__)
        print("No database writes requested. Report this output.")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
