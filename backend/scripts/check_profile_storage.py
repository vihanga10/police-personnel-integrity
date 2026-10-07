"""Exercise encrypted profile migration/import in one transaction; ALWAYS rollback.

Uses temporary synthetic values and ephemeral keys. Existing personnel values
and production encryption keys are neither read nor printed. Run before upgrade.
"""
import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import URL, create_engine, func, inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models import Officer, OfficerIdentifierVersion, SourceAssertion, ProfileTransformReceipt
from app.staging.models import RawRecord
from app.staging.identity_decision import IdentityRegistrationDecision
from app.identity.profile_plan import EXPECTED_COLUMNS, plan_profile
from app.identity.profile_writer import MODELS, PK, transform_row
from app.identity.registration_service import REGISTRATION_LOCK
from app.security.identity_crypto import IdentityCrypto
from migration_settings import MigrationSettings

REVISION = "c91a4b7e2036"
TABLE = "staging.profile_transform_receipt"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    settings = MigrationSettings()
    require((settings.host, settings.port, settings.user, settings.name) ==
            ("127.0.0.1", 5432, "police_identity_migrator", "police_identity"),
            "Unexpected migration database target.")
    engine = create_engine(URL.create("postgresql+psycopg", username=settings.user,
        password=settings.password.get_secret_value(), host=settings.host,
        port=settings.port, database=settings.name), poolclass=NullPool,
        hide_parameters=True, connect_args={"connect_timeout":5})
    path = BACKEND / "migrations/versions/e62c9a01bd47_encrypt_empty_profile_destinations.py"
    spec = importlib.util.spec_from_file_location("profile_storage_check_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = 0
    baseline = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            key = base64.b64encode(__import__("os").urandom(32)).decode()
            material = dict(active_encryption_key_version="ephemeral", active_lookup_key_version="ephemeral",
                            encryption_keys={"ephemeral":key}, lookup_keys={"ephemeral":key})
            paths = [Path(directory)/"primary.json", Path(directory)/"backup.json"]
            for key_path in paths:
                key_path.write_text(json.dumps(material)); key_path.chmod(0o600)
            crypto, backup = (IdentityCrypto(p) for p in paths)
            with engine.connect() as connection:
                outer = connection.begin()
                try:
                    connection.execute(text("SET LOCAL lock_timeout = '5s'"))
                    connection.execute(text("SET LOCAL statement_timeout = '30s'"))
                    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key":REGISTRATION_LOCK})
                    require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == [REVISION], "Unexpected applied revision.")
                    require(connection.execute(text("SELECT to_regclass(:table)"), {"table":TABLE}).scalar_one() is None, "Profile receipt already exists; run this check before upgrading.")
                    baseline = tuple(connection.execute(select(func.count()).select_from(m.__table__)).scalar_one() for m in (Officer, OfficerIdentifierVersion, SourceAssertion))
                    require(baseline == (6596,23966,23966), "Unexpected registry baseline; review before continuing.")
                    for model in MODELS.values():
                        require(connection.execute(select(func.count()).select_from(model.__table__)).scalar_one() == 0, "Profile destination is not empty.")
                    decision = connection.execute(select(IdentityRegistrationDecision.__table__).where(
                        IdentityRegistrationDecision.outcome.in_(["CREATED","MATCHED"])
                    ).order_by(IdentityRegistrationDecision.raw_record_id).limit(1)).mappings().one()
                    raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == decision["raw_record_id"])).mappings().one()
                    context = MigrationContext.configure(connection)
                    with Operations.context(context):
                        module.upgrade()
                    checks += 1
                    context = MigrationContext.configure(connection, opts={
                        "include_schemas":True, "compare_type":True,
                        "version_table":"alembic_version", "version_table_schema":"identity",
                        "include_object":lambda obj,name,kind,reflected,other: kind != "table" or obj.schema in {"identity","staging"},
                    })
                    differences = compare_metadata(context,[Base.metadata,StagingBase.metadata])
                    for group in differences:
                        for item in group if isinstance(group,list) else [group]:
                            metadata = [
                                value for value in item[1:4]
                                if value is None or isinstance(value,(str,bool))
                            ]
                            metadata.extend(
                                value.name for value in item[1:4]
                                if hasattr(value,"name")
                            )
                            print("Schema difference:",item[0],metadata)
                    require(not differences, "Schema/model differences detected.")
                    checks += 1
                    inspector = inspect(connection)
                    for table in module.SPEC:
                        mapped = Base.metadata.tables["identity."+table]
                        reflected = {c["name"] for c in inspector.get_columns(table,schema="identity")}
                        require(reflected == set(mapped.c.keys()), "Profile columns differ from model.")
                        actual = {c["name"] for c in inspector.get_check_constraints(table,schema="identity")}
                        expected = {connection.dialect.identifier_preparer.format_constraint(c).strip('"')
                                    for c in mapped.constraints if c.__class__.__name__ == "CheckConstraint"}
                        require(actual == expected, "Profile checks differ from model.")
                        checks += 2
                    for privilege, expected in (("SELECT",True),("INSERT",True),("UPDATE",False),("DELETE",False),("TRUNCATE",False)):
                        actual = connection.execute(text("SELECT has_table_privilege('police_identity_app', :table, :privilege)"), {"table":TABLE,"privilege":privilege}).scalar_one()
                        require(actual is expected, "Unexpected profile receipt permissions.")
                        checks += 1
                    # Synthetic fixture exercises every populated destination without
                    # decrypting any real officer's staged personnel values.
                    row = {name:"" for name in EXPECTED_COLUMNS}
                    row.update(full_name="Rollback Synthetic Officer", name_with_initials="R S Officer", father_name="Rollback Synthetic Parent",
                        gender="Female", nationality="Sri Lankan", date_of_birth="1990-01-02", age="36",
                        height_cm="165.25", chest_cm="80.25", blood_group="O+", present_address="Rollback Synthetic Address",
                        identifying_marks="Synthetic mark", mo_remark="Synthetic remark", prev_employment_dept="Synthetic Department",
                        officer_email="Synthetic@EXAMPLE.ORG", officer_mobile_number="0712345678")
                    plan = plan_profile(row,phone_region="LK")
                    require(not plan.needs_review,"Synthetic plan requires unexpected review.")
                    kwargs = dict(raw=raw,decision=decision,plan=plan,references={},code_revision="0"*40)
                    status, total = transform_row(connection,crypto,backup,allow_write=True,**kwargs)
                    require((status,total) == ("CREATED",9),"Atomic profile fixture coverage differs.")
                    checks += 1
                    require(transform_row(connection,crypto,backup,allow_write=True,**kwargs) == ("VERIFIED_EXISTING",9),"Profile replay did not verify existing evidence.")
                    checks += 1
                    receipt = connection.execute(select(ProfileTransformReceipt.__table__)).mappings().one()

                    def rejected(action, sqlstate):
                        nonlocal checks
                        savepoint = connection.begin_nested()
                        try:
                            action()
                        except DBAPIError as error:
                            require(getattr(error.orig,"sqlstate",None) == sqlstate,"Unexpected rejection type.")
                            checks += 1
                        else:
                            raise RuntimeError("Invalid database mutation was accepted.")
                        finally:
                            savepoint.rollback()

                    for verb in ("UPDATE staging.profile_transform_receipt SET policy_version=policy_version", "DELETE FROM staging.profile_transform_receipt", "TRUNCATE staging.profile_transform_receipt"):
                        rejected(lambda statement=verb:connection.execute(text(statement)),"P0001")
                    # Insert trigger must reject a receipt whose source decision is
                    # valid but belongs to a different registered source row.
                    other = connection.execute(select(IdentityRegistrationDecision.decision_id).where(
                        IdentityRegistrationDecision.raw_record_id != raw["raw_record_id"]
                    ).limit(1)).scalar_one()
                    changed = dict(receipt, identity_decision_id=other)
                    changed.pop("recorded_at")
                    rejected(lambda:connection.execute(ProfileTransformReceipt.__table__.insert().values(**changed)),"P0001")
                    for table, model in MODELS.items():
                        rejected(lambda model=model:connection.execute(model.__table__.update().values(record_state="DISPUTED")),"P0001")
                        different_source = connection.execute(select(SourceAssertion.source_assertion_id, SourceAssertion.officer_uid).where(
                        SourceAssertion.officer_uid != decision["officer_uid"]
                    ).limit(1)).one()
                    for table in module.SPEC:
                        model = MODELS[table]
                        saved = dict(connection.execute(select(model.__table__)).mappings().one())
                        saved[PK[table]] = uuid4()
                        saved["officer_uid"] = different_source.officer_uid
                        saved["source_assertion_id"] = different_source.source_assertion_id
                        for name in ("relation_chain_uid", "employment_chain_uid", "restricted_profile_chain_uid"):
                            if name in saved:
                                saved[name] = uuid4()
                        saved["valid_from"] = __import__("datetime").date(2026,1,1)
                        rejected(lambda model=model,saved=saved:connection.execute(model.__table__.insert().values(**saved)),"23514")
                    # Outer transaction atomicity: a simulated failure following
                    # a successful write rolls back assertion, destinations and receipt.
                    later = connection.execute(select(IdentityRegistrationDecision.__table__).where(
                        IdentityRegistrationDecision.officer_uid != decision["officer_uid"],
                        IdentityRegistrationDecision.outcome.in_(["CREATED","MATCHED"])
                    ).limit(1)).mappings().one()
                    later_raw = connection.execute(select(RawRecord.__table__).where(RawRecord.raw_record_id == later["raw_record_id"])).mappings().one()
                    before = connection.execute(select(func.count()).select_from(SourceAssertion.__table__)).scalar_one()
                    savepoint = connection.begin_nested()
                    try:
                        transform_row(connection,crypto,backup,raw=later_raw,decision=later,plan=plan,references={},code_revision="0"*40,allow_write=True)
                    finally:
                        savepoint.rollback()
                    require(connection.execute(select(func.count()).select_from(SourceAssertion.__table__)).scalar_one() == before,"Rolled-back row retained an assertion.")
                    require(connection.execute(select(func.count()).select_from(ProfileTransformReceipt.__table__)).scalar_one() == 1,"Rolled-back row retained a receipt.")
                    checks += 2
                    print("Transactional profile storage checks: PASSED | checks=",checks)
                finally:
                    outer.rollback()
            with engine.connect() as connection:
                require(connection.execute(text("SELECT to_regclass(:table)"),{"table":TABLE}).scalar_one() is None,"Rollback did not remove receipt table.")
                require(connection.execute(text("SELECT version_num FROM identity.alembic_version")).scalars().all() == [REVISION],"Applied revision changed during rollback check.")
                restored = tuple(connection.execute(select(func.count()).select_from(m.__table__)).scalar_one() for m in (Officer,OfficerIdentifierVersion,SourceAssertion))
                require(restored == baseline,"Registry counts changed after rollback.")
                for table, columns in module.SPEC.items():
                    reflected = {c["name"] for c in inspect(connection).get_columns(table,schema="identity")}
                    require(set(columns["columns"]).issubset(reflected),"Original profile columns were not restored.")
                print("Rollback verified: original schema restored; no test profile rows retained.")
                print("Applied revision remains:",REVISION)
                print("No personnel values displayed; only ephemeral test keys used.")
        return 0
    except Exception as error:
        print("Profile storage check stopped:",type(error).__name__)
        print("No commit was requested. Review the failing check before upgrading.")
        if isinstance(error,DBAPIError):
            print("SQL state:",getattr(error.orig,"sqlstate",None))
            print("Constraint:",getattr(getattr(error.orig,"diag",None),"constraint_name",None))
        if isinstance(error,RuntimeError):
            print(str(error))
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
