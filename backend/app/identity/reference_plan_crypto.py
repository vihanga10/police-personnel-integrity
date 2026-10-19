"""Authenticated reference plans bound to source and recovered master provenance."""
import json
from uuid import UUID
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.identity.reference_plan import POLICY, ReferencePlan, validate_payload, raw_id, require
from app.identity.station_vocabulary import HEADERS


def context(filename, raw_record_id, evidence):
    require(filename in HEADERS)
    raw_id(raw_record_id)
    require(set(evidence) == {"batch_id", "archive_sha256", "confirmation_sha256", "source_system_code",
        "import_file_id", "source_file_sha256", "source_row_number", "master_import_file_id", "master_file_sha256", "master_rows"})
    require((evidence["batch_id"], evidence["archive_sha256"], evidence["confirmation_sha256"], evidence["source_system_code"]) ==
            (BATCH, ARCHIVE, CONFIRMATION, "POLICE_HR_IS"))
    for name in ("import_file_id", "master_import_file_id"):
        require(str(UUID(evidence[name])) == evidence[name])
    for name in ("source_file_sha256", "master_file_sha256"):
        raw_id(evidence[name])
    require(type(evidence["source_row_number"]) is int and evidence["source_row_number"] > 0 and
            type(evidence["master_rows"]) is int and evidence["master_rows"] > 0)
    # The master snapshot and source row are authenticated along with policy.
    return json.dumps(["REFERENCE_PLAN_ENVELOPE_V1", POLICY, filename, raw_record_id, evidence], sort_keys=True, separators=(",", ":"))


def seal_reference_plan(crypto, plan, *, evidence):
    require(isinstance(plan, ReferencePlan))
    validate_payload(plan.payload)
    binding = context(plan.payload["filename"], plan.payload["raw_record_id"], evidence)
    return crypto.encrypt_assertion(dict(plan=plan.payload, evidence=evidence), context=binding)


def open_reference_plan(crypto, cipher, *, key_version, filename, raw_record_id, evidence):
    payload = crypto.decrypt_assertion(cipher, key_version=key_version, context=context(filename, raw_record_id, evidence))
    require(set(payload) == {"plan", "evidence"} and payload["evidence"] == evidence)
    validate_payload(payload["plan"])
    require(payload["plan"]["filename"] == filename and payload["plan"]["raw_record_id"] == raw_record_id)
    # Recovery authenticates candidate evidence; it does not independently accept
    # the mapping. The runner builds candidates from verified master rows first.
    return payload
