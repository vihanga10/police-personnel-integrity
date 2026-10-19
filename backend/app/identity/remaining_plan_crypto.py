"""Authenticated remaining-source plans bound to policy, file and encrypted raw row."""
from datetime import date, time
from decimal import Decimal
import json, re
from uuid import UUID
from app.identity.remaining_plan import REMAINING_PLAN_POLICY, ROUTES, RemainingPlan
from app.identity.inspect_remaining_sources import HEADERS


def context(filename, raw_record_id):
    # Source-scoped binding works for both single-subject and multi-person events.
    if filename not in HEADERS or not isinstance(raw_record_id, str) or re.fullmatch("[0-9a-f]{64}", raw_record_id) is None:
        raise ValueError("Supported source/raw-record binding required.")
    return json.dumps(["REMAINING_PLAN_ENVELOPE_V1", REMAINING_PLAN_POLICY, filename, raw_record_id], separators=(",", ":"))


def encoded(value):
    if isinstance(value, (date, time)): return {"type": type(value).__name__, "value": value.isoformat()}
    if isinstance(value, UUID): return {"type": "uuid", "value": str(value)}
    if isinstance(value, Decimal): return {"type": "decimal", "value": str(value)}
    return value


def seal_remaining_plan(crypto, plan, *, raw_record_id, reference_evidence):
    if not isinstance(plan, RemainingPlan) or plan.policy_version != REMAINING_PLAN_POLICY:
        raise ValueError("Unsupported remaining plan.")
    if tuple(f.source_column for f in plan.fields) != HEADERS[plan.filename] or any((f.destination, f.target_field) != ROUTES[plan.filename][f.source_column] for f in plan.fields):
        raise ValueError("Remaining plan coverage/routing differs.")
    if "officer_nic_no" in HEADERS[plan.filename]:
        if next(f.value for f in plan.fields if f.source_column == "officer_nic_no") != plan.officer_uid:
            raise ValueError("Remaining subject binding differs.")
    elif plan.officer_uid is not None: raise ValueError("Unexpected single event subject.")
    payload = dict(schema_version="1.0", policy_version=REMAINING_PLAN_POLICY, filename=plan.filename,
        raw_record_id=raw_record_id, officer_uid=str(plan.officer_uid) if plan.officer_uid else None,
        record_classification="UNASSESSED", authority_result=None, authority_assessment="NOT_RUN",
        valid_from=None, valid_to=None, reconstructed_state=None, effects_applied=False,
        needs_review=plan.needs_review, reference_evidence=reference_evidence,
        observations=list(plan.observations), review_issues=list(plan.review_issues), uncertainties=list(plan.uncertainties),
        fields=[dict(source_column=f.source_column, destination=f.destination, target_field=f.target_field,
            source_value=f.source_value, value=encoded(f.value), status=f.status, issues=list(f.issues)) for f in plan.fields])
    return crypto.encrypt_assertion(payload, context=context(plan.filename, raw_record_id))


def open_remaining_plan(crypto, cipher, *, key_version, filename, raw_record_id):
    payload = crypto.decrypt_assertion(cipher, key_version=key_version, context=context(filename, raw_record_id))
    if (payload.get("schema_version"), payload.get("policy_version"), payload.get("filename"), payload.get("raw_record_id"), payload.get("record_classification")) != ("1.0", REMAINING_PLAN_POLICY, filename, raw_record_id, "UNASSESSED"):
        raise ValueError("Remaining envelope binding differs.")
    if payload.get("authority_result") is not None or payload.get("authority_assessment") != "NOT_RUN" or payload.get("effects_applied") is not False or any(payload.get(k) is not None for k in ("valid_from", "valid_to", "reconstructed_state")):
        raise ValueError("Unapproved remaining-source determination.")
    fields = payload.get("fields", [])
    if tuple(f["source_column"] for f in fields) != HEADERS[filename] or any((f["destination"], f["target_field"]) != ROUTES[filename][f["source_column"]] for f in fields):
        raise ValueError("Remaining envelope coverage/routing differs.")
    subject = next((f for f in fields if f["source_column"] == "officer_nic_no"), None)
    expected = {"type": "uuid", "value": payload["officer_uid"]} if payload.get("officer_uid") else None
    if (subject is not None and subject["value"] != expected) or (subject is None and payload.get("officer_uid") is not None):
        raise ValueError("Remaining envelope subject differs.")
    return payload
