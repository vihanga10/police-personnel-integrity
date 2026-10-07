"""Authenticated history plans; all fields remain encrypted and classification unassessed."""
from datetime import date
from decimal import Decimal
import json
import re
from uuid import UUID
from app.identity.history_plan import HISTORY_PLAN_POLICY, ROUTES, HistoryPlan
from app.identity.service_values import SERVICE_VALUE_POLICY


def context(filename, officer_uid, raw_record_id):
    # Authenticated context prevents moving a ciphertext to another row or officer.
    if filename not in {"transfer_history.csv", "promotion_history.csv"} or not isinstance(officer_uid, UUID) or not isinstance(raw_record_id, str) or re.fullmatch("[0-9a-f]{64}", raw_record_id) is None:
        raise ValueError("Historical source/officer binding required.")
    return json.dumps(["PF_HISTORY_PLAN_ENVELOPE_V1", HISTORY_PLAN_POLICY, SERVICE_VALUE_POLICY,
                       filename, str(officer_uid), raw_record_id], separators=(",", ":"))


def encoded(value):
    if type(value) is date:
        return {"type": "date", "value": value.isoformat()}
    if isinstance(value, UUID):
        return {"type": "uuid", "value": str(value)}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    return value


def seal_history_plan(crypto, plan, *, raw_record_id, reference_evidence):
    if not isinstance(plan, HistoryPlan) or plan.policy_version != HISTORY_PLAN_POLICY or plan.value_policy_version != SERVICE_VALUE_POLICY:
        raise ValueError("Unsupported historical plan policy.")
    if plan.filename not in ROUTES or len(plan.fields) != len(ROUTES[plan.filename]) or {f.source_column for f in plan.fields} != set(ROUTES[plan.filename]):
        raise ValueError("Historical plan coverage differs.")
    if any(f.target_field != ROUTES[plan.filename][f.source_column] for f in plan.fields):
        raise ValueError("Historical plan routing differs.")
    nic = next(f for f in plan.fields if f.source_column == "officer_nic_no")
    if nic.value is not None and nic.value != plan.officer_uid:
        raise ValueError("Historical plan officer binding differs.")
    # Parsing an order does not approve its authority, classification or service period.
    payload = dict(schema_version="1.0", policy_version=plan.policy_version, value_policy_version=plan.value_policy_version,
        filename=plan.filename, officer_uid=str(plan.officer_uid), raw_record_id=raw_record_id,
        record_classification="UNASSESSED", authority_result=None, authority_assessment="NOT_RUN",
        valid_from=None, valid_to=None, needs_review=plan.needs_review,
        reference_evidence=reference_evidence, review_issues=list(plan.review_issues), observations=list(plan.observations),
        uncertainties=list(plan.uncertainties), fields=[dict(source_column=f.source_column, target_field=f.target_field,
        source_value=f.source_value, value=encoded(f.value), status=f.status, issues=list(f.issues)) for f in plan.fields])
    return crypto.encrypt_assertion(payload, context=context(plan.filename, plan.officer_uid, raw_record_id))


def open_history_plan(crypto, cipher, *, key_version, filename, officer_uid, raw_record_id):
    payload = crypto.decrypt_assertion(cipher, key_version=key_version, context=context(filename, officer_uid, raw_record_id))
    if (payload.get("schema_version"), payload.get("policy_version"), payload.get("value_policy_version"),
        payload.get("filename"), payload.get("officer_uid"), payload.get("raw_record_id"), payload.get("record_classification")) != (
        "1.0", HISTORY_PLAN_POLICY, SERVICE_VALUE_POLICY, filename, str(officer_uid), raw_record_id, "UNASSESSED"):
        raise ValueError("Historical envelope binding differs.")
    return payload
