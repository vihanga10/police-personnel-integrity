"""Encrypt in-memory review plans; this is not a destination-table writer."""

import json
import re
from datetime import date
from decimal import Decimal
from uuid import UUID

from app.identity.profile_plan import PLAN_POLICY, ProfilePlan


def plan_context(*, officer_uid, raw_record_id):
    if not isinstance(officer_uid, UUID):
        raise ValueError("An established officer UUID is required.")
    if not isinstance(raw_record_id, str) or re.fullmatch(r"[0-9a-f]{64}", raw_record_id) is None:
        raise ValueError("A staged source-row reference is required.")
    return json.dumps(["ENCRYPTED_PROFILE_REVIEW_PLAN_V1", PLAN_POLICY,
                       str(officer_uid), raw_record_id], separators=(",", ":"))


def _encoded(value):
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    if type(value) is date:
        return {"type": "date", "value": value.isoformat()}
    return value


def seal_plan(crypto, plan, *, officer_uid, raw_record_id):
    if not isinstance(plan, ProfilePlan) or plan.policy_version != PLAN_POLICY:
        raise ValueError("Unsupported profile plan.")
    payload = {
        "schema_version": "1.0", "policy_version": PLAN_POLICY,
        "officer_uid": str(officer_uid), "raw_record_id": raw_record_id,
        "record_classification": "UNASSESSED", "needs_review": plan.needs_review,
        "valid_from": None, "valid_to": None, "measured_at": None,
        "fields": [dict(
            source_column=item.source_column, table=item.table, target_field=item.target_field,
            source_value=item.source_value, value=_encoded(item.value),
            status=item.status, issues=list(item.issues),
        ) for item in plan.fields],
    }
    return crypto.encrypt_assertion(payload, context=plan_context(
        officer_uid=officer_uid, raw_record_id=raw_record_id,
    ))


def open_plan(crypto, ciphertext, *, key_version, officer_uid, raw_record_id):
    payload = crypto.decrypt_assertion(ciphertext, key_version=key_version,
        context=plan_context(officer_uid=officer_uid, raw_record_id=raw_record_id))
    if (payload.get("schema_version"), payload.get("policy_version"),
        payload.get("officer_uid"), payload.get("raw_record_id")) != (
        "1.0", PLAN_POLICY, str(officer_uid), raw_record_id):
        raise ValueError("Profile plan binding differs.")
    return payload
