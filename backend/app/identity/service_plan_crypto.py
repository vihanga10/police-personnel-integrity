"""Authenticated service-plan envelopes; never an operational MongoDB writer."""
import json
import re
from datetime import date
from uuid import UUID
from app.identity.service_plan import SERVICE_PLAN_POLICY, ServicePlan
from app.identity.service_values import SERVICE_VALUE_POLICY


def context(*,officer_uid,raw_record_id):
    if not isinstance(officer_uid,UUID) or not isinstance(raw_record_id,str) or re.fullmatch(r'[0-9a-f]{64}',raw_record_id) is None:
        raise ValueError('Established officer/source-row binding is required.')
    return json.dumps(['HR_SERVICE_PLAN_ENVELOPE_V1',SERVICE_PLAN_POLICY,SERVICE_VALUE_POLICY,
        str(officer_uid),raw_record_id],separators=(',',':'))


def encoded(value):
    if type(value) is date:
        return {'type':'date','value':value.isoformat()}
    if isinstance(value,UUID):
        return {'type':'uuid','value':str(value)}
    return value


def seal_service_plan(crypto,plan,*,officer_uid,raw_record_id,reference_evidence):
    if not isinstance(plan,ServicePlan) or plan.policy_version != SERVICE_PLAN_POLICY:
        raise ValueError('Unsupported service plan.')
    nic_field = next((f for f in plan.fields if f.source_column == 'officer_nic_no'),None)
    if nic_field is None or nic_field.value is not None and nic_field.value != officer_uid:
        raise ValueError('Planned officer and encryption binding differ.')
    payload = dict(schema_version='1.0',policy_version=SERVICE_PLAN_POLICY,value_policy_version=SERVICE_VALUE_POLICY,
        officer_uid=str(officer_uid),raw_record_id=raw_record_id,
        logical_destination='mongodb.service_status_events',record_classification='UNASSESSED',
        needs_review=plan.needs_review,snapshot_date=None,valid_from=None,valid_to=None,
        review_issues=list(plan.review_issues),uncertainties=list(plan.uncertainties),
        reference_evidence=reference_evidence,
        fields=[dict(source_column=f.source_column,target_field=f.target_field,source_value=f.source_value,
                     value=encoded(f.value),status=f.status,issues=list(f.issues)) for f in plan.fields])
    return crypto.encrypt_assertion(payload,context=context(officer_uid=officer_uid,raw_record_id=raw_record_id))


def open_service_plan(crypto,ciphertext,*,key_version,officer_uid,raw_record_id):
    payload = crypto.decrypt_assertion(ciphertext,key_version=key_version,context=context(officer_uid=officer_uid,raw_record_id=raw_record_id))
    if (payload.get('schema_version'),payload.get('policy_version'),payload.get('value_policy_version'),
        payload.get('officer_uid'),payload.get('raw_record_id')) != ('1.0',SERVICE_PLAN_POLICY,SERVICE_VALUE_POLICY,str(officer_uid),raw_record_id):
        raise ValueError('Service envelope binding differs.')
    return payload
