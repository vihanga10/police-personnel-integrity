"""Authenticate a freshly encrypted live gate before authorizing the exact public commitment payload."""
from datetime import datetime, timezone
import hashlib
import hmac
from app.identity.anchor_gate import POLICY, publication_plan, require_recent_gate
from app.identity.evidence_bundle_v2 import open_artifact, canonical, require
from app.identity.protected_commitment import digest

SCOPE=dict(officers=6596,source_rows=167865,sql_records=794200,mongo_documents=154673)


def authenticate_gate(envelope,crypto,backup,public,*,revision,commitment_attempt_id,expected_sha,now=None):
    require(digest(public)==expected_sha,'Requested publication digest differs.')
    binding=dict(artifact='LIVE_ANCHOR_GATE',policy=POLICY,public_payload_sha256=expected_sha)
    gate=open_artifact(crypto,envelope,binding)
    require(open_artifact(backup,envelope,binding)==gate,'Gate backup recovery differs.')
    require_recent_gate(gate,public,now)
    require(gate['code_revision']==revision and gate['commitment_attempt_id']==commitment_attempt_id and
        gate['scope']==SCOPE and gate['max_age_seconds']==600 and gate['historical_claims']=='UNASSESSED', 'Live gate context differs.')
    require(gate['plan']==publication_plan(public),'Authenticated publication plan differs.')
    require(datetime.fromisoformat(gate['completed_at'])>=datetime.fromisoformat(gate['checked_at']), 'Gate time order differs.')
    return gate


def authorization(public,gate,network,mode,secret):
    require(mode in ('VALIDATE','EXECUTE','RECONCILE') and len(secret)==32,'Authorization mode/key differs.')
    require_recent_gate(gate,public)
    payload=dict(policy='FABRIC_RESEARCH_SUBMISSION_V1',mode=mode,publication=public,plan=gate['plan'],
        checked_at=gate['checked_at'],public_payload_sha256=digest(public),network=network)
    mac=hmac.new(secret,canonical(payload).encode(),hashlib.sha256).hexdigest()
    return dict(payload=payload,mac=mac)
