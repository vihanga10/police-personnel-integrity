"""Invented test evidence only. No real personnel, law, ledger or live readiness."""
import base64
from copy import deepcopy
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time
from app.access.policy import encoded
from app.access import research_policy as P
from app.access.research_store import ResearchStore
from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from scoped_access_fixture import setup, grant as account_grant, catalog, identifier, PASSWORD

def sign(key, value):
    return dict(key_id='workspace-test', payload=deepcopy(value), signature=base64.b64encode(key.sign(encoded(value))).decode())

def presentation(key, *, officer=identifier(1), generation=1, now=None):
    now=int(time.time()) if now is None else int(now)
    start=datetime.fromtimestamp(now-172800,timezone.utc); correction=start+timedelta(days=1); end=datetime.fromtimestamp(now-20,timezone.utc)
    reference=lambda filename:json.dumps(dict(filename=filename,provenance=dict(reported_source=filename)))
    def claim(cid,value):return Claim(cid,officer,'rank',json.dumps(dict(to_rank=value)),reference('promotion_history.csv' if cid=='reported-row-A' else 'transfer_history.csv'),'a'*64,start=date(2024,1,1))
    first=EvidenceVersion('version-A',claim('reported-row-A','Reported Inspector'),'source-A',start,'receipt-A','1'*64)
    other=EvidenceVersion('version-B',claim('reported-row-B','Reported Superintendent'),'source-B',start,'receipt-B','2'*64)
    changed=EvidenceVersion('version-A2',claim('reported-row-A','Reported Superintendent'),'source-A',correction,'receipt-A2','3'*64,supersedes='version-A')
    h=RecordingHistory(officer,start,end,'fixture-recorded-coverage','4'*64,(first,other,changed))
    wire=json.loads(json.dumps(asdict(h),default=lambda x:x.isoformat()));wire.pop('officer_uid')
    value=dict(policy=P.POLICY,kind='PRESENTATION',issued_at=now-1,expires_at=now+1800,officer_uid=officer,generation=generation,
        source_public_sha256='a'*64,observed_at=datetime.fromtimestamp(now-10,timezone.utc).isoformat(),recording_tip_sha256='5'*64,
        history=wire,findings=[dict(finding_id=identifier(201),head_sha256='b'*64,status='REPORTED_CONTRADICTION_CANDIDATE',dimension='rank',
            effective_on='2024-12-31',known_at=start.isoformat(),versions=[dict(kind='FINDING',entry_sha256='b'*64,supersedes=None,
                recorded_at=start.isoformat(),decision=None,reason='Invented fixture: two source reports disagree. No accepted contradiction.')])],
        authority=[dict(action_id='c'*64,action_type='REPORTED_PROMOTION',action_on='2024-01-01',status='CANNOT_VERIFY',
            reasons=['AUTHORITY_AND_DELEGATION_UNASSESSED'],assessment_receipt_sha256=None)],
        anchoring=dict(fabric=dict(status='ISOLATED_ONLY',receipt_sha256='d'*64),public=dict(status='FINALITY_PENDING',receipt_sha256=None),recovery=dict(status='ISOLATED_ONLY',receipt_sha256='e'*64)))
    return sign(key,value)

def disclosure(key, *, user=identifier(100), officer=identifier(1), now=None, assignment='ORDINARY', classification='ORDINARY', clearance=False, reviews=True, version=1):
    now=int(time.time()) if now is None else int(now)
    return sign(key,dict(policy=P.POLICY,kind='DISCLOSURE',issued_at=now-1,expires_at=now+1800,user_id=user,account_version=version,
        officer_uid=officer,source_public_sha256='a'*64,assignment=assignment,classification=classification,
        restricted_clearance=clearance,request_reviews=reviews,reviewer_uid=identifier(1) if reviews else None))

def initialize(root, *, clock=time.time):
    access,key,config=setup(root,clock=clock)
    access.put_account(account_grant(key,now=clock()),PASSWORD);access.put_directory(catalog(key,now=clock()))
    workspace=root/'workspace';workspace.mkdir(mode=0o700)
    file=root/'workspace.key';file.write_bytes(os.urandom(32));file.chmod(0o600)
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    keys={'workspace-test':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    store=ResearchStore(workspace,file,keys,access=access,create=True)
    store.import_packet(presentation(key,now=clock()));store.import_grant(disclosure(key,now=clock()))
    cfg=root/'workspace-config.json';cfg.write_text(json.dumps(dict(policy='RESEARCH_WEB_CONFIG_V1',access_config=str(config),
        state_directory=str(workspace),key_file=str(file),presentation_keys={k:base64.b64encode(v).decode() for k,v in keys.items()})));cfg.chmod(0o600)
    return store,key,cfg

def review_body(**changes):
    value=dict(officer_uid=identifier(1),operation_id=identifier(301),finding_id=identifier(201),target_head_sha256='b'*64,
        generation=1,kind='REVIEW',decision='NEEDS_MORE_EVIDENCE',reason='Invented fixture review needs evidence.',evidence_references=['b'*64])
    value.update(changes);return value
