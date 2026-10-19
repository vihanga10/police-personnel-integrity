from copy import deepcopy
from datetime import datetime,timezone,timedelta
import base64,json,subprocess
from pathlib import Path
import pytest
from app.identity.research_anchor import authenticate_gate,authorization,SCOPE
from app.identity.anchor_gate import POLICY,publication_plan
from app.identity.protected_commitment import digest
from app.identity.evidence_bundle_v2 import seal_artifact
from app.security.identity_crypto import IdentityCrypto
from test_anchor_gate import public_fixture


def fixture(tmp_path):
    encoded=base64.b64encode(b'E'*32).decode();lookup=base64.b64encode(b'L'*32).decode()
    p=tmp_path/'keys.json';p.write_text(json.dumps(dict(active_encryption_key_version='test',active_lookup_key_version='test',encryption_keys={'test':encoded},lookup_keys={'test':lookup})))
    crypto=IdentityCrypto(p);backup=IdentityCrypto(p);public=public_fixture();now=datetime.now(timezone.utc)
    gate=dict(policy=POLICY,status='PASSED',checked_at=now.isoformat(),completed_at=now.isoformat(),code_revision='a'*40,commitment_attempt_id='fixture',public_payload_sha256=digest(public),scope=SCOPE,max_age_seconds=600,historical_claims='UNASSESSED',plan=publication_plan(public))
    binding=dict(artifact='LIVE_ANCHOR_GATE',policy=POLICY,public_payload_sha256=digest(public))
    return crypto,backup,public,gate,binding


def test_encrypted_gate_and_python_node_authorization_agree(tmp_path):
    c,b,p,g,context=fixture(tmp_path);envelope=seal_artifact(c,b,g,context)
    assert authenticate_gate(envelope,c,b,p,revision='a'*40,commitment_attempt_id='fixture',expected_sha=digest(p))==g
    network=dict(channel='personnel',chaincode='officer-evidence-v1')
    ticket=authorization(p,g,network,'EXECUTE',b'S'*32)
    repo=Path(__file__).resolve().parents[2]
    code="const {authorize}=require('./blockchain/fabric/client/research-authorization');const fs=require('fs');const ticket=JSON.parse(fs.readFileSync(0,'utf8'));authorize(ticket,Buffer.alloc(32,83),'EXECUTE');console.log('PASSED');"
    result=subprocess.run(['node','-e',code],input=json.dumps(ticket),text=True,cwd=repo,capture_output=True)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='PASSED'


@pytest.mark.parametrize('kind',['expired','future','revision','attempt','scope','classification','plan','timestamp','ciphertext','publication'])
def test_gate_cannot_authorize_changed_evidence_or_context(tmp_path,kind):
    c,b,p,g,context=fixture(tmp_path)
    if kind=='expired':g['checked_at']=(datetime.now(timezone.utc)-timedelta(minutes=11)).isoformat()
    if kind=='future':g['checked_at']=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()
    if kind=='revision':g['code_revision']='b'*40
    if kind=='attempt':g['commitment_attempt_id']='other'
    if kind=='scope':g['scope']=dict(SCOPE,officers=1)
    if kind=='classification':g['historical_claims']='ACCEPTED'
    if kind=='plan':g['plan']=deepcopy(g['plan']);g['plan']['chunks'][0]['records'][0]['commitment']='f'*64
    if kind=='timestamp':g['completed_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    envelope=seal_artifact(c,b,g,context)
    if kind=='ciphertext':envelope['ciphertext']=base64.b64encode(b'invalid').decode()
    if kind=='publication':p=deepcopy(p);p['officers'][0]['commitment']='e'*64
    with pytest.raises(Exception):authenticate_gate(envelope,c,b,p,revision='a'*40,commitment_attempt_id='fixture',expected_sha=context['public_payload_sha256'])
