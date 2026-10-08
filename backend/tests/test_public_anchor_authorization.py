from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import subprocess
from pathlib import Path
import pytest
import app.identity.public_anchor_authorization as module
from app.identity.anchor_gate import POLICY
from app.identity.evidence_bundle_v2 import canonical
from app.identity.protected_commitment import digest
from test_anchor_gate import public_fixture


def inputs(monkeypatch):
    public = public_fixture()
    sha = digest(public)
    # Test-only digest override; production always requires the original publication SHA.
    monkeypatch.setattr(module, 'PUBLIC_SHA', sha)
    gate = dict(policy=POLICY, status='PASSED', public_payload_sha256=sha,
        checked_at=datetime.now(timezone.utc).isoformat())
    reconciliation = dict(status='PASSED', mode='RECONCILE', public_payload_sha256=sha,
        fabric_result=dict(status='PASSED', mode='RECONCILE', public_payload_sha256=sha,
            officers=6596, original_valid_transactions=68, two_organization_readback=True,
            batch_publication_id=public['batch_publication_id'], merkle_root=public['merkle_root'], classification='UNASSESSED'))
    return public, gate, reconciliation


def test_public_session_mac_matches_node_canonicalization(monkeypatch):
    p, g, r = inputs(monkeypatch)
    envelope = module.ticket(p, g, r, mode='VALIDATE', budget='0.025', secret=b'S' * 32)
    repo = Path(__file__).resolve().parents[2]
    code = "const crypto=require('crypto'),F=require('./blockchain/public/deployment-files');const t=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(crypto.createHmac('sha256',Buffer.alloc(32,83)).update(F.stable(t.payload)).digest('hex'));"
    result = subprocess.run(['node', '-e', code], cwd=repo, input=json.dumps(envelope), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == envelope['mac']


@pytest.mark.parametrize('kind', ['mode', 'key', 'budget', 'negative_budget', 'large_budget', 'expired', 'future',
    'fabric_mode', 'officers', 'receipts', 'peer', 'classification', 'root', 'publication'])
def test_public_session_rejects_changed_context(monkeypatch, kind):
    p, g, r = inputs(monkeypatch)
    mode, budget, secret = 'EXECUTE', '0.025', b'S' * 32
    if kind == 'mode': mode = 'OTHER'
    if kind == 'key': secret = b'S'
    if kind == 'budget': budget = 'NaN'
    if kind == 'negative_budget': budget = '-1'
    if kind == 'large_budget': budget = '6'
    if kind == 'expired': g['checked_at'] = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
    if kind == 'future': g['checked_at'] = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    if kind == 'fabric_mode': r['fabric_result']['mode'] = 'EXECUTE'
    if kind == 'officers': r['fabric_result']['officers'] = 1
    if kind == 'receipts': r['fabric_result']['original_valid_transactions'] = 67
    if kind == 'peer': r['fabric_result']['two_organization_readback'] = False
    if kind == 'classification': r['fabric_result']['classification'] = 'ACCEPTED'
    if kind == 'root': r['fabric_result']['merkle_root'] = '0' * 64
    if kind == 'publication': p['officers'][0]['commitment'] = 'f' * 64
    with pytest.raises(Exception): module.ticket(p, g, r, mode=mode, budget=budget, secret=secret)
