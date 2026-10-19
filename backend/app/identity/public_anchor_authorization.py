"""Bind fresh live/Fabric reconciliation to one exact Sepolia publication session."""
from datetime import datetime, timezone
import hashlib
import hmac
import re

PUBLIC_SHA = 'fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b'
DEPLOYMENT_TX = '0x9240ee602582b02fc0e363610bbbaf462215aca366771891a9e6508c42be1dbd'


def ticket(publication, gate, reconciliation, *, mode, budget, secret):
    # Imports are inside the function so pure negative tests can reject malformed input first.
    if mode not in ('VALIDATE', 'EXECUTE', 'RECONCILE') or len(secret) != 32:
        raise ValueError('Public session mode or key differs.')
    if not isinstance(budget, str) or not re.fullmatch(r'\d+(\.\d{1,9})?', budget):
        raise ValueError('Public session budget differs.')
    from decimal import Decimal
    if not 0 < Decimal(budget) <= 5:
        raise ValueError('Public session test budget outside policy.')
    from app.identity.evidence_bundle_v2 import canonical, require
    from app.identity.anchor_gate import require_recent_gate
    from app.identity.protected_commitment import digest
    require_recent_gate(gate, publication)
    require(digest(publication) == PUBLIC_SHA, 'Original research publication required.')
    r = reconciliation['fabric_result']
    require(reconciliation['status'] == 'PASSED' and reconciliation['mode'] == 'RECONCILE' and
        reconciliation['public_payload_sha256'] == PUBLIC_SHA and r['status'] == 'PASSED' and
        r['mode'] == 'RECONCILE' and r['public_payload_sha256'] == PUBLIC_SHA and r['officers'] == 6596 and
        r['original_valid_transactions'] == 68 and r['two_organization_readback'] is True and
        r['batch_publication_id'] == publication['batch_publication_id'] and
        r['merkle_root'] == publication['merkle_root'] and r['classification'] == 'UNASSESSED', 'Fresh Fabric result differs.')
    payload = dict(policy='SEPOLIA_RESEARCH_SUBMISSION_V1', mode=mode, checked_at=gate['checked_at'],
        publication=publication, public_payload_sha256=PUBLIC_SHA, reconciliation=reconciliation,
        deployment_transaction=DEPLOYMENT_TX, publication_fee_budget_eth=budget)
    mac = hmac.new(secret, canonical(payload).encode(), hashlib.sha256).hexdigest()
    return dict(payload=payload, mac=mac)
