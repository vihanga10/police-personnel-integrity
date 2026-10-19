"""Short-lived research audit permits for the exact, fully reconciled received batch.

Receipt dictionaries are trusted-runner inputs, never independent chain proofs.
The CLI obtains them using live read-only verifiers before sealing a permit.
"""
from datetime import datetime, timezone, timedelta
import re
from app.identity.anchor_gate import publication_plan, require_recent_gate
from app.identity.evidence_bundle_v2 import require, open_artifact, seal_artifact
from app.identity.protected_commitment import digest
from app.identity.research_anchor import SCOPE
from app.identity.public_anchor_authorization import PUBLIC_SHA, DEPLOYMENT_TX

POLICY = 'ANCHORED_RESEARCH_AUDIT_GATE_V1'
CONTRACT = '0x4Ae794040d9794cd3b50BB06Fd41eE540c2435a6'
WRITER = '0x88208CC4Bf8118072C909A8Fef25740126f66AE1'
GENESIS = '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'
RUNTIME = '342e000dc0be621e29a8db988c9e8e545402ab0153bd5acc179af4e520f53b94'
CONFIG = 'b1fb4596332921c0c68a66504098fb3b4ba988e36d6f79ab465d6b22fc7aba61'
FABRIC_GENESIS = '7e496158e847bd1ed07232f4790331f9ec9a6639e3419e2e98ea55a89948016e'
HEADER = 'b9ed551d2ce23b9ac765e6e9e9966ce498e7b09e85450fb98103e38354588cb6'
DATA = '2d4a456cfa91b90cbbd152d47ee960f07a42be2eba401d4a0bedddf42064d434'


def binding(context):
    require(set(context) == {'code_revision', 'bundle_attempt_id', 'binding_attempt_id',
        'commitment_attempt_id', 'binding_artifact_sha256'}, 'Audit evidence context differs.')
    require(all(isinstance(v, str) and v for v in context.values()), 'Audit context is missing.')
    require(re.fullmatch('[0-9a-f]{40}', context['code_revision']) is not None and
        re.fullmatch('[0-9a-f]{64}', context['binding_artifact_sha256']) is not None, 'Audit version digest differs.')
    return dict(artifact='AUDIT_PERMIT', policy=POLICY, public_payload_sha256=PUBLIC_SHA, context=context)


def verify_inputs(public, live, fabric, result, context, *, now=None):
    now = now or datetime.now(timezone.utc)
    binding(context)
    require(digest(public) == PUBLIC_SHA, 'Original publication required.')
    require_recent_gate(live, public, now)
    require(live['code_revision'] == context['code_revision'] and
        live['commitment_attempt_id'] == context['commitment_attempt_id'] and
        live['binding_artifact_sha256'] == context['binding_artifact_sha256'] and
        live['scope'] == SCOPE and live['max_age_seconds'] == 600 and
        live['historical_claims'] == 'UNASSESSED' and live['plan'] == publication_plan(public), 'Live evidence version differs.')
    checked = datetime.fromisoformat(live['checked_at'])
    completed = datetime.fromisoformat(live['completed_at'])
    require(checked <= completed <= now, 'Live evidence time order differs.')
    require(fabric['status'] == 'PASSED' and fabric['mode'] == 'RECONCILE' and
        fabric['code_revision'] == context['code_revision'] and fabric['public_payload_sha256'] == PUBLIC_SHA, 'Fabric runner differs.')
    f = fabric['fabric_result']
    require(f['status'] == 'PASSED' and f['mode'] == 'RECONCILE' and f['officers'] == 6596 and
        f['original_valid_transactions'] == 68 and f['two_organization_readback'] is True and
        f['classification'] == 'UNASSESSED' and f['public_payload_sha256'] == PUBLIC_SHA and
        f['batch_publication_id'] == public['batch_publication_id'] and f['merkle_root'] == public['merkle_root'], 'Full Fabric reconciliation required.')
    n = f['network']; g = n['genesis_identity']
    require(n['channel'] == 'personnel' and n['chaincode'] == 'officer-evidence-v1' and
        n['genesis_sha256'] == FABRIC_GENESIS and g['policy'] == 'FABRIC_GENESIS_HEADER_DATA_V1' and
        g['header_sha256'] == HEADER and g['data_sha256'] == DATA, 'Fabric network differs.')
    require(result['status'] == 'PASSED' and result['mode'] == 'RECONCILE' and
        result['code_revision'] == context['code_revision'], 'Public runner differs.')
    p = result['public_result']
    require(p['policy'] == 'SEPOLIA_RESEARCH_PUBLICATION_V1' and p['status'] == 'PASSED' and
        p['mode'] == 'RECONCILE' and p['code_revision'] == context['code_revision'] and
        p['officers'] == 6596 and p['original_valid_transactions'] == 68 and
        p['two_rpc_readback'] is True and p['finalized'] is True and
        p['research_publication_complete'] is True and p['submitted_transactions_this_run'] == 0 and
        p['classification'] == 'UNASSESSED', 'Full finalized public reconciliation required.')
    identity = dict(policy='SEPOLIA_PUBLICATION_TRANSACTION_V1', chain_id=11155111, genesis=GENESIS,
        contract=CONTRACT, deployment_transaction=DEPLOYMENT_TX, writer=WRITER, runtime_sha256=RUNTIME,
        config_sha256=CONFIG, batch='0x' + public['batch_publication_id'], public_payload_sha256=PUBLIC_SHA,
        merkle_root='0x' + public['merkle_root'])
    require(p['identity'] == identity, 'Public deployment or commitment version differs.')
    txs = p['transaction_hashes']
    require(isinstance(txs, list) and len(txs) == len(set(txs)) == 68 and
        all(isinstance(t, str) and re.fullmatch('0x[0-9a-f]{64}', t) for t in txs), 'Original transaction inventory differs.')
    require(isinstance(p['sealed_block'], str) and re.fullmatch('0x[0-9a-f]+', p['sealed_block']) and
        int(p['sealed_block'], 16) > 0 and re.fullmatch('0x[0-9a-f]{64}', p['sealed_block_hash']), 'Finalized seal block differs.')
    return dict(policy=POLICY, status='READY', context=context, scope=SCOPE,
        public_payload_sha256=PUBLIC_SHA, batch_publication_id=public['batch_publication_id'],
        merkle_root=public['merkle_root'], checked_at=live['checked_at'], issued_at=now.isoformat(),
        expires_at=(checked + timedelta(seconds=600)).isoformat(), classification='UNASSESSED',
        purpose='RESEARCH_AUDIT_OF_ANCHORED_SNAPSHOT', live_gate_sha256=digest(live),
        fabric_result_sha256=digest(fabric), public_result_sha256=digest(result),
        sealed_block=p['sealed_block'], sealed_block_hash=p['sealed_block_hash'],
        original_transaction_inventory_sha256=digest(txs))


def seal_permit(crypto, backup, permit):
    require(permit['policy'] == POLICY and permit['status'] == 'READY', 'Audit readiness required.')
    return seal_artifact(crypto, backup, permit, binding(permit['context']))


def require_audit_permit(envelope, crypto, backup, public, context, *, now=None):
    """Future audit entry points must call this against their exact selected evidence context."""
    now = now or datetime.now(timezone.utc)
    permit = open_artifact(crypto, envelope, binding(context))
    require(open_artifact(backup, envelope, binding(context)) == permit, 'Audit backup recovery differs.')
    require(permit['policy'] == POLICY and permit['status'] == 'READY' and permit['context'] == context and
        permit['scope'] == SCOPE and permit['public_payload_sha256'] == digest(public) == PUBLIC_SHA and
        permit['batch_publication_id'] == public['batch_publication_id'] and
        permit['merkle_root'] == public['merkle_root'] and permit['classification'] == 'UNASSESSED' and
        permit['purpose'] == 'RESEARCH_AUDIT_OF_ANCHORED_SNAPSHOT', 'Audit permit scope differs.')
    publication_plan(public)
    checked, issued, expires = (datetime.fromisoformat(permit[k]) for k in ('checked_at', 'issued_at', 'expires_at'))
    require(checked.tzinfo is not None and issued.tzinfo is not None and expires.tzinfo is not None and
        checked <= issued <= now < expires and expires == checked + timedelta(seconds=600), 'Audit permit expired or time differs.')
    return permit
