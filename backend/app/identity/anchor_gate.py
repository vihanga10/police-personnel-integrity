"""Compare captured versions and plan publication; never infer live readiness from counts alone."""
from datetime import datetime, timezone, timedelta
import re

from app.identity.destination_binding import require
from app.identity.protected_commitment import POLICY as COMMITMENT_POLICY, digest, merkle_root

POLICY = 'LIVE_EVIDENCE_ANCHOR_GATE_V1'
HEX = re.compile(r'[0-9a-f]{64}')
CORE = ('policy', 'raw_bindings', 'officer_bindings', 'shared_bindings', 'sql_records', 'mongo_documents')
BATCH_SIZE = 100


def compare_live(captured, live, counts):
    require(all(captured.get(name) == live.get(name) for name in CORE), 'Live evidence fingerprint inventory differs.')
    require(captured['sql_table_counts'] == counts, 'Live SQL scope differs.')


def publication_plan(public):
    require(set(public) == {'policy', 'commitment_version', 'key_version', 'batch_publication_id', 'officers',
                           'shared_commitment', 'coverage_commitment', 'batch_commitment', 'merkle_root'}, 'Publication fields differ.')
    require(public['policy'] == COMMITMENT_POLICY and type(public['commitment_version']) is int and
            public['commitment_version'] == 1 and public['key_version'] == 'commit-v1', 'Publication policy differs.')
    for name in ('batch_publication_id', 'shared_commitment', 'coverage_commitment', 'batch_commitment', 'merkle_root'):
        require(isinstance(public[name], str) and HEX.fullmatch(public[name]), 'Publication digest differs.')
    rows = public['officers']
    require(len(rows) == 6596, 'All 6,596 officer commitments required.')
    for row in rows:
        require(set(row) == {'publication_id', 'commitment_version', 'commitment'} and
                type(row['commitment_version']) is int and row['commitment_version'] == 1 and
                HEX.fullmatch(row['publication_id']) and HEX.fullmatch(row['commitment']), 'Officer publication shape differs.')
    require(rows == sorted(rows, key=lambda r: r['publication_id']) and
            len({r['publication_id'] for r in rows}) == len({r['commitment'] for r in rows}) == 6596,
            'Officer order or uniqueness differs.')
    leaves = [dict(kind='OFFICER', **r) for r in rows] + [dict(kind='BATCH', publication_id=public['batch_publication_id'], commitment=public['batch_commitment'])]
    require(merkle_root(leaves) == public['merkle_root'], 'Publication Merkle root differs.')
    metadata = {k: v for k, v in public.items() if k != 'officers'}
    metadata.update(officer_count=6596, public_payload_sha256=digest(public))
    chunks = [dict(index=i//BATCH_SIZE, records=rows[i:i+BATCH_SIZE], records_sha256=digest(rows[i:i+BATCH_SIZE]))
              for i in range(0, len(rows), BATCH_SIZE)]
    return dict(policy=POLICY, metadata=metadata, chunks=chunks, officer_count=len(rows),
                chunk_count=len(chunks), transaction_count=len(chunks)+2)


def require_recent_gate(gate, public, now=None):
    """Future submitters must authenticate the encrypted gate before checking its age."""
    now = now or datetime.now(timezone.utc)
    created = datetime.fromisoformat(gate['checked_at'])
    require(created.tzinfo is not None and now.tzinfo is not None, 'Gate timestamp requires timezone.')
    require(gate['policy'] == POLICY and gate['status'] == 'PASSED' and
            gate['public_payload_sha256'] == digest(public), 'Live gate publication binding differs.')
    require(timedelta(0) <= now-created <= timedelta(minutes=10), 'Live evidence gate expired or timestamp is future.')


def verify_fabric_receipt(receipt, expected, *, network_id, channel, chaincode, observed_by_peer):
    """Require VALID commit status and exact independent peer readback, not an endorsement result.

    Inputs must come from authenticated Gateway/peer connections. A pasted JSON receipt
    does not authenticate a Fabric network. Real acquisition belongs to the adapter.
    """
    require(receipt['network_id'] == network_id and receipt['channel'] == channel and
            receipt['chaincode'] == chaincode, 'Fabric receipt network binding differs.')
    require(type(receipt['validation_code']) is int and receipt['validation_code'] == 0 and
            receipt['successful'] is True and type(receipt['block_number']) is int and
            receipt['block_number'] >= 0 and HEX.fullmatch(receipt['transaction_id']), 'Fabric transaction not VALID.')
    require(set(observed_by_peer) == {'Org1MSP', 'Org2MSP'} and
            all(value == expected for value in observed_by_peer.values()), 'Fabric peer readback differs.')
    require(receipt['payload_sha256'] == digest(expected) and expected.get('transaction_id') == receipt['transaction_id'],
            'Fabric receipt payload or original write transaction differs.')
    return True
