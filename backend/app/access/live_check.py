"""Operator-enabled, READ-ONLY live check of one officer's ORIGINAL anchor on Fabric and Sepolia.

The reviewed Node script asks both Fabric organizations' peers (reader identity) and the Sepolia contract (view calls) for the
officer's commitment and the batch root, right now. It never signs or submits a transaction; this module refuses any result that
claims otherwise. Only public identifiers and stored commitments go in; no key material, path or raw error comes back.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading

from app.access.policy import AccessError, require
from app.access.store import private

POLICY = 'LIVE_CHAIN_CHECK_V1'
SCRIPT = 'blockchain/public/live-original-check.js'
FIELDS = {'policy', 'fabric_gateway_config', 'fabric_gateway_sha256', 'sepolia_network_config', 'sepolia_network_sha256'}
HEX64 = re.compile(r'^[0-9a-f]{64}$')
TIMEOUT_SECONDS = 90
_busy = threading.Lock()


def configured(file, repo):
    """Validated live-check configuration, or raises. The two chain configurations are pinned by SHA-256."""
    path = private(file, repo=repo)
    config = json.loads(path.read_text())
    require(type(config) is dict and set(config) == FIELDS and config['policy'] == POLICY, 'Live check configuration differs')
    for name in ('fabric_gateway_sha256', 'sepolia_network_sha256'):
        require(type(config[name]) is str and HEX64.fullmatch(config[name]), 'Live check pin differs')
    for name in ('fabric_gateway_config', 'sepolia_network_config'):
        require(type(config[name]) is str and Path(config[name]).is_absolute(), 'Live check path differs')
        private(config[name], repo=repo)
    return config


def build_job(config, entry, meta):
    """Public identifiers and stored commitments only."""
    block = meta['sepolia_sealing_block']
    return {'batch': meta['batch_publication_id'], 'handle': entry['publication_id'], 'commitment': entry['commitment'],
            'merkle_root': meta['merkle_root'], 'contract': meta['sepolia_contract'], 'chain_id': meta['sepolia_chain_id'],
            'sealing_block': int(block, 16) if isinstance(block, str) else int(block), 'officers': meta['officers'],
            'fabric_config': config['fabric_gateway_config'], 'fabric_sha256': config['fabric_gateway_sha256'],
            'network_config': config['sepolia_network_config'], 'network_sha256': config['sepolia_network_sha256']}


def run_node(repo, job):
    node = shutil.which('node')
    if node is None:
        raise AccessError(503, 'LIVE_CHECK_UNAVAILABLE')
    repo = Path(repo)
    env = {'PATH': os.environ.get('PATH', ''), 'NODE_PATH': str(repo / 'blockchain/fabric/integration/node_modules')}
    try:
        done = subprocess.run([node, str(repo / SCRIPT)], input=json.dumps(job), capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                              cwd=repo / 'blockchain/public', env=env)
    except subprocess.TimeoutExpired:
        raise AccessError(504, 'LIVE_CHECK_TIMEOUT') from None
    if len(done.stdout) > 65536:
        raise AccessError(502, 'LIVE_CHECK_FAILED')
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except Exception:
        raise AccessError(502, 'LIVE_CHECK_FAILED') from None


def vet(result):
    """Defence in depth: a live check that was not read-only, or has an unexpected shape, is never shown."""
    ok = (type(result) is dict and result.get('policy') == 'ORIGINAL_ANCHOR_LIVE_CHECK_V1' and result.get('read_only') is True
          and result.get('transactions_submitted') == 0 and type(result.get('passed')) is bool)
    if not ok:
        raise AccessError(502, 'LIVE_CHECK_FAILED')
    if 'error' in result and 'fabric' not in result:
        raise AccessError(502, 'LIVE_CHECK_FAILED')
    for chain in ('fabric', 'sepolia'):
        part = result.get(chain)
        if type(part) is not dict or part.get('status') not in ('READ', 'UNAVAILABLE'):
            raise AccessError(502, 'LIVE_CHECK_FAILED')
    return result


def verdict(result):
    parts = (result['fabric'], result['sepolia'])
    if any(p['status'] == 'UNAVAILABLE' for p in parts):
        return 'UNAVAILABLE'
    return 'PASSED' if result['passed'] and all(p.get('passed') is True for p in parts) else 'FAILED'


def check(config, repo, entry, meta, *, runner=None):
    """One check at a time: the public RPC and the local peers are never hammered."""
    if not _busy.acquire(blocking=False):
        raise AccessError(429, 'LIVE_CHECK_BUSY')
    try:
        result = vet((runner or run_node)(repo, build_job(config, entry, meta)))
    finally:
        _busy.release()
    return {'basis': 'FRESH_READ_NOW', 'overall': verdict(result), 'checked_at': result.get('checked_at'), 'fabric': result['fabric'], 'sepolia': result['sepolia'],
            'transactions_submitted': 0,
            'limits': ['A passing check shows the chains currently return the stored commitment for this officer; it does not show the record is true.',
                       'The checkpoint chain and uploaded batches are not covered by this check.']}
