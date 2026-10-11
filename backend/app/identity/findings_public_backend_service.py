"""Trusted private-pipe public bridge, with live transport explicitly disabled."""
from copy import deepcopy
from pathlib import Path
import os
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity.findings_backend_service import _exchange
from app.identity.findings_public_backend_gate import FindingsPublicBackendGate,verify_approval,POLICY
from app.identity import findings_commitments as C
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest


def run_public(gate, *, approval, trusted_keys, node_binary, network_config_file,
        witness_config_file, witness_config_sha256, recovery_directory,
        recovery_key_file, timeout=300):
    """Fixture-only public backend bridge. No live public runtime is provisioned.

    Configuration/trust comes from backend administration. No caller callback,
    SDK override, fixture witness or public-provider fallback is accepted here.
    """
    require(type(gate) is FindingsPublicBackendGate, 'Configured full-source public gate required.')
    grant, keys, selected = deepcopy(approval),deepcopy(trusted_keys),gate.selection
    verify_approval(grant,keys,selected,gate.mode)
    gate.check('ENTRY',selected,gate.mode)
    recovery_root = C._root(recovery_directory,gate.repo)
    stores = (C._root(gate.directory,gate.repo),gate.findings.registry.root,gate.findings.registry.journal.root)
    require(all(not recovery_root.is_relative_to(p) and not p.is_relative_to(recovery_root) for p in stores),
            'Recovery storage must be separate from findings and commitment stores.')
    fabric_root = C._root(gate.fabric.options['recovery_directory'],gate.repo)
    require(not recovery_root.is_relative_to(fabric_root) and not fabric_root.is_relative_to(recovery_root),
            'Separate Fabric/public recovery stores required.')
    key_path = Path(recovery_key_file).expanduser().absolute()
    C._root(key_path.parent,gate.repo)
    require(not key_path.is_symlink() and key_path.is_file() and key_path.stat().st_uid == os.getuid() and
        key_path.stat().st_nlink == 1 and key_path.stat().st_mode & 0o077 == 0,
        'Private dedicated recovery key file required.')
    raw_key = key_path.read_bytes();gate.check_recovery_key(raw_key)
    binary = Path(node_binary)
    require(binary.is_absolute() and binary.is_file() and os.access(binary,os.X_OK),
            'Configured absolute Node executable required.')
    # Fixed committed worker; nothing is chosen from a request or command string.
    worker = gate.repo/'blockchain/public/findings/findings-public-backend-worker.js'
    require(worker.is_file() and not any(p.is_symlink() for p in (worker,*worker.parents)),
            'Committed ordinary backend worker required.')
    public_keys = {name:Ed25519PublicKey.from_public_bytes(value).public_bytes(
        Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode() for name,value in keys.items()}
    job = dict(selection=selected,approval=grant,trustedKeys=public_keys,mode=gate.mode,
        repo=str(gate.repo),networkConfigFile=str(network_config_file),
        witnessConfigFile=str(witness_config_file),witnessConfigSha256=witness_config_sha256,
        directory=str(recovery_root),recoveryKeyFile=str(key_path))
    def guard(action,selection,mode):
        verify_approval(grant,keys,selected,gate.mode)
        current = gate.check(action,selection,mode)
        require(not key_path.is_symlink() and key_path.is_file() and key_path.stat().st_uid == os.getuid() and
            key_path.stat().st_nlink == 1 and key_path.stat().st_mode & 0o077 == 0 and key_path.read_bytes() == raw_key,
            'Backend recovery key changed.')
        gate.check_recovery_key(raw_key)
        verify_approval(grant,keys,selected,gate.mode)
        return current
    result = _exchange([str(binary),str(worker)],job,guard,timeout=timeout)
    guard('RETURN',selected,gate.mode)
    require(type(result) is dict and result.get('status') in ('ISOLATED_PUBLIC_VERIFIED','PENDING') and
        result.get('mode')==gate.mode and result.get('operation')==digest(dict(policy=POLICY,selection=selected)) and
        result.get('recovery_witness_transport')=='MTLS' and result.get('recovery_witness_fixture') is False and
        result.get('backend_public_runtime')=='FIXTURE_ONLY' and result.get('live_chain_verification') is False and
        result.get('public_transport_enabled') is False and result.get('both_chains_anchored') is False and
        result.get('independent_witness_deployment_verified') is False,'Isolated witnessed public result required.')
    receipt=result.get('receipt',{})
    transaction=receipt.get('transaction_id')
    require(type(transaction) is str and re.fullmatch('0x[0-9a-f]{64}',transaction),'Original public transaction hash required.')
    if result['status']=='ISOLATED_PUBLIC_VERIFIED':
        require(set(receipt)=={'status','destination','payload','transaction_id','verification'} and receipt['status']=='FINAL' and
            receipt['destination']==selected['destination'] and receipt['payload']==selected['payload'],
            'Original public receipt scope differs.')
        v=receipt['verification']
        require(type(v) is dict and set(v)=={'execution_status','finalized','independent_readback','block_sha256'} and
            type(v['execution_status']) is int and v['execution_status']==1 and v['finalized'] is True and
            v['independent_readback'] is True and type(v['block_sha256']) is str and re.fullmatch('[0-9a-f]{64}',v['block_sha256']),
            'Fixture public verification differs.')
    else:
        require(set(receipt)=={'status','reason','transaction_id'} and receipt['status']=='PENDING' and
            receipt['reason'] in ('BOTH_ORIGINAL_RECEIPTS_REQUIRED','FINALITY_AND_CONFIRMATIONS_REQUIRED'),
            'Explicit pending public state required.')
    return dict(result,backend_gate='FULL_SOURCE_AND_FRESH_FABRIC',
        public_finality_simulated=True,provider_independence_verified=False,live_research_ready=False)
