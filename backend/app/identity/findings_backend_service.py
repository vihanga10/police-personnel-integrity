"""Fixed Python-to-Node private-pipe orchestration; no API route or automatic retry."""
from copy import deepcopy
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity.findings_backend_gate import FindingsBackendGate, verify_approval
from app.identity import findings_commitments as C
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import encoded

LIMIT = 1048576


def _json(data):
    def unique(items):
        value = {}
        for key,item in items:
            require(key not in value, 'Duplicate backend pipe field.')
            value[key] = item
        return value
    return json.loads(data,object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite pipe value')))


def _exchange(command, job, guard, *, timeout=300):
    """Internal transport test boundary. Public entry fixes the command and guard.

    Any timeout/crash is an uncertain operation; preserve recovery files and
    obtain a new RECONCILE approval. Never rerun EXECUTE automatically.
    """
    require(type(timeout) is int and 1 <= timeout <= 600, 'Bounded backend deadline required.')
    deadline = time.monotonic()+timeout
    env = {'PATH':os.defpath,'LANG':'C.UTF-8','TZ':'UTC'}
    process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,env=env,bufsize=0,close_fds=True)
    selector = selectors.DefaultSelector(); selector.register(process.stdout,selectors.EVENT_READ)
    buffer = b''; expected_id = 1; result = None
    def send(value):
        data = encoded(value)+b'\n'
        require(len(data) <= LIMIT, 'Backend pipe frame too large.')
        # Bounded frames normally fit in the kernel pipe; write readiness prevents
        # a stalled child from trapping the backend on a large initial approval.
        writer = selectors.DefaultSelector(); writer.register(process.stdin,selectors.EVENT_WRITE)
        try:
            os.set_blocking(process.stdin.fileno(),False)
            offset = 0
            while offset < len(data):
                left = deadline-time.monotonic()
                require(left > 0 and writer.select(left), 'Backend pipe write timed out.')
                try:offset += os.write(process.stdin.fileno(),data[offset:])
                except BlockingIOError:continue
        finally:writer.close()
    try:
        send({'kind':'start','job':job})
        while result is None:
            left = deadline-time.monotonic()
            require(left > 0 and selector.select(left), 'Backend worker timed out; reconcile original attempt.')
            chunk = os.read(process.stdout.fileno(),65536)
            require(chunk, 'Backend worker stopped; reconcile original attempt.')
            buffer += chunk
            require(len(buffer) <= LIMIT, 'Backend pipe frame too large.')
            while b'\n' in buffer:
                line,buffer = buffer.split(b'\n',1)
                message = _json(line)
                require(type(message) is dict and type(message.get('kind')) is str, 'Backend pipe schema differs.')
                if message['kind'] == 'guard':
                    require(set(message) == {'kind','id','action','selection','mode'} and
                        type(message['id']) is int and message['id'] == expected_id,
                        'Backend guard order differs.')
                    try:
                        selected = guard(message['action'],message['selection'],message['mode'])
                    except Exception:
                        # Ordered denial is never approval. Let the worker unwind
                        # its owned session before terminating it. Hard deadlines
                        # and crashes still leave interrupted artifacts intact.
                        try:
                            send({'kind':'denied','id':expected_id})
                            process.stdin.close()
                            process.wait(timeout=min(3,max(0.001,deadline-time.monotonic())))
                        except Exception:
                            pass
                        raise
                    require(time.monotonic() < deadline, 'Backend approval response deadline passed.')
                    send({'kind':'approved','id':expected_id,'selection':selected}); expected_id += 1
                elif message['kind'] == 'result':
                    require(set(message) == {'kind','result'} and expected_id > 1 and not buffer,
                        'Backend result without verified guard or trailing data.')
                    result = message['result'];break
                else:raise ValueError('Backend worker rejected operation; reconcile original attempt.')
        require(process.wait(timeout=max(0.001,deadline-time.monotonic())) == 0,
                'Backend worker failed after result; reconcile original attempt.')
        require(not process.stdout.read(1), 'Unexpected trailing backend worker output.')
        return result
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        process.stdin.close();process.stdout.close()


def run_fabric(gate, *, approval, trusted_keys, node_binary, gateway_config_file,
        witness_config_file, witness_config_sha256, recovery_directory,
        recovery_key_file, timeout=300):
    """Trusted backend service only. RECONCILE is selected on gate construction.

    Configuration/trust comes from backend administration. No caller callback,
    SDK override, fixture witness or public-provider fallback is accepted here.
    """
    require(type(gate) is FindingsBackendGate, 'Configured full-replay backend gate required.')
    grant, keys, selected = deepcopy(approval),deepcopy(trusted_keys),gate.selection
    verify_approval(grant,keys,selected,gate.mode)
    gate.check('ENTRY',selected,gate.mode)
    recovery_root = C._root(recovery_directory,gate.repo)
    stores = (C._root(gate.directory,gate.repo),gate.findings.registry.root,gate.findings.registry.journal.root)
    require(all(not recovery_root.is_relative_to(p) and not p.is_relative_to(recovery_root) for p in stores),
            'Recovery storage must be separate from findings and commitment stores.')
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
    worker = gate.repo/'blockchain/fabric/client/findings-backend-worker.js'
    require(worker.is_file() and not any(p.is_symlink() for p in (worker,*worker.parents)),
            'Committed ordinary backend worker required.')
    public_keys = {name:Ed25519PublicKey.from_public_bytes(value).public_bytes(
        Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode() for name,value in keys.items()}
    job = dict(selection=selected,approval=grant,trustedKeys=public_keys,mode=gate.mode,
        repo=str(gate.repo),gatewayConfigFile=str(gateway_config_file),
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
    require(type(result) is dict and result.get('status') == 'FABRIC_COMMIT_VERIFIED' and
        result.get('mode') == gate.mode and result.get('operation') == digest_operation(selected) and
        result.get('recovery_witness_transport') == 'MTLS' and result.get('recovery_witness_fixture') is False and
        result.get('both_chains_anchored') is False and
        result.get('independent_witness_deployment_verified') is False,
        'Verified witnessed Fabric result required.')
    # Defense in depth: do not let any worker result change the approved payload.
    receipt = result.get('receipt',{})
    require(receipt.get('status') == 'FINAL' and receipt.get('payload') == selected['payload'] and
        receipt.get('destination') == selected['destination'] and
        receipt.get('verification',{}).get('validation_code') == 'VALID' and
        receipt.get('verification',{}).get('organizations') == ['Org1MSP','Org2MSP'],
        'Backend final receipt scope differs.')
    return dict(result,backend_gate='FULL_REPLAY_AND_WITNESSED_FINDINGS',
        public_transport_enabled=False,live_research_ready=False)


def digest_operation(selection):
    from app.identity.findings_backend_gate import POLICY
    from app.identity.protected_commitment import digest
    return digest(dict(policy=POLICY,selection=selection))
