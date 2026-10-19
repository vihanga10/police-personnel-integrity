"""Live mismatch, publication privacy, cross-language payloads and VALID receipt gates."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import subprocess

import pytest
from app.identity.anchor_gate import compare_live, publication_plan, require_recent_gate, verify_fabric_receipt, POLICY
from app.identity.protected_commitment import digest, merkle_root


def public_fixture():
    rows = [dict(publication_id='%064x' % (i+1), commitment_version=1, commitment='%064x' % (i+10000)) for i in range(6596)]
    payload = dict(policy='OFFICER_PROTECTED_COMMITMENT_V1', commitment_version=1, key_version='commit-v1',
                   batch_publication_id='%064x' % 80000, officers=rows, shared_commitment='%064x' % 80001,
                   coverage_commitment='%064x' % 80002, batch_commitment='%064x' % 80003)
    leaves = [dict(kind='OFFICER', **r) for r in rows] + [dict(kind='BATCH', publication_id=payload['batch_publication_id'], commitment=payload['batch_commitment'])]
    payload['merkle_root'] = merkle_root(leaves)
    return payload


@pytest.mark.parametrize('field', ['policy', 'raw_bindings', 'officer_bindings', 'shared_bindings', 'sql_records', 'mongo_documents'])
def test_any_live_version_difference_stops_gate(field):
    captured = dict(policy='fixture', raw_bindings={'raw': ['fingerprint']}, officer_bindings={'officer': []},
                    shared_bindings=['shared'], sql_records=2, mongo_documents=1, sql_table_counts={'fixture': 2})
    live = {k: deepcopy(v) for k, v in captured.items() if k != 'sql_table_counts'}
    compare_live(captured, live, {'fixture': 2})
    live[field] = 'changed'
    with pytest.raises(ValueError): compare_live(captured, live, {'fixture': 2})


def test_live_count_match_alone_does_not_establish_integrity():
    captured = dict(policy='fixture', raw_bindings={'raw': ['original']}, officer_bindings={}, shared_bindings=[],
                    sql_records=1, mongo_documents=0, sql_table_counts={'fixture': 1})
    live = dict(captured, raw_bindings={'raw': ['changed']})
    with pytest.raises(ValueError): compare_live(captured, live, {'fixture': 1})
    with pytest.raises(ValueError): compare_live(captured, captured, {'fixture': 2})


def test_publication_plan_contains_every_officer_and_matches_canonical_digest():
    public = public_fixture(); plan = publication_plan(public)
    assert len(plan['chunks']) == 66 and plan['transaction_count'] == 68
    assert plan['chunks'][-1]['index'] == 65 and len(plan['chunks'][-1]['records']) == 96
    assert [r for c in plan['chunks'] for r in c['records']] == public['officers']
    assert plan['metadata']['public_payload_sha256'] == digest(public)
    assert all(c['records_sha256'] == digest(c['records']) for c in plan['chunks'])


@pytest.mark.parametrize('kind', ['missing_officer', 'duplicate', 'reordered', 'extra_personal_field', 'root', 'version'])
def test_invalid_publication_cannot_be_planned(kind):
    public = public_fixture()
    if kind == 'missing_officer': public['officers'].pop()
    elif kind == 'duplicate': public['officers'][1] = deepcopy(public['officers'][0])
    elif kind == 'reordered': public['officers'].reverse()
    elif kind == 'extra_personal_field': public['officers'][0]['nic'] = '123456789V'
    elif kind == 'root': public['merkle_root'] = 'f'*64
    elif kind == 'version': public['commitment_version'] = True
    with pytest.raises(ValueError): publication_plan(public)


@pytest.mark.parametrize('minutes', [-1, 0, 9, 10, 11])
def test_gate_freshness_has_fixed_limit(minutes):
    public = public_fixture(); now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    gate = dict(policy=POLICY, status='PASSED', checked_at=(now-timedelta(minutes=minutes)).isoformat(), public_payload_sha256=digest(public))
    if 0 <= minutes <= 10: require_recent_gate(gate, public, now)
    else:
        with pytest.raises(ValueError): require_recent_gate(gate, public, now)
    gate['public_payload_sha256'] = 'f'*64
    with pytest.raises(ValueError): require_recent_gate(gate, public, now)


@pytest.mark.parametrize('kind', ['valid', 'validation_code', 'successful', 'block', 'tx', 'payload', 'channel', 'network', 'chaincode', 'one_peer', 'peer_mismatch', 'different_valid_tx'])
def test_receipt_requires_valid_status_and_two_peer_readback(kind):
    expected = dict(commitment='a'*64, transaction_id='b'*64)
    receipt = dict(network_id='research-net', channel='personnel', chaincode='officer-evidence',
                   validation_code=0, successful=True, block_number=9, transaction_id='b'*64, payload_sha256=digest(expected))
    observed = {'Org1MSP': expected, 'Org2MSP': expected}
    changes = dict(validation_code=11, successful=False, block=-1, tx='not-a-transaction', payload='f'*64,
                   channel='different', network='other-net', chaincode='other-chaincode')
    names = {'block': 'block_number', 'tx': 'transaction_id', 'payload': 'payload_sha256', 'network': 'network_id'}
    if kind in changes: receipt[names.get(kind, kind)] = changes[kind]
    if kind == 'different_valid_tx': receipt['transaction_id'] = 'c'*64
    if kind == 'one_peer': observed.pop('Org2MSP')
    if kind == 'peer_mismatch': observed['Org2MSP'] = dict(commitment='c'*64)
    kwargs = dict(network_id='research-net', channel='personnel', chaincode='officer-evidence', observed_by_peer=observed)
    if kind == 'valid': assert verify_fabric_receipt(receipt, expected, **kwargs)
    else:
        with pytest.raises(ValueError): verify_fabric_receipt(receipt, expected, **kwargs)


def test_python_publication_digest_and_merkle_tree_match_chaincode():
    repo = Path(__file__).resolve().parents[2]
    core = repo/'blockchain/fabric/chaincode/lib/evidence.js'
    if not core.exists():
        # Verification overlay has the staged package in its parent workspace.
        core = repo.parent/'fabric-foundation-step/blockchain/fabric/chaincode/lib/evidence.js'
    public = public_fixture()
    script = '''const fs=require('node:fs'); const {sha,tree}=require(process.argv[1]);
const p=JSON.parse(fs.readFileSync(0,'utf8'));
const leaves=p.officers.map(r=>({kind:'OFFICER',...r}));
leaves.push({kind:'BATCH',publication_id:p.batch_publication_id,commitment:p.batch_commitment});
process.stdout.write(JSON.stringify({digest:sha(p),root:tree(leaves)}));'''
    result = subprocess.run(['node', '-e', script, str(core)], input=json.dumps(public), text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == dict(digest=digest(public), root=public['merkle_root'])


def test_docker_preflight_uses_only_read_commands_and_does_not_print_secrets():
    from scripts.check_fabric_prerequisites import check
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if command == ['node', '--version']: return 'v24.21.0'
        if command[:2] == ['docker', 'version']: return json.dumps({'Server': {'Version': '29.6.2'}})
        if command[:3] == ['docker', 'compose', 'version']: return '5.3.1'
        return json.dumps({'OSType': 'linux', 'Architecture': 'aarch64', 'MemTotal': 8*1024**3, 'Name': 'private-user', 'HTTPProxy': 'secret'})
    result = check(run)
    assert result['docker_memory_gib'] == 8 and result['docker_architecture'] == 'aarch64'
    assert 'private-user' not in json.dumps(result) and 'secret' not in json.dumps(result)
    assert all(c[:2] in [['node', '--version'], ['docker', 'version'], ['docker', 'compose'], ['docker', 'info']] for c in calls)


def test_saved_commitment_replay_uses_authenticated_original_revision_after_git_advances(tmp_path, monkeypatch):
    import base64
    from app.identity import check_live_anchor_gate as gate
    from app.identity.evidence_bundle_v2 import seal_artifact
    from app.intake.registration_receipt import save_receipt
    from app.security.identity_crypto import IdentityCrypto
    public = public_fixture(); original = 'c'*40
    keyfile = tmp_path/'keys.json'
    keyfile.write_text(json.dumps(dict(active_encryption_key_version='enc', active_lookup_key_version='lookup',
        encryption_keys={'enc': base64.b64encode(b'E'*32).decode()}, lookup_keys={'lookup': base64.b64encode(b'L'*32).decode()})))
    keyfile.chmod(0o600); crypto = IdentityCrypto(keyfile)
    directory = tmp_path/'commitments'; directory.mkdir(mode=0o700)
    bundle_directory = tmp_path/'bundle'; binding_directory = tmp_path/'binding'
    private = dict(context=dict(generator_revision=original), public=public,
                   bundle_attempt_id='bundle', binding_attempt_id='binding', binding_artifact_sha256='f'*64)
    binding = dict(artifact='PROTECTED_COMMITMENTS', policy='OFFICER_PROTECTED_COMMITMENT_V1', context=private['context'])
    summary = dict(policy='OFFICER_PROTECTED_COMMITMENT_V1', status='PASSED', officers=6596, source_rows=167865,
                   sql_records=794200, mongo_documents=154673, code_revision=original, public_payload_sha256=digest(public))
    save_receipt(summary, directory/'PASSED.json')
    save_receipt(public, directory/'public-commitments.json')
    save_receipt(seal_artifact(crypto, crypto, private, binding), directory/'commitments.encrypted.json')
    def frozen_generator(*args, **kwargs):
        assert kwargs['generator_revision'] == original
        return public, dict(context=private['context'], public=public)
    monkeypatch.setattr(gate, 'generate', frozen_generator)
    restored, plan = gate.authenticate_commitments(directory, {}, {}, {}, 'f'*64, bundle_directory,
                                                   binding_directory, crypto, crypto, None)
    assert restored == public and plan['chunk_count'] == 66
    damaged = json.loads((directory/'public-commitments.json').read_text())
    damaged['officers'][0]['commitment'] = 'f'*64
    (directory/'public-commitments.json').write_text(json.dumps(damaged))
    with pytest.raises(ValueError): gate.authenticate_commitments(directory, {}, {}, {}, 'f'*64, bundle_directory,
                                                                binding_directory, crypto, crypto, None)
