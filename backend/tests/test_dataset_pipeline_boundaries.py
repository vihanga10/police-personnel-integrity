"""Cross-language registry pins and the real HTTP boundary for dataset intake."""
import base64
import json
import subprocess
import pytest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from app.intake.dataset_pipeline.registry import DATASETS, CODES
from app.intake.dataset_pipeline.core import publication, expected_public, FABRIC_POLICY, PUBLIC_POLICY, NAMESPACE
from app.intake.dataset_pipeline.configuration import source_files
from test_dataset_pipeline import d, published, review, row, transfer, csv_bytes, NIC  # noqa: F401
from test_promotion_approvals import e  # noqa: F401
from test_promotion_analysis import connected  # noqa: F401
from test_priority2_workflows import env  # noqa: F401

REPO = Path(__file__).resolve().parents[2]


def test_chaincode_dataset_whitelist_matches_the_python_registry_exactly():
    codes = json.loads((REPO / 'blockchain/fabric/intake-chaincode/lib/datasets.json').read_text())
    assert sorted(codes) == sorted(CODES) and len(codes) == len(DATASETS) == 18


def test_python_payloads_pass_the_real_chaincode_and_contract_validators():
    batch = {'batch_id': str(uuid4()), 'dataset': 'COURT_CASES', 'file_sha256': 'a' * 64, 'received_at': '2026-10-17T00:00:00+00:00',
             'actor': {'user_id': str(uuid4()), 'username': 'research.hq', 'account_version': 1}, 'source_reference': 'HQ/FIXTURE',
             'source_system': 'PF_REGISTRY', 'rows': [{'row': 1, 'status': 'READY', 'subjects': [], 'source': {'court_no': 'C-1'}}]}
    payload, _ = publication(b'k' * 32, batch)
    fabric = {'status': 'FINAL', 'payload': payload, 'transaction_id': 'b' * 64, 'destination': {'chaincode': NAMESPACE}}
    public = expected_public(payload, {'fabric': fabric})
    assert payload['policy'] == FABRIC_POLICY and public['policy'] == PUBLIC_POLICY and public['dataset'] == 'COURT_CASES'
    script = ("const {validate,canonical}=require(process.argv[1]);const {argumentsFor}=require(process.argv[2]);"
              "const [f,p]=JSON.parse(process.argv[3]);validate(f);const a=argumentsFor(p);"
              "console.log(JSON.stringify({canonical:canonical(f),dataset:a[1]}));")
    node_path = Path.home() / 'Developer/police-personnel-integrity/blockchain/public/node_modules'
    result = subprocess.run(['node', '-e', script, str(REPO / 'blockchain/fabric/intake-chaincode/lib/intake.js'),
                             str(REPO / 'blockchain/public/intake/payload.js'), json.dumps([payload, public])],
                            capture_output=True, text=True, env={'NODE_PATH': str(node_path), 'PATH': '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin'})
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert json.loads(out['canonical']) == payload
    assert bytes.fromhex(out['dataset'][2:]).rstrip(b'\0').decode() == 'COURT_CASES'


def test_source_pins_cover_intake_chaincode_contract_worker_and_shared_dependencies():
    files = set(source_files(REPO))
    for required in ('blockchain/fabric/intake-chaincode/lib/intake.js', 'blockchain/fabric/intake-chaincode/lib/datasets.json',
                     'blockchain/public/intake/contracts/PersonnelIntakeAnchor.sol', 'blockchain/public/intake/application-anchor-worker.js',
                     'blockchain/fabric/client/intake-gateway.js', 'blockchain/fabric/client/promotions-block.js',
                     'backend/app/intake/dataset_pipeline/acceptance.py'):
        assert required in files, required
    assert not any('/test/' in f for f in files)


def test_real_http_boundary_hq_cannot_review_and_igp_review_is_origin_bound(d):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from app.access.api import COOKIE, RequestBoundary, _json_object
    from app.access.policy import AccessError
    from app.intake.dataset_pipeline.http import register
    from test_scoped_access_api import Client
    app = FastAPI()

    @app.exception_handler(AccessError)
    async def denied(request, error):
        return JSONResponse({'error': error.code}, status_code=error.status)

    async def read(request, fields):
        value = json.loads(await request.body(), object_pairs_hook=_json_object)
        if set(value) != fields:
            raise AccessError(400, 'INVALID_REQUEST')
        return value
    runtime = SimpleNamespace(service=d['dataset'], check_pins=lambda: None, errors={})
    register(app, runtime, lambda request: request.cookies.get(COOKIE), read)
    client = Client(RequestBoundary(app, 'https://access.test:9443'))
    s = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    item = s['row_acceptance'][0]
    body = dict(batch_id=s['batch_id'], row=1, operation_id=str(uuid4()), expected_version=0, decision='ACCEPT',
                reason='Signed transfer order inspected', evidence_reference='HQ/TRF/1', evaluation_reference=item['evaluation_reference'])
    client.cookie, client.csrf = COOKIE + '=' + d['hq'][0], d['hq'][1]
    assert client.request('/api/research/intake/review', 'POST', body)[0] == 403
    code, _, caps = client.request('/api/research/intake/capabilities')
    assert code == 200 and caps['can_upload'] and not caps['can_approve'] and len(caps['datasets']) == 18
    client.cookie, client.csrf = COOKIE + '=' + d['igp'][0], d['igp'][1]
    assert client.request('/api/research/intake/review', 'POST', body, origin='https://evil.test')[0] == 403
    code, _, result = client.request('/api/research/intake/review', 'POST', body)
    assert code == 200 and result['row_acceptance'][0]['status'] == 'ACCEPTED'
    code, _, listing = client.request('/api/research/intake/datasets/TRANSFER_HISTORY/batches/0')
    assert code == 200 and listing['items'][0]['batch_id'] == s['batch_id']
    assert client.request('/api/research/intake/datasets/NOT_A_DATASET/batches/0')[0] == 404
    assert client.request('/api/research/intake/datasets/TRANSFER_HISTORY/batches/x')[0] == 400
    from app.access.accountability import action_for
    assert action_for('/api/research/intake/datasets/TRANSFER_HISTORY/batches/0') == 'DATASET_IMPORT_BATCHES'
    code, _, rows = client.request('/api/research/intake/officers/' + s['rows'][0]['officer_uid'])
    assert code == 200 and rows['current']['projection']['posting']['to_station_code'] == 'ST-002'


def test_upload_history_lists_record_type_times_stages_and_no_row_values(d):
    from app.access.upload_history import history
    s = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    review(d, s)
    s2 = published(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2011')])
    result = history([(None, d['dataset_store'], d['dataset_engine'], d['dataset_analysis'])])
    assert result['total'] == 2 and result['record_types'] == {'Education': 1, 'Transfers': 1}
    newest, older = result['items']
    assert (newest['record_type'], older['record_type']) == ('EDUCATION', 'TRANSFER_HISTORY')
    stages = [e['stage'] for e in older['events']]
    for required in ('UPLOAD_PREVIEW_RETAINED', 'SUBMITTED_FOR_IGP_APPROVAL', 'IGP_APPROVED_PROCESSING', 'BOTH_CHAINS_VERIFIED',
                     'CONNECTED_TO_ANALYSIS', 'ROW_EVALUATED', 'ROW_REVIEWED'):
        assert required in stages, required
    times = [e['at'] for e in older['events']]
    from datetime import datetime
    assert times == sorted(times, key=lambda t: datetime.fromisoformat(t).timestamp())
    assert older['uploader']['username'] == 'station.one' and older['rows'] == {'total': 1, 'ready': 1, 'duplicate': 0, 'needs_review': 0}
    assert older['acceptance']['ACCEPTED'] == 1 and older['current_stage'] in ('ROW_EVALUATED', 'ROW_REVIEWED')
    blob = json.dumps(result)
    assert NIC not in blob and 'Kandy' not in blob and 'ST-002' not in blob


def _fake_original(store, officer, officers=5, tamper=False):
    import hashlib
    from app.intake.dataset_pipeline import merkle_proof as M
    leaves = [hashlib.sha256(('officer-%d' % i).encode()).digest() for i in range(officers)]
    nodes = [M.leaf_node(x) for x in leaves]
    entry = {'publication_id': 'a' * 64, 'commitment': 'b' * 64, 'leaf_index': 2, 'leaf_sha256': nodes[2].hex(), 'proof': M.proof(nodes, 2)}
    if tamper:
        entry['leaf_sha256'] = nodes[3].hex()
    meta = {'policy': 'OFFICER_PROTECTED_COMMITMENT_V1', 'key_version': 'commit-v1', 'merkle_root': M.root(nodes), 'batch_publication_id': 'c' * 64,
            'batch_commitment': 'd' * 64, 'public_payload_sha256': 'e' * 64, 'officers': 1, 'leaves': officers,
            'sepolia_contract': '0x' + '1' * 40, 'sepolia_chain_id': 11155111, 'sepolia_sealing_block': '0x1', 'sepolia_sealing_block_hash': '0x2',
            'fabric_channel': 'personnel', 'fabric_chaincode': 'officer-evidence-v1', 'verified_on': '2026-10-09', 'verification_basis': 'TEST'}
    store.install_original_commitments(meta, {officer: entry})
    return meta


def test_merkle_proofs_equal_the_production_tree_for_many_sizes():
    import hashlib
    from app.intake.dataset_pipeline import merkle_proof as M
    from app.intake.promotion_pipeline.core import merkle
    for n in (1, 2, 3, 5, 8, 13, 100):
        leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]
        nodes = [M.leaf_node(bytes.fromhex(x)) for x in leaves]
        assert M.root(nodes) == merkle(leaves)
        assert all(M.fold(nodes[i], M.proof(nodes, i)) == merkle(leaves) for i in range(n))
    assert M.fold(M.leaf_node(b'x' * 32), M.proof(nodes, 0)) != merkle(leaves)


def test_officer_integrity_shows_uploads_inclusion_and_a_checkpoint_chain(d):
    from app.access.officer_integrity import officer_integrity
    from research_workspace_fixture import identifier
    empty = officer_integrity(d['service'], identifier(1))
    assert empty['uploads'] == [] and empty['original'] is None and empty['checkpoint_chain']['length'] == 0
    assert empty['checkpoint_chain']['head'] == '0' * 64
    s1 = published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    one = officer_integrity(d['service'], identifier(1))
    assert len(one['uploads']) == 1 and one['all_recomputed_checks_passed'] is True
    up = one['uploads'][0]
    assert up['record_type'] == 'TRANSFER_HISTORY' and up['root_matches_published'] and up['all_rows_included'] and up['rows_for_officer'][0]['included']
    assert up['fabric_transaction_id'] == 'b' * 64 and up['batch_id'] == s1['batch_id']
    assert one['checkpoint_chain']['length'] == 1 and one['checkpoint_chain']['links'][0]['previous'] == '0' * 64
    s2 = published(d, 'officer_education.csv', [row('officer_education.csv', officer_nic_no=NIC, ol_year='2012')])
    two = officer_integrity(d['service'], identifier(1))
    links = two['checkpoint_chain']['links']
    assert [l['record_type_label'] for l in links] == ['Transfers', 'Education'] and links[1]['previous'] == links[0]['hash']
    assert two['checkpoint_chain']['head'] == links[1]['hash'] != one['checkpoint_chain']['head']
    assert officer_integrity(d['service'], identifier(1))['checkpoint_chain'] == two['checkpoint_chain']
    assert NIC not in json.dumps(two) and 'Kandy' not in json.dumps(two)


def test_original_fingerprint_is_shown_and_a_wrong_proof_is_flagged(d):
    from app.access.officer_integrity import officer_integrity
    from research_workspace_fixture import identifier
    meta = _fake_original(d['dataset_store'], identifier(1))
    view = officer_integrity(d['service'], identifier(1))
    assert view['original_available'] and view['original']['inclusion_verified'] and view['original']['merkle_root'] == meta['merkle_root']
    assert view['original']['commitment'] == 'b' * 64 and view['all_recomputed_checks_passed']
    assert view['checkpoint_chain']['genesis'] == view['original']['leaf_sha256']
    assert view['original']['anchors'] is None
    receipts = {'batch_publication_id': 'c' * 64, 'merkle_root': meta['merkle_root'], 'chunk_size': 100,
                'fabric': {**{'chunk-%03d' % i: {'transaction_id': '%064x' % i, 'block_number': 10 + i, 'validation_code': 0} for i in range(66)},
                           'batch': {'transaction_id': 'f' * 64, 'block_number': 5, 'validation_code': 0},
                           'seal': {'transaction_id': 'e' * 64, 'block_number': 99, 'validation_code': 0}},
                'sepolia': [{'transaction_hash': '0x%064x' % i, 'block': hex(1000 + i), 'block_hash': '0x' + '9' * 64} for i in range(68)]}
    d['dataset_store'].install_original_receipts(receipts)
    anchors = officer_integrity(d['service'], identifier(1))['original']['anchors']
    assert anchors['chunk'] == 0 and anchors['fabric']['transaction_id'] == '%064x' % 0 and anchors['sepolia']['transaction_hash'] == '0x%064x' % 1
    assert anchors['transactions_per_chain'] == 68 and anchors['fabric_seal']['transaction_id'] == 'e' * 64
    with pytest.raises(Exception, match='ORIGINAL_RECEIPTS_ALREADY_INSTALLED'):
        d['dataset_store'].install_original_receipts(receipts)
    import sqlite3
    with pytest.raises(sqlite3.DatabaseError):
        with sqlite3.connect(d['dataset_store'].path) as c:
            c.execute('DELETE FROM original_receipts')
    assert officer_integrity(d['service'], identifier(2))['original'] is None
    from app.intake.promotion_pipeline.core import IntakeError
    with pytest.raises(IntakeError, match='ORIGINAL_COMMITMENTS_ALREADY_INSTALLED'):
        _fake_original(d['dataset_store'], identifier(1))


def test_tampered_original_proof_and_tampered_batch_leaves_are_detected(d):
    from app.access.officer_integrity import officer_integrity
    from research_workspace_fixture import identifier
    _fake_original(d['dataset_store'], identifier(1), tamper=True)
    bad = officer_integrity(d['service'], identifier(1))
    assert bad['original']['inclusion_verified'] is False and bad['all_recomputed_checks_passed'] is False
    published(d, 'transfer_history.csv', [transfer(from_station_code=d['origin_station'])])
    real = d['dataset_store'].publication

    def altered(batch):
        payload, manifest = real(batch)
        return payload, dict(manifest, rows=['9' * 64] + manifest['rows'][1:])
    d['dataset_store'].publication = altered
    broken = officer_integrity(d['service'], identifier(1))
    # The analysis layer already refuses a batch whose recomputed commitment differs; the view reports it plainly.
    assert broken['all_recomputed_checks_passed'] is False and 'ANALYSIS_VISIBILITY_BINDING_DIFFERS' in broken['verification_errors']
    assert broken['uploads'] == []


def test_integrity_section_and_route_are_registered_for_logging():
    from app.access.accountability import action_for
    from app.access.accountability_activity import SECTIONS
    assert 'integrity' in SECTIONS
    assert action_for('/api/research/officers/' + str(uuid4()) + '/integrity') == 'OFFICER_INTEGRITY_READ'
