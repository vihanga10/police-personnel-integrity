"""Cross-language registry pins and the real HTTP boundary for dataset intake."""
import base64
import json
import subprocess
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
    code, _, rows = client.request('/api/research/intake/officers/' + s['rows'][0]['officer_uid'])
    assert code == 200 and rows['current']['projection']['posting']['to_station_code'] == 'ST-002'
