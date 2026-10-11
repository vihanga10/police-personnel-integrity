"""Offline source/launcher verification; actual peers require the explicit launcher."""
import ast
import importlib.util
import json
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import base64
from datetime import datetime,timezone,timedelta

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'backend/scripts/run_isolated_backend_findings_peers.py'
INTEGRATION=ROOT/'blockchain/fabric/integration'


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_original_network_isolation_helpers_are_unchanged():
    before=ast.parse((ROOT/'backend/scripts/run_isolated_https_witnessed_findings.py').read_text())
    after=ast.parse(SCRIPT.read_text())
    def functions(tree):return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)}
    a,b=functions(before),functions(after)
    for name in ('captured_env','package_cc','configs','plan','peer_env','owned'):assert a[name]==b[name]
    text=SCRIPT.read_text();assert "'system','prune'" not in text


def test_actual_service_worker_and_exact_backend_sources_packaged():
    text=SCRIPT.read_text()
    for name in ('findings-backend-worker.js','backend-service-fixture.py','backend-service-check.js','findings-backend-peer-check.js','Dockerfile.backend',
        'findings_backend_gate.py','findings_backend_service.py'):assert name in text
    docker=(INTEGRATION/'Dockerfile.backend').read_text()
    assert 'python3-cryptography' in docker and 'COPY backend/ /work/backend/' in docker
    assert docker.count('npm ci --ignore-scripts --no-audit --no-fund')==2
    assert 'cp -a /work/fabric/client /work/fabric/blockchain/fabric/client' in docker
    assert 'cp -a /work/fabric/integration/node_modules /work/fabric/blockchain/fabric/integration/node_modules' in docker
    assert 'ln -s' not in docker



def test_completion_cannot_omit_real_execution_or_fixture_limits():
    text=SCRIPT.read_text()
    for flag in ('actual_python_service','actual_node_worker','actual_fabric_sdk','actual_fabric_peers',
        'https_witness_transport','full_source_replay_simulated','live_research_ready','research_records_used',
        'independent_witness_deployment_verified'):assert flag in text
    assert "backend.get('checks')!=11" in text
    source=(INTEGRATION/'backend-service-check.js').read_text()
    assert source.count('    done(')==11
    for action in ("'ENTRY'","'BEFORE_ATTEMPT'","'BEFORE_SUBMIT'","'ACK'","'FINAL'"):assert action in source


def test_service_driver_uses_real_service_and_exact_approval_function():
    source=(INTEGRATION/'backend-service-fixture.py').read_text()
    assert "n.name=='verify_approval'" in source and 'service.run_fabric(' in source
    assert "full_source_replay_simulated=True" in source
    assert "SUBSTITUTED_SOURCE_REPLAY_FIXTURE" in source
    assert "'PPI_DISPOSABLE_FINDINGS_FABRIC_V1'" in source
    assert "job['repo']=='/work/fabric'" in source


@pytest.mark.parametrize('denied',[False,True])
def test_real_python_service_rejects_approval_or_source_before_worker(tmp_path,monkeypatch,capsys,denied):
    module=load(INTEGRATION/'backend-service-fixture.py','fixture_driver')
    root=tmp_path/'owned';root.mkdir(mode=0o700)
    (root/'ISOLATED-RUN.json').write_text(json.dumps({'policy':'PPI_DISPOSABLE_FINDINGS_FABRIC_V1'}))
    case=root/'case';case.mkdir(mode=0o700)
    for name in ('retention',): (case/name).mkdir(mode=0o700)
    key=case/'recovery.key';key.write_bytes(b'R'*32);key.chmod(0o600)
    signer=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    fmt=lambda t:t.isoformat(timespec='milliseconds').replace('+00:00','Z')
    selection={'fixture':'opaque'}
    body=dict(policy='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1',key_id='test',mode='EXECUTE',
        issued_at=fmt(now-timedelta(seconds=1)),expires_at=fmt(now+timedelta(seconds=30)),selection=selection)
    grant=dict(body=body,signature=base64.b64encode(signer.sign(module.encoded(body)) if denied else b'X'*64).decode())
    job=dict(repo='/work/fabric',mode='EXECUTE',selection=selection,approval=grant,
        trustedKeys={'test':signer.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()},
        gatewayConfigFile=str(case/'gateway.json'),witnessConfigFile=str(case/'witness.json'),witnessConfigSha256='a'*64,
        directory=str(case/'retention'),recoveryKeyFile=str(key))
    request=case/'request.json';request.write_text(json.dumps(dict(policy='PPI_BACKEND_SERVICE_FIXTURE_V1',job=job,deny_action='ENTRY' if denied else None)))
    actual_path=module.Path
    def mapped(value):
        if str(value).startswith('/work/backend/'):
            return ROOT/'backend'/str(value).removeprefix('/work/backend/')
        return actual_path(value)
    monkeypatch.setattr(module,'Path',mapped)
    monkeypatch.setenv('PPI_TEST_ROOT',str(root));monkeypatch.setattr(sys,'argv',['fixture',str(request)])
    # The driver deliberately stubs these names; restore the real test interpreter
    # module registry afterward, just as a separate Docker process would exit.
    names=['app','app.identity','app.identity.findings_backend_gate','app.identity.findings_commitments',
        'app.identity.historical_reconstruction','app.identity.protected_commitment']
    saved={name:sys.modules.get(name) for name in names}
    try:module.main()
    finally:
        for name,value in saved.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value
    result=json.loads(capsys.readouterr().out)
    assert result['ok'] is False and result['full_source_replay_simulated'] is True
    assert result['guards']==(['ENTRY'] if denied else [])
    assert list((case/'retention').iterdir())==[]


def test_docker_source_paths_exist_and_new_peer_entry_loads_bridge():
    peer=(INTEGRATION/'findings-backend-peer-check.js').read_text()
    assert "require('./backend-service-check').checks" in peer
    assert "assert.equal(backend.checks,11)" in peer
    assert 'BACKEND-BRIDGE-PASSED.json' in peer
    for path in (SCRIPT,INTEGRATION/'backend-service-fixture.py',INTEGRATION/'backend-service-check.js'):
        assert path.is_file()
