"""Isolation and completion checks; real peer suite requires explicit Docker run."""
import ast
from copy import deepcopy
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'backend/scripts/run_isolated_backend_pipeline.py'
INTEGRATION=ROOT/'blockchain/fabric/integration'


def module():
    spec=importlib.util.spec_from_file_location('isolated_pipeline',SCRIPT)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def summary():
    s=dict(policy='PPI_ISOLATED_BACKEND_PIPELINE_V1',checks=9,checks_completed=[str(i) for i in range(9)],research_records_used=0)
    for k in ('actual_python_coordinator','actual_python_services','actual_node_workers','actual_fabric_sdk','actual_fabric_peers',
        'actual_local_evm','https_rpc_transport','https_witness_transport','full_source_replay_simulated','public_finality_simulated'):s[k]=True
    for k in ('provider_independence_verified','independent_witness_deployment_verified','live_research_ready'):s[k]=False
    return s


def test_valid_isolated_summary_is_accepted():module().validate_pipeline_summary(summary())


@pytest.mark.parametrize('field',['checks','checks_completed','policy','research_records_used','actual_python_coordinator',
    'actual_python_services','actual_node_workers','actual_fabric_sdk','actual_fabric_peers','actual_local_evm','https_rpc_transport',
    'https_witness_transport','full_source_replay_simulated','public_finality_simulated','provider_independence_verified',
    'independent_witness_deployment_verified','live_research_ready'])
def test_incomplete_or_overstated_summary_cannot_pass(field):
    s=summary()
    if field=='checks':s[field]=8
    elif field=='checks_completed':s[field]=['duplicate']*9
    elif field=='policy':s[field]='LIVE'
    elif field=='research_records_used':s[field]=1
    else:s[field]=not s[field]
    with pytest.raises(RuntimeError):module().validate_pipeline_summary(s)


def test_owned_network_configuration_and_cleanup_are_preserved():
    def functions(p):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(p.read_text()).body if isinstance(n,ast.FunctionDef)}
    a=functions(ROOT/'backend/scripts/run_isolated_backend_findings_peers.py');b=functions(SCRIPT)
    for name in ('captured_env','package_cc','configs','plan','peer_env','owned'):assert a[name]==b[name]
    text=SCRIPT.read_text();assert 'docker.sock' not in text and "'system','prune'" not in text
    env=module().captured_env();assert not any(k.startswith(('CORE_PEER_','PPI_','DATABASE_')) for k in env)


def test_exact_service_chain_and_ordinary_worker_layout_are_packaged():
    text=SCRIPT.read_text()
    for name in ('findings_backend_pipeline.py','findings_public_backend_gate.py','findings_public_backend_service.py',
        'configured-public-runtime.js','configured-public-backend-worker.js','backend-pipeline-fixture.py',
        'backend-pipeline-runtime.js','backend-pipeline-check.js','findings-pipeline-peer-check.js','Dockerfile.pipeline'):
        assert name in text
    docker=(INTEGRATION/'Dockerfile.pipeline').read_text()
    assert 'cp -a /work/backend /work/pipeline/backend' in docker
    assert 'cp -a /work/public/findings /work/pipeline/blockchain/public/findings' in docker
    assert 'ln -s' not in docker


def test_driver_never_substitutes_chain_services_or_coordinator():
    text=(INTEGRATION/'backend-pipeline-fixture.py').read_text()
    for name in ('findings_backend_service','findings_public_backend_gate','findings_public_backend_service','findings_backend_pipeline'):
        assert "load('"+name+"')" in text
    assert "pipeline.FindingsBackendPipeline(" in text and "full_source_replay_simulated=True" in text
    assert "job['repo']=='/work/pipeline'" in text
    assert "'PPI_DISPOSABLE_FINDINGS_FABRIC_V1'" in text
