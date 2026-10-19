import json,hashlib
from pathlib import Path
import pytest
from scripts.deploy_research_fabric import prerequisites


def fixture(tmp_path):
    root=tmp_path/'network';root.mkdir(mode=0o700);repo=tmp_path/'repo';repo.mkdir()
    def save(name,value):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value));p.chmod(0o600);return p
    block=root/'genesis.block';block.write_bytes(b'genesis');block.chmod(0o600);digest=hashlib.sha256(block.read_bytes()).hexdigest()
    locks={}
    for name in ('client','chaincode'):
        lock=save('runtime/'+name+'/package-lock.json',{});locks[name]=hashlib.sha256(lock.read_bytes()).hexdigest()
    network=dict(genesis_sha256=digest,genesis_identity={'policy':'FABRIC_GENESIS_HEADER_DATA_V1'})
    save('gateway-config.json',dict(channel='personnel',chaincode='officer-evidence-test-v1',genesis_sha256=digest))
    save('SETUP_PASSED.json',dict(status='PASSED',fabric='2.5.16',ca='1.5.17',test_chaincode='officer-evidence-test-v1',genesis_sha256=digest,runtime_lockfiles=locks))
    save('recovery-checks/PASSED.json',dict(status='PASSED',test_officers=6596,valid_transactions=68,interruption_cases=4,two_peer_readback=True,research_commitments_submitted=0,network=network))
    return root,repo


def test_deployment_prerequisites_preserve_existing_network(tmp_path):
    root,repo=fixture(tmp_path);before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert prerequisites(root,repo)[0]==root
    assert before=={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('kind',['unverified','genesis','lock','existing_deployment','existing_runtime'])
def test_deployment_refuses_wrong_or_existing_material(tmp_path,kind):
    root,repo=fixture(tmp_path)
    if kind=='unverified':(root/'recovery-checks/PASSED.json').write_text('{}')
    if kind=='genesis':(root/'genesis.block').write_bytes(b'changed')
    if kind=='lock':(root/'runtime/client/package-lock.json').write_text('changed')
    if kind=='existing_deployment':(root/'research-deployment').mkdir()
    if kind=='existing_runtime':(root/'runtime/research-client').mkdir()
    with pytest.raises((KeyError,ValueError,RuntimeError)):prerequisites(root,repo)
