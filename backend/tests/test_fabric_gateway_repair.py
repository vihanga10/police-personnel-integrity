import hashlib,json
from pathlib import Path
import pytest
from scripts.repair_fabric_gateway import plan,OLD_GATEWAY


def fixture(tmp_path,monkeypatch):
    from scripts import repair_fabric_gateway as repair
    root=tmp_path/'network';root.mkdir(mode=0o700);repo=tmp_path/'repo';repo.mkdir()
    def write(p,value):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value);p.chmod(0o600)
    write(root/'genesis.block',b'captured genesis')
    write(root/'gateway-config.json',json.dumps(dict(channel='personnel',chaincode='officer-evidence-test-v1',genesis_sha256=hashlib.sha256(b'captured genesis').hexdigest())).encode())
    (root/'recovery-checks').mkdir(mode=0o700)
    write(root/'runtime/client/gateway.js',b'old gateway')
    monkeypatch.setattr(repair,'OLD_GATEWAY',hashlib.sha256(b'old gateway').hexdigest())
    for name in ('gateway.js','block-identity.js'):write(repo/'blockchain/fabric/client'/name,b'new code')
    return root,repo


def test_repair_plan_has_no_file_or_network_mutation(tmp_path,monkeypatch):
    root,repo=fixture(tmp_path,monkeypatch)
    before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result=plan(root,repo)
    assert result[0]==root and set(result[3])=={'gateway.js','block-identity.js'}
    assert before=={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('kind',['journal','gateway','genesis','helper','configuration','source_symlink'])
def test_repair_rejects_existing_commitments_or_changed_material(tmp_path,monkeypatch,kind):
    root,repo=fixture(tmp_path,monkeypatch)
    if kind=='journal':(root/'recovery-checks/fixture.json').write_text('preserve')
    if kind=='gateway':(root/'runtime/client/gateway.js').write_text('changed')
    if kind=='genesis':(root/'genesis.block').write_bytes(b'changed')
    if kind=='helper':(root/'runtime/client/block-identity.js').write_text('existing')
    if kind=='configuration':(root/'gateway-config.json').write_text('{}')
    if kind=='source_symlink':
        p=repo/'blockchain/fabric/client/gateway.js';p.unlink();p.symlink_to(root/'genesis.block')
    with pytest.raises((ValueError,RuntimeError,KeyError)):plan(root,repo)
