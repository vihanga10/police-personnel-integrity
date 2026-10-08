"""Setup guards preserve existing Docker ledgers and keep network material outside Git."""
from pathlib import Path
import pytest
from scripts.setup_fabric_network import preflight, one, FABRIC, CA


@pytest.mark.parametrize('kind', ['container', 'network', 'volume', 'port', 'nonempty', 'inside_repo', 'symlink'])
def test_existing_or_unsafe_network_target_rejected(tmp_path, kind):
    repo = tmp_path/'repo'; repo.mkdir(); root = tmp_path/'network'
    names, networks, volumes = set(), [], []
    if kind == 'container': names.add('peer0.org1.example.com')
    if kind == 'network': networks.append('fabric_test')
    if kind == 'volume': volumes.append('retained_peer0.org2.example.com')
    if kind == 'nonempty': root.mkdir(); (root/'ledger').write_text('preserve')
    if kind == 'inside_repo': root = repo/'network'
    if kind == 'symlink': target = tmp_path/'target'; target.mkdir(); root.symlink_to(target)
    with pytest.raises(ValueError): preflight(root, repo, names, lambda _:kind != 'port', networks, volumes)
    if kind == 'nonempty': assert (root/'ledger').read_text() == 'preserve'


def test_new_network_does_not_touch_other_containers(tmp_path):
    repo = tmp_path/'repo'; repo.mkdir(); root = tmp_path/'network'
    assert preflight(root, repo, {'mongodb', 'postgresql'}, lambda _:True) == root
    assert not root.exists()
    assert (FABRIC, CA) == ('2.5.16', '1.5.17')


def test_single_key_file_is_required(tmp_path):
    with pytest.raises(ValueError): one(tmp_path)
    first = tmp_path/'first'; first.write_text('key')
    assert one(tmp_path) == first
    (tmp_path/'second').write_text('key')
    with pytest.raises(ValueError): one(tmp_path)


def test_setup_and_checker_have_no_destructive_or_research_submission_command():
    source = Path(__file__).resolve().parents[1]/'scripts/setup_fabric_network.py'
    text = source.read_text()
    assert "'down'" not in text and 'docker system prune' not in text and 'rmtree' not in text
    assert 'officer-evidence-test-v1' in text and 'private_key' in text
    assert "'--id.attrs', 'evidence.anchor=true:ecert'" in text
    assert 'package-lock.json' in text


@pytest.mark.parametrize('value', ['Version: v2.5.16\n', 'Version: 2.5.16\n', '  Version:\tV2.5.16\n'])
def test_exact_version_accepts_official_prefix(value):
    from scripts.setup_fabric_network import verify_version
    verify_version(value, FABRIC)


@pytest.mark.parametrize('value', ['Version: v2.5.15', 'Version: v2.5.160', 'Version: v2.5.16-dev',
    'Version: v2.5.16\nVersion: v2.5.16', 'Other: v2.5.16'])
def test_version_rejects_changed_or_ambiguous_binary(value):
    from scripts.setup_fabric_network import verify_version
    with pytest.raises(ValueError): verify_version(value, FABRIC)


def downloaded_fixture(tmp_path, monkeypatch):
    import json, hashlib, subprocess
    from scripts import setup_fabric_network as setup
    root=tmp_path/'network'; root.mkdir(mode=0o700)
    repo=tmp_path/'repo'; repo.mkdir()
    original=subprocess.check_output
    def git(directory,*args): return original(['git','-C',str(directory),*args],text=True).strip()
    for directory in (repo,root/'release-source',root/'fabric-samples'):
        directory.mkdir(exist_ok=True)
        git(directory,'init','-q');git(directory,'config','user.name','Fixture');git(directory,'config','user.email','fixture@example.invalid')
        (directory/'README').write_text('original')
        if directory.name=='release-source':
            (directory/'scripts').mkdir();(directory/'scripts/install-fabric.sh').write_text('original installer')
        git(directory,'add','.');git(directory,'commit','-qm','fixture')
    revision=git(repo,'rev-parse','HEAD')
    def output(args,**kwargs):
        if args[-1]=='6f6899a^{commit}': return revision+'\n'
        return original(args,**kwargs)
    monkeypatch.setattr(setup.subprocess,'check_output',output)
    def save(path,value): path.write_text(json.dumps(value));path.chmod(0o600)
    save(root/'SETUP_STARTED.json',dict(status='STARTED',code_revision=revision,fabric=FABRIC,ca=CA,channel=setup.CHANNEL,chaincode=setup.CHAINCODE))
    save(root/'release-source.json',dict(release_commit=git(root/'release-source','rev-parse','HEAD'),installer_sha256=hashlib.sha256((root/'release-source/scripts/install-fabric.sh').read_bytes()).hexdigest()))
    logs=root/'logs';logs.mkdir(mode=0o700)
    for phase in ('release_source','downloads','peer_binary_version','ca_binary_version'):
        save(logs/(phase+'.json'),dict(phase=phase,status='PASSED'))
        p=logs/(phase+'.log');p.write_text('Version: v'+(CA if phase=='ca_binary_version' else FABRIC)+'\n');p.chmod(0o600)
    (root/'fabric-samples/bin').mkdir()
    for name in ('peer','fabric-ca-client'): (root/'fabric-samples/bin'/name).write_text('fixture binary')
    return root,repo,setup


def test_resume_preserves_downloads_and_original_receipts(tmp_path,monkeypatch):
    root,repo,setup=downloaded_fixture(tmp_path,monkeypatch)
    before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert setup.resume_pre_network(root,repo,set(),lambda _:True)==root
    assert before=={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('kind',['started_network','other_material','incomplete','wrong_receipt','source_changed','wrong_version','container','port','binary_symlink'])
def test_resume_rejects_other_failure_or_network_state(tmp_path,monkeypatch,kind):
    root,repo,setup=downloaded_fixture(tmp_path,monkeypatch)
    if kind=='started_network':(root/'logs/network_start.log').write_text('preserve')
    if kind=='other_material':(root/'anchorer-msp').mkdir()
    if kind=='incomplete':(root/'logs/downloads.json').unlink()
    if kind=='wrong_receipt':(root/'SETUP_STARTED.json').write_text('{}')
    if kind=='source_changed':(root/'fabric-samples/README').write_text('changed')
    if kind=='wrong_version':(root/'logs/peer_binary_version.log').write_text('Version: v2.5.15')
    if kind=='binary_symlink':
        p=root/'fabric-samples/bin/peer';p.unlink();p.symlink_to(root/'fabric-samples/README')
    with pytest.raises((ValueError,RuntimeError)):
        setup.resume_pre_network(root,repo,{'peer0.org1.example.com'} if kind=='container' else set(),lambda _:kind!='port')
