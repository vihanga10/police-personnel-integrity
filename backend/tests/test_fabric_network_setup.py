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
