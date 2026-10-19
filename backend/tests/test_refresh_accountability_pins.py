"""Re-pinning changes only the digests of already pinned files and keeps a backup."""
import hashlib
import json
import os
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from refresh_accountability_pins import refresh
from app.access.accountability_anchor import FIELDS, POLICY


def setup(tmp_path):
    repo = tmp_path / 'repo'
    (repo / 'backend/app/access').mkdir(parents=True)
    pinned = repo / 'backend/app/access/accountability.py'
    pinned.write_text('one')
    state = tmp_path / 'private'
    state.mkdir(mode=0o700)
    config = {k: 'x' for k in FIELDS}
    config.update(policy=POLICY, interval_seconds=60, batch_events=100,
                  source_pins={'backend/app/access/accountability.py': hashlib.sha256(b'one').hexdigest()})
    file = state / 'worker-config.json'
    file.write_text(json.dumps(config))
    file.chmod(0o600)
    return repo, pinned, file, config


def test_refresh_updates_only_changed_pinned_digests_and_keeps_backup(tmp_path):
    repo, pinned, file, config = setup(tmp_path)
    assert refresh(repo, file, check_tree=False)['status'] == 'ANCHOR_PINS_ALREADY_CURRENT'
    pinned.write_text('two')
    before = file.read_bytes()
    result = refresh(repo, file, check_tree=False)
    assert result['status'] == 'ANCHOR_PINS_REFRESHED' and result['files_changed'] == ['backend/app/access/accountability.py']
    updated = json.loads(file.read_text())
    assert updated['source_pins'] == {'backend/app/access/accountability.py': hashlib.sha256(b'two').hexdigest()}
    assert {k: v for k, v in updated.items() if k != 'source_pins'} == {k: v for k, v in config.items() if k != 'source_pins'}
    assert (os.stat(file).st_mode & 0o777) == 0o600
    assert Path(result['backup']).read_bytes() == before
    assert refresh(repo, file, check_tree=False)['status'] == 'ANCHOR_PINS_ALREADY_CURRENT'


def test_refresh_refuses_missing_file_and_wrong_policy(tmp_path):
    repo, pinned, file, config = setup(tmp_path)
    pinned.unlink()
    with pytest.raises(ValueError):
        refresh(repo, file, check_tree=False)
    pinned.write_text('one')
    file.write_text(json.dumps({**config, 'policy': 'OTHER'}))
    with pytest.raises(ValueError):
        refresh(repo, file, check_tree=False)
