"""Re-pin the source files of the private-chain accountability anchor after reviewed, committed changes.

Only the digests of the files already pinned are refreshed: no file is added or
removed, no key, gateway, journal or log is touched, and nothing is submitted.
The previous configuration is retained as a backup. Run with the application stopped.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.policy import require
from app.access.store import private
from app.access.accountability_anchor import FIELDS, POLICY


def refresh(repo, anchor_config, *, check_tree=True):
    repo = Path(repo).resolve()
    if check_tree:
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(), 'Commit source before pinning')
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() if check_tree else 'UNCHECKED'
    file = private(anchor_config, repo=repo)
    raw = file.read_bytes()
    config = json.loads(raw)
    require(set(config) == FIELDS and config['policy'] == POLICY, 'Accountability anchor configuration differs')
    pins = {}
    for name in config['source_pins']:
        source = repo / name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and source.is_file() and not source.is_symlink(), 'Pinned file missing')
        pins[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    changed = sorted(n for n in pins if pins[n] != config['source_pins'][n])
    if not changed:
        return {'status': 'ANCHOR_PINS_ALREADY_CURRENT', 'revision': revision, 'files_changed': []}
    backup = file.with_name('worker-config-before-repin-' + revision[:12] + '.json')
    if backup.exists():
        require(private(backup).read_bytes() == raw, 'Backup differs from the current configuration')
    else:
        with backup.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    temp = file.with_name('.worker-config-repin-' + secrets.token_hex(8) + '.tmp')
    try:
        with temp.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps({**config, 'source_pins': pins}, sort_keys=True, separators=(',', ':')).encode())
            f.flush()
            os.fsync(f.fileno())
        require(private(file).read_bytes() == raw, 'Configuration changed while pinning')
        os.replace(temp, file)
    finally:
        if temp.exists():
            temp.unlink()
    return {'status': 'ANCHOR_PINS_REFRESHED', 'revision': revision, 'files_changed': changed, 'backup': str(backup),
            'logs_touched': False, 'chain_submitted': False}


def main():
    from app.access.research_app import configured
    base = Path.home() / 'ResearchKeys/police-personnel-integrity'
    workspace_config = base / 'research-app-v1/workspace-config.json'
    workspace, origin = configured(workspace_config)
    port = int(origin.rsplit(':', 1)[-1].split('/')[0])
    with socket.socket() as s:
        s.settimeout(2)
        require(s.connect_ex(('127.0.0.1', port)) != 0, 'Stop the application before re-pinning')
    anchor = json.loads(private(json.loads(private(workspace_config, repo=workspace.repo).read_bytes())['accountability_config'], repo=workspace.repo).read_bytes())['anchor_config']
    print(json.dumps(refresh(workspace.repo, anchor), indent=2))


if __name__ == '__main__':
    main()
