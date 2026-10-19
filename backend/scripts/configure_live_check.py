"""Operator tool: enable the READ-ONLY live chain check on the Integrity tab (run with the application STOPPED).

  uv run python scripts/configure_live_check.py --repository ~/Developer/police-personnel-integrity

Pins the reader-only Fabric gateway configuration and the Sepolia network configuration by SHA-256, writes a new owner-only
live-check configuration beside the workspace configuration, and adds one field to the workspace configuration after saving a
backup of it. Idempotent. Prints counts and status only; never reads or prints a key, and never contacts a chain.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.live_check import FIELDS, POLICY, configured
from app.access.policy import require
from app.access.store import private

HOME = Path.home() / 'ResearchKeys/police-personnel-integrity'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, data):
    with Path(path).open('xb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_private(path, data):
    temp = Path(str(path) + '.tmp')
    write_new(temp, data)
    os.replace(temp, path)
    fd = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def plan(app_root, repository, gateway, network):
    workspace_file = private(Path(app_root) / 'workspace-config.json', repo=repository)
    workspace = json.loads(workspace_file.read_text())
    gateway, network = private(gateway, repo=repository), private(network, repo=repository)
    gate = json.loads(gateway.read_text())
    require(gate.get('chaincode') == 'officer-evidence-v1' and gate.get('channel') == 'personnel' and 'reader' in gate, 'Reader-capable original gateway configuration required')
    require(json.loads(network.read_text()).get('policy') == 'SEPOLIA_DEPLOYMENT_NETWORK_V1', 'Original Sepolia network configuration required')
    require('intake_read_only' not in workspace, 'Never enable live chain checks on a public read-only copy')
    config = {'policy': POLICY, 'fabric_gateway_config': str(gateway), 'fabric_gateway_sha256': sha(gateway),
              'sepolia_network_config': str(network), 'sepolia_network_sha256': sha(network)}
    require(set(config) == FIELDS, 'Live check fields differ')
    return workspace_file, workspace, config


def apply(app_root, repository, gateway, network):
    workspace_file, workspace, config = plan(app_root, repository, gateway, network)
    target = Path(app_root) / 'live-check-config.json'
    data = (json.dumps(config, sort_keys=True, indent=1) + '\n').encode()
    if 'live_check_config' in workspace:
        require(workspace['live_check_config'] == str(target) and target.exists() and private(target, repo=repository).read_bytes() == data, 'Existing live check configuration differs; inspect before replacing')
        configured(target, repository)
        return {'status': 'LIVE_CHECK_ALREADY_CONFIGURED', 'chain_contacted': False}
    require(not target.exists(), 'Unexpected live check file exists; inspect before continuing')
    original = workspace_file.read_bytes()
    write_new(Path(app_root) / ('workspace-config-before-live-check-' + hashlib.sha256(original).hexdigest()[:12] + '.json'), original)
    write_new(target, data)
    updated = {**workspace, 'live_check_config': str(target)}
    replace_private(workspace_file, json.dumps(updated).encode())
    configured(target, repository)
    return {'status': 'LIVE_CHECK_CONFIGURED', 'chain_contacted': False, 'keys_printed': False, 'restart_required': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', type=Path, required=True)
    p.add_argument('--app-root', type=Path, default=HOME / 'research-app-v1')
    p.add_argument('--gateway', type=Path, default=HOME / 'fabric-local-v1/research-gateway-config.json')
    p.add_argument('--network', type=Path, default=HOME / 'sepolia-v1/network.json')
    a = p.parse_args()
    origin = json.loads(Path(json.loads((a.app_root / 'workspace-config.json').read_text())['access_config']).read_text())['origin']
    url = urlsplit(origin)
    with socket.socket() as s:
        s.settimeout(2)
        require(s.connect_ex((url.hostname, url.port or 443)) != 0, 'Stop the application before changing its configuration')
    print(json.dumps(apply(a.app_root, a.repository.expanduser(), a.gateway, a.network), indent=1))


if __name__ == '__main__':
    main()
