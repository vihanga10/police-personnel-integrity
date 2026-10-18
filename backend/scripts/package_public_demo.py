"""Operator tool: build the transfer bundle for a public read-only demonstration copy (run with the app STOPPED).

  uv run python scripts/package_public_demo.py --app-root ~/ResearchKeys/police-personnel-integrity/research-app-v1 \
      --out ~/Desktop/ppi-public-bundle --origin https://demo.example.edu --server-root /srv/ppi --server-repo /srv/ppi/repo

Prints counts only; never prints key material. Wallets, Fabric/Sepolia writer keys, intake and provisioning files are never copied.
"""
import argparse
import json
from pathlib import Path
import socket
import sys
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.policy import require
from app.access.public_demo_bundle import build


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app-root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--origin', required=True)
    p.add_argument('--server-root', type=Path, required=True)
    p.add_argument('--server-repo', type=Path, required=True)
    a = p.parse_args()
    local_origin = json.loads(Path(json.loads((a.app_root / 'workspace-config.json').read_text())['access_config']).read_text())['origin']
    url = urlsplit(local_origin)
    with socket.socket() as s:
        s.settimeout(2)
        require(s.connect_ex((url.hostname, url.port or 443)) != 0, 'Stop the application before packaging')
    print(json.dumps(build(a.app_root.expanduser(), a.out.expanduser(), origin=a.origin, server_root=a.server_root, server_repo=a.server_repo), indent=1))


if __name__ == '__main__':
    main()
