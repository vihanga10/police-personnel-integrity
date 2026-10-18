"""Public read-only demonstration launcher (synthetic data only), meant to sit behind a reverse proxy on the same host.

Refuses to start unless the configuration is a public HTTPS DNS name with mandatory TOTP and with uploads, chain
writes and log anchoring switched off. Binds only to loopback; the proxy must pass the original Host header and set
X-Forwarded-For. It reads no key material itself and prints no secrets.
"""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.policy import require
from app.access.public_demo import problems, read_json
from app.access.store import private

ACKNOWLEDGEMENT = '--accept-public-synthetic-demo'


def prepare(config, certificate, tls_key, acknowledged):
    """Validate everything that can be validated from configuration alone; returns (config_file, origin, cert, key)."""
    require(acknowledged, 'Public mode needs ' + ACKNOWLEDGEMENT + ': this serves SYNTHETIC data only')
    configfile = private(config)
    workspace = json.loads(configfile.read_text())
    require(workspace.get('policy') == 'RESEARCH_WEB_CONFIG_V1', 'Workspace configuration required')
    access = read_json(private(workspace['access_config']))
    accountability = read_json(private(workspace['accountability_config'])) if 'accountability_config' in workspace else None
    found = problems(workspace, access, accountability)
    require(not found, 'Not a safe public demonstration configuration: ' + ', '.join(found))
    repo = Path(access['repository'])
    cert, key = private(certificate, repo=repo), private(tls_key, repo=repo)
    require(key != cert and key not in (Path(workspace['key_file']).resolve(), Path(access['key_file']).resolve()), 'Separate TLS key required')
    return configfile, access['origin'], cert, key


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--certificate', type=Path, required=True)
    p.add_argument('--tls-key', type=Path, required=True)
    p.add_argument('--port', type=int, default=8443)
    p.add_argument(ACKNOWLEDGEMENT, dest='acknowledged', action='store_true')
    a = p.parse_args()
    require(1024 <= a.port <= 65535, 'Unprivileged port required')
    configfile, origin, cert, key = prepare(a.config, a.certificate, a.tls_key, a.acknowledged)
    import os
    os.environ['PPI_RESEARCH_CONFIG'] = str(configfile)
    import uvicorn
    # The proxy runs on this host: only loopback peers may supply the forwarded client address.
    uvicorn.run('app.access.research_app:application', factory=True, host='127.0.0.1', port=a.port, workers=1, reload=False,
                proxy_headers=True, forwarded_allow_ips='127.0.0.1', access_log=False, server_header=False,
                limit_concurrency=32, timeout_keep_alive=5, timeout_graceful_shutdown=10, ssl_certfile=str(cert), ssl_keyfile=str(key))


if __name__ == '__main__':
    main()
