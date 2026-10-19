"""Rules for a public, read-only demonstration copy of the research workspace (synthetic data only).

A public copy never accepts uploads, never writes to a blockchain and never serves a login without a second
factor. These checks run before the server starts and before a transfer bundle is built; they raise nothing
secret and read no key material.
"""
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
UPLOAD_AND_CHAIN_WRITERS = ('promotion_intake_config', 'personnel_intake_config')
CHAIN_AND_DATABASE_FIELDS = ('chains', 'postgres_credentials', 'mongo_credentials')
PRIVATE_NAME_PARTS = ('wallet', 'mnemonic', 'fabric', 'sepolia', 'intake', 'promotion', 'credentials', 'enrollment', 'recovery',
                      'identity-keys', 'commitment')


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def public_dns_name(origin):
    host = urlsplit(origin).hostname or ''
    labels = host.split('.')
    return (not is_ip(host) and len(labels) >= 2 and all(LABEL.fullmatch(x) for x in labels)
            and labels[-1] not in ('local', 'localhost', 'internal', 'lan', 'test', 'invalid', 'example')
            and not host.endswith('.in-addr.arpa'))


def problems(workspace, access, accountability=None, intake_runtimes=()):
    """Stable, secret-free reasons a configuration may not run as a public demonstration."""
    found = []
    origin = access.get('origin', '')
    if urlsplit(origin).scheme != 'https' or not public_dns_name(origin):
        found.append('PUBLIC_HTTPS_DNS_NAME_REQUIRED')
    if access.get('totp_required') is not True:
        found.append('MANDATORY_TOTP_REQUIRED')
    for name in UPLOAD_AND_CHAIN_WRITERS:
        # Retained intake stores may be loaded for reading only; the workers that upload and publish must not exist.
        if name in workspace and workspace.get('intake_read_only') is not True:
            found.append('UPLOADS_AND_CHAIN_WRITES_MUST_BE_OFF:' + name)
    for runtime in intake_runtimes:
        for name in CHAIN_AND_DATABASE_FIELDS:
            if name in runtime:
                found.append('INTAKE_RUNTIME_MUST_NOT_HOLD:' + name)
    if accountability is not None and 'anchor_config' in accountability:
        found.append('LOG_ANCHORING_MUST_BE_OFF:anchor_config')
    return found


def read_json(path):
    return json.loads(Path(path).read_text())


def forbidden_name(name):
    lowered = name.lower()
    return any(part in lowered for part in PRIVATE_NAME_PARTS)
