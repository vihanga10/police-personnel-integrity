"""Builds the transfer bundle for a public read-only demonstration copy.

Copies only what the web workspace needs (three state stores, three key files, log-reader grants), rewrites the
configurations for the server, and refuses anything that looks like chain-writing or provisioning material.
Key bytes are copied but never read into output, logged or hashed into the manifest by value.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil

from app.access.policy import require
from app.access.public_demo import UPLOAD_AND_CHAIN_WRITERS, forbidden_name, problems, read_json

SUMMARY = 'PUBLIC_DEMO_BUNDLE_V1'


def inside(path, root):
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def vet(source, app_root):
    source = Path(source)
    require(source.exists() and not source.is_symlink(), 'Missing or linked source: ' + source.name)
    require(inside(source, app_root), 'Source outside the application folder refused: ' + source.name)
    names = [source.name] + ([p.name for p in source.rglob('*')] if source.is_dir() else [])
    require(not source.is_symlink() and not any(p.is_symlink() for p in (source.rglob('*') if source.is_dir() else [])), 'Links refused')
    bad = sorted({n for n in names if forbidden_name(n)})
    require(not bad, 'Chain or provisioning material refused: ' + ', '.join(bad[:5]))
    return source


def copy(source, destination):
    destination = Path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=False)
        for p in [destination, *destination.rglob('*')]:
            p.chmod(0o700 if p.is_dir() else 0o600)
    else:
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
    return destination


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def write_private(path, value):
    path = Path(path)
    with path.open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(value, f, indent=1, sort_keys=True)
    return path


def build(app_root, out, *, origin, server_root, server_repo):
    """Returns a secret-free summary. `out` must not exist; `server_root` is where the bundle will live on the server."""
    app_root, out, server_root = Path(app_root).resolve(), Path(out), Path(server_root)
    require(not out.exists(), 'Output folder must not exist')
    require(server_root.is_absolute() and Path(server_repo).is_absolute(), 'Absolute server paths required')
    workspace = read_json(app_root / 'workspace-config.json')
    access = read_json(workspace['access_config'])
    accountability = read_json(workspace['accountability_config']) if 'accountability_config' in workspace else None
    for name in ('access_config', 'state_directory', 'key_file', *(['accountability_config'] if accountability else [])):
        vet(workspace[name], app_root)
    plan = [(workspace['state_directory'], 'state/workspace'), (workspace['key_file'], 'keys/workspace.key'),
            (access['state_directory'], 'state/access'), (access['key_file'], 'keys/access.key')]
    if accountability:
        plan += [(accountability['state_directory'], 'state/accountability'), (accountability['key_file'], 'keys/accountability.key')]
        plan += [(g, 'grants/' + Path(g).name) for g in accountability['reader_grants']]
    # Rewritten copies of the configuration that the server will read.
    new_access = {**access, 'origin': origin, 'repository': str(server_repo), 'state_directory': str(server_root / 'state/access'),
                  'key_file': str(server_root / 'keys/access.key'), 'totp_required': True}
    require(access.get('totp_required') is True, 'The source workspace must already require TOTP')
    new_workspace = {k: v for k, v in workspace.items() if k not in UPLOAD_AND_CHAIN_WRITERS}
    new_workspace.update(access_config=str(server_root / 'private/access-config.json'), state_directory=str(server_root / 'state/workspace'),
                         key_file=str(server_root / 'keys/workspace.key'))
    new_accountability = None
    if accountability:
        new_accountability = {k: v for k, v in accountability.items() if k != 'anchor_config'}
        new_accountability.update(state_directory=str(server_root / 'state/accountability'), key_file=str(server_root / 'keys/accountability.key'),
                                  reader_grants=[str(server_root / 'grants' / Path(g).name) for g in accountability['reader_grants']])
        new_workspace['accountability_config'] = str(server_root / 'private/accountability-config.json')
    found = problems(new_workspace, new_access, new_accountability)
    require(not found, 'Result would not be a safe public demonstration: ' + ', '.join(found))
    sources = [(vet(src, app_root), rel) for src, rel in plan]
    out.mkdir(mode=0o700)
    (out / 'private').mkdir(mode=0o700)
    copied = [(copy(src, out / rel), rel) for src, rel in sources]
    write_private(out / 'private/access-config.json', new_access)
    write_private(out / 'private/workspace-config.json', new_workspace)
    if new_accountability:
        write_private(out / 'private/accountability-config.json', new_accountability)
    files = {}
    for p in sorted(x for x in out.rglob('*') if x.is_file()):
        files[str(p.relative_to(out))] = {'sha256': digest(p), 'bytes': p.stat().st_size}
    write_private(out / 'MANIFEST.json', {'policy': SUMMARY, 'origin': origin, 'files': files})
    return {'policy': SUMMARY, 'origin': origin, 'files': len(files), 'stores': sum(1 for _, rel in copied if rel.startswith('state/')),
            'keys_printed': False, 'chain_keys_included': False, 'uploads_and_chain_writes': 'OFF', 'log_anchoring': 'OFF'}
