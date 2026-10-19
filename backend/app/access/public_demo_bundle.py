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
# Retained intake stores are loaded read-only. Only these exact files may ever be copied from an intake folder; the same
# folders hold database / Fabric / Sepolia credentials and recovery keys that must never leave the laptop.
INTAKES = (('personnel_intake_config', 'dataset', 'personnel-intake.sqlite3'), ('promotion_intake_config', 'promotion', 'promotion-intake.sqlite3'))
INTAKE_RUNTIME_KEEP = ('policy', 'baseline_source_set_sha256', 'source_public_sha256', 'importer_ids', 'source_pins')
SQLITE_SUFFIXES = ('', '-wal', '-shm', '-journal')


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


def intake_files(folder, names, roots):
    """Existing allowlisted files of one intake folder (database plus its write-ahead companions)."""
    folder = Path(folder)
    require(any(inside(folder, r) for r in roots) and folder.is_dir() and not folder.is_symlink(), 'Intake folder outside its own state refused')
    found = []
    for name in names:
        for suffix in SQLITE_SUFFIXES if name.endswith('.sqlite3') else ('',):
            p = folder / (name + suffix)
            if p.exists():
                require(not p.is_symlink() and p.is_file(), 'Intake link refused: ' + p.name)
                found.append(p)
    return found


def pins_current(repo, kind, runtime):
    """Refuse a bundle whose intake source pins no longer match the repository (a server checkout could not start)."""
    import hashlib
    if kind == 'dataset':
        from app.intake.dataset_pipeline.configuration import source_files
    else:
        from app.intake.promotion_pipeline.configuration import source_files
    pins = runtime['source_pins']
    require(set(pins) == set(source_files(repo)), 'Intake source pins out of date: run refresh-pins with the app stopped')
    for relative, expected in pins.items():
        require(hashlib.sha256((Path(repo) / relative).read_bytes()).hexdigest() == expected, 'Intake source pins out of date: run refresh-pins with the app stopped')


def private_directories(directory):
    """Create `directory` and every missing ancestor as owner-only (mkdir(parents=True) would leave the ancestors open)."""
    directory = Path(directory)
    missing = []
    while not directory.exists():
        missing.append(directory)
        directory = directory.parent
    for folder in reversed(missing):
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)


def copy(source, destination):
    destination = Path(destination)
    private_directories(destination.parent)
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


def build(app_root, out, *, origin, server_root, server_repo, repo=None, check_only=False):
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
    intake_plan, intake_configs, rewritten_runtimes = [], {}, []
    for field, kind, database in INTAKES:
        if field not in workspace:
            continue
        runtime_file = vet(workspace[field], app_root.parent)
        runtime = read_json(runtime_file)
        analysis_cfg, approval_cfg = read_json(runtime['analysis_config']), read_json(runtime['approval_config'])
        state_root = Path(runtime['state_root'])
        backup_root = state_root.parent / (state_root.name + '-backup')   # the real layout: a sibling folder, never an arbitrary one
        roots = [state_root, backup_root]
        require(inside(runtime['key_file'], state_root) and Path(runtime['backup_key_file']).resolve().parent == backup_root.resolve(), 'Intake key locations differ')
        if repo is not None:
            pins_current(repo, kind, runtime)
        base = 'intake/' + kind
        key_src, backup_src = Path(runtime['key_file']), Path(runtime['backup_key_file'])
        require(key_src.is_file() and backup_src.is_file() and not key_src.is_symlink() and not backup_src.is_symlink(), 'Intake key files required')
        files = intake_files(state_root, (database, 'worker.lock'), roots)
        require(any(f.name == database for f in files), 'Intake database missing')
        analysis_files = intake_files(analysis_cfg['analysis_root'], ('availability.sqlite3',), roots)
        decision_files = intake_files(approval_cfg['decision_root'], ('decisions.sqlite3',), roots)
        require(analysis_files and decision_files, 'Intake analysis and approval stores required')
        intake_plan += [(f, base + '/state/' + f.name) for f in files]
        intake_plan += [(key_src, base + '/keys/intake.key'), (backup_src, base + '/keys/intake-backup.key')]
        intake_plan += [(f, base + '/analysis/' + f.name) for f in analysis_files] + [(f, base + '/decisions/' + f.name) for f in decision_files]
        runtime_path, analysis_path, approval_path = (str(server_root / 'private' / (kind + '-' + n + '.json')) for n in ('runtime', 'analysis-config', 'approval-config'))
        new_runtime = {k: v for k, v in runtime.items() if k in INTAKE_RUNTIME_KEEP}
        new_runtime.update(analysis_config=analysis_path, approval_config=approval_path, key_file=str(server_root / base / 'keys/intake.key'),
                           backup_key_file=str(server_root / base / 'keys/intake-backup.key'), state_root=str(server_root / base / 'state'))
        rewritten_runtimes.append(new_runtime)
        intake_configs[field] = (runtime_path, new_runtime,
                                 {**analysis_cfg, 'intake_config': runtime_path, 'analysis_root': str(server_root / base / 'analysis')}, analysis_path,
                                 {**approval_cfg, 'decision_root': str(server_root / base / 'decisions')}, approval_path, kind)
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
    for field, (runtime_path, *_rest) in intake_configs.items():
        new_workspace[field] = runtime_path
    if intake_configs:
        new_workspace['intake_read_only'] = True
    found = problems(new_workspace, new_access, new_accountability, rewritten_runtimes)
    require(not found, 'Result would not be a safe public demonstration: ' + ', '.join(found))
    sources = [(vet(src, app_root), rel) for src, rel in plan]
    if check_only:
        # Everything above has been validated against the real configuration; nothing is created or copied.
        def size(path):
            path = Path(path)
            return sum(f.stat().st_size for f in path.rglob('*') if f.is_file()) if path.is_dir() else path.stat().st_size
        planned = [src for src, _ in sources] + [src for src, _ in intake_plan]
        return {'policy': SUMMARY, 'check_only': True, 'origin': origin, 'sources': len(planned), 'megabytes': round(sum(size(x) for x in planned) / 1e6, 1),
                'intake_stores_read_only': sorted(v[6] for v in intake_configs.values()), 'keys_printed': False, 'chain_keys_included': False,
                'uploads_and_chain_writes': 'OFF', 'log_anchoring': 'OFF', 'nothing_written': True}
    out.mkdir(mode=0o700)
    (out / 'private').mkdir(mode=0o700)
    copied = [(copy(src, out / rel), rel) for src, rel in sources]
    copied += [(copy(src, out / rel), rel) for src, rel in intake_plan]
    for field, (runtime_path, new_runtime, new_analysis, analysis_path, new_approval, approval_path, kind) in intake_configs.items():
        write_private(out / 'private' / (kind + '-runtime.json'), new_runtime)
        write_private(out / 'private' / (kind + '-analysis-config.json'), new_analysis)
        write_private(out / 'private' / (kind + '-approval-config.json'), new_approval)
    write_private(out / 'private/access-config.json', new_access)
    write_private(out / 'private/workspace-config.json', new_workspace)
    if new_accountability:
        write_private(out / 'private/accountability-config.json', new_accountability)
    files = {}
    for p in sorted(x for x in out.rglob('*') if x.is_file()):
        files[str(p.relative_to(out))] = {'sha256': digest(p), 'bytes': p.stat().st_size}
    write_private(out / 'MANIFEST.json', {'policy': SUMMARY, 'origin': origin, 'files': files})
    return {'policy': SUMMARY, 'origin': origin, 'files': len(files), 'stores': sum(1 for _, rel in copied if rel.startswith('state/')), 'intake_stores_read_only': sorted(k for _, _, _, _, _, _, k in intake_configs.values()),
            'keys_printed': False, 'chain_keys_included': False, 'uploads_and_chain_writes': 'OFF', 'log_anchoring': 'OFF'}
