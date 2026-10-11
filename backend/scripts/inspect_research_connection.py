"""Read-only Mac inventory for configuring the original dataset connection.

No encrypted artifact/key/credential contents, CSV rows, database, wallet or RPC
are read. Only allowlisted artifact names and public commitment metadata are
inspected within explicitly supplied roots. Presence does not establish readiness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

MARKERS = {
    'officer-manifests.encrypted.json': 'bundle_attempt',
    'destination-bindings.encrypted.json': 'binding_attempt',
    'public-commitments.json': 'commitment_attempt',
    'audit-permit.encrypted.json': 'audit_gate_attempt',
    'access-config.json': 'access_configuration',
    'workspace-config.json': 'workspace_configuration',
    'connection-config.json': 'connection_configuration',
    'Step_1_Controlled_Data_Intake_Batch.zip': 'original_intake_archive',
}


def inventory(repository, roots):
    repo = Path(repository).expanduser().resolve()
    git = lambda *args: subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
    found = {value: [] for value in MARKERS.values()}; seen = set(); scanned = 0; incomplete = False
    for root in roots:
        root = Path(root).expanduser().absolute()
        if root.is_symlink() or not root.is_dir(): incomplete = True; continue
        stack = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                for entry in os.scandir(directory):
                    scanned += 1
                    if scanned > 50000: incomplete = True; stack.clear(); break
                    if entry.is_symlink(): continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in ('node_modules', '.git'): continue
                        if depth < 8: stack.append((Path(entry.path), depth + 1))
                        else: incomplete = True
                        continue
                    if entry.name not in MARKERS or not entry.is_file(follow_symlinks=False): continue
                    file = Path(entry.path).absolute()
                    if file in seen: continue
                    seen.add(file); info = file.stat()
                    item = dict(path=str(file), owner_only=info.st_uid == os.getuid() and
                                info.st_mode & 0o077 == 0 and info.st_nlink == 1,
                                parent_owner_only=file.parent.stat().st_uid == os.getuid() and file.parent.stat().st_mode & 0o077 == 0)
                    if entry.name == 'public-commitments.json' and info.st_size <= 16 * 1024 * 1024:
                        try:
                            public = json.loads(file.read_bytes())
                            if type(public) is not dict or public.get('policy') != 'OFFICER_PROTECTED_COMMITMENT_V1' or type(public.get('officers')) is not list:
                                raise ValueError('Public publication metadata required')
                            wire = json.dumps(public, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
                            item['public_payload_sha256'] = hashlib.sha256(wire).hexdigest()
                            item['reported_officer_count'] = len(public.get('officers', []))
                        except Exception: item['public_metadata'] = 'UNREADABLE'
                    found[MARKERS[entry.name]].append(item)
            except OSError: incomplete = True
    return dict(status='INVENTORY_ONLY', branch=git('branch', '--show-current'), code_revision=git('rev-parse', 'HEAD'),
        clean_source=not bool(git('status', '--porcelain')), artifacts=found, scan_incomplete=incomplete,
        scanned_entries=scanned, data_use_authorization='NOT_VALIDATED', original_replay='NOT_EXECUTED',
        audit_permit='NOT_AUTHENTICATED', rpc_1='NOT_TESTED', production_witnesses='NOT_TESTED',
        research_database_access=False, blockchain_submission=False, secret_contents_included=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--data-root', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = inventory(args.repository, args.data_root); data = (json.dumps(report, indent=2) + '\n').encode()
        if args.output:
            output = args.output.expanduser().absolute(); repo = args.repository.expanduser().resolve()
            if output.resolve().is_relative_to(repo) or any(p.is_symlink() for p in (output, *output.parents)):
                raise ValueError('Report path must be separate from repository and symlinks')
            with output.open('xb') as file:
                os.fchmod(file.fileno(), 0o600); file.write(data); file.flush(); os.fsync(file.fileno())
            print('Read-only inventory saved:', output)
            print('No source rows, encrypted artifacts, secrets, database or RPC were read.')
        else: print(data.decode(), end='')
        return 0
    except Exception:
        print('Inventory stopped. Check repository, explicit data roots and a new output path; no research state changed.', file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
