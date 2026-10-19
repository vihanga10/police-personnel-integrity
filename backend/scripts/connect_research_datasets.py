"""Operator-only dataset connection; no CSV shortcut or automatic readiness.

diagnose uses Git and source-file presence only, with no configuration/secrets,
database or network access. check is local. verify/export/import use an existing
fresh audit permit and the full original loader. Import touches only UI stores.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.research_connection import Connection, POLICY
from app.access.research_connection_runtime import read_json
from app.access.policy import encoded, require
from app.access.store import private


def diagnose(repo):
    repo = Path(repo).expanduser().resolve()
    command = lambda *args: subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    required = ('backend/app/access/research_connection.py',
        'backend/app/identity/algorithm_snapshot.py', 'backend/app/access/research_bridge.py')
    return dict(status='INVENTORY_ONLY', branch=command('branch', '--show-current'),
        code_revision=command('rev-parse', 'HEAD'), clean_source=not bool(command('status', '--porcelain')),
        connector_files_present=all((repo / name).is_file() for name in required),
        original_source_replay='NOT_CHECKED', data_use_authorization='NOT_CHECKED',
        rpc_1='NOT_CHECKED', audit_permit='NOT_CHECKED', operational_witnesses='NOT_CHECKED',
        ui_dataset_connected='NOT_CHECKED', network_access=False, database_access=False)


def write_export(connection, bundle, output):
    output = Path(output).expanduser().absolute()
    private(output.parent, directory=True, repo=connection.repo)
    require(not output.exists() and not output.is_symlink(), 'New private export directory required')
    roots = [Path(v).resolve() for k, v in connection.c['source'].items() if k.endswith('_attempt')]
    roots += [Path(c['state_directory']).resolve() for c in (connection.access_config, connection.workspace_config)]
    for runtime in connection.c['officers'].values():
        for file in runtime.values():
            if file is None: continue
            value = read_json(file, connection.repo)
            if 'registry_root' in value: roots += [Path(value[k]).resolve() for k in ('registry_root', 'journal_root')]
            if 'journal' in value: roots += [Path(value[k]['root']).resolve() for k in ('journal', 'registry')]
    require(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),
            'Export must be separate from source and protected stores')
    files = {'directory-draft.json': encoded(bundle['directory'])}
    files.update({'presentation-' + officer + '-draft.json': encoded(p) for officer, p in bundle['presentations'].items()})
    require(all(len(data) <= 16 * 1024 * 1024 for data in files.values()) and
            sum(map(len, files.values())) <= 64 * 1024 * 1024, 'Export too large; select fewer officers')
    manifest = {k: v for k, v in bundle.items() if k not in ('directory', 'presentations')}
    manifest['files'] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    files['EXPORT.json'] = encoded(manifest)
    created = []
    output.mkdir(mode=0o700)
    try:
        for name, data in files.items():
            path = output / name
            with path.open('xb') as file:
                os.fchmod(file.fileno(), 0o600); created.append((path, os.fstat(file.fileno()).st_ino))
                file.write(data); file.flush(); os.fsync(file.fileno())
        fd = os.open(output, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except BaseException:
        for path, inode in reversed(created):
            require(not path.is_symlink() and path.is_file() and path.stat().st_ino == inode,
                    'Concurrent export replacement; inspect private directory')
            path.unlink()
        output.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('diagnose', 'check', 'verify', 'membership-draft', 'export', 'import'))
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--officer', action='append', default=[])
    parser.add_argument('--membership', type=Path)
    parser.add_argument('--directory-generation', type=int)
    parser.add_argument('--presentation-generation', type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--review-reference')
    args = parser.parse_args(); stage = 'ARGUMENTS'; connection = None
    try:
        if args.action == 'diagnose':
            require(args.repository is not None and args.config is None and not args.officer and
                all(x is None for x in (args.membership, args.directory_generation, args.presentation_generation, args.output, args.bundle)),
                'Diagnose needs only repository')
            require(args.review_reference is None, 'Inapplicable review reference')
            stage = 'INVENTORY'; print(json.dumps(diagnose(args.repository), indent=2)); return 0
        require(args.config is not None and args.repository is None, 'Private connection config required')
        if args.action not in ('export', 'membership-draft'):
            require(all(x is None for x in (args.membership, args.directory_generation, args.presentation_generation, args.output)), 'Inapplicable export arguments')
        if args.action != 'membership-draft': require(args.review_reference is None, 'Membership-only review reference')
        if args.action != 'import': require(args.bundle is None, 'Import-only bundle argument')
        stage = 'CONFIGURATION'; connection = Connection(args.config)
        if args.action == 'check': stage = 'LOCAL_READINESS'; result = connection.check(args.officer)
        elif args.action == 'verify': stage = 'ORIGINAL_SOURCE_AND_WITNESSES'; result = connection.verify(args.officer)
        elif args.action == 'membership-draft':
            require(args.output is not None and args.review_reference is not None and not args.officer and
                all(x is None for x in (args.membership, args.directory_generation, args.presentation_generation)), 'Membership worksheet arguments differ')
            stage = 'ORIGINAL_SOURCE_AND_WITNESSES'; payload = connection.membership_draft(args.review_reference)
            output = args.output.absolute(); private(output.parent, directory=True, repo=connection.repo)
            stage = 'PRIVATE_DRAFT_OUTPUT'
            with output.open('xb') as file:
                os.fchmod(file.fileno(), 0o600); file.write(encoded(payload)); file.flush(); os.fsync(file.fileno())
            result = dict(status='UNSIGNED_MEMBERSHIP_WORKSHEET', officers=len(payload['officers']), current_scopes_assessed=False,
                          administrator_review_and_signature_required=True, ui_connected=False)
        elif args.action == 'export':
            require(args.membership is not None and args.output is not None and
                args.directory_generation is not None and (not args.officer or args.presentation_generation is not None), 'Complete export arguments required')
            require(len(args.officer) == len(set(args.officer)), 'Duplicate officer refused')
            stage = 'ORIGINAL_SOURCE_AND_WITNESSES'
            bundle = connection.export(args.membership, generation=args.directory_generation,
                selections={o: args.presentation_generation for o in args.officer})
            stage = 'PRIVATE_DRAFT_OUTPUT'; write_export(connection, bundle, args.output)
            result = dict(status='UNSIGNED_DRAFTS_EXPORTED', presentations=len(bundle['presentations']),
                ui_connected=False, signatures_required=True, source_public_sha256=bundle['source_public_sha256'])
        else:
            require(args.bundle is not None and not args.officer, 'Private reviewed import manifest required')
            stage = 'SIGNED_IMPORT_INPUTS'; manifest = read_json(args.bundle, connection.repo)
            require(type(manifest) is dict and set(manifest) == {'policy', 'directory', 'presentations', 'disclosures'} and
                manifest['policy'] == POLICY and type(manifest['presentations']) is list and type(manifest['disclosures']) is list,
                'Import manifest differs')
            files = [manifest['directory'], *manifest['presentations'], *manifest['disclosures']]
            connection._watch(args.bundle)
            for path in files: connection._watch(path)
            directory = read_json(manifest['directory'], connection.repo)
            presentations = [read_json(path, connection.repo) for path in manifest['presentations']]
            disclosures = [read_json(path, connection.repo) for path in manifest['disclosures']]
            stage = 'SIGNED_CACHE_IMPORT'; result = connection.install(directory, presentations, disclosures)
        print(json.dumps(result, indent=2)); return 0
    except Exception:
        failed_stage = connection.stage if connection is not None and stage in ('LOCAL_READINESS', 'ORIGINAL_SOURCE_AND_WITNESSES', 'SIGNED_CACHE_IMPORT') else stage
        print(json.dumps(dict(status='BLOCKED', stage=failed_stage, ui_connection_complete=False,
            retry_import_may_be_required=stage == 'SIGNED_CACHE_IMPORT',
            research_storage_changed=False, audit_permit_issued=False, blockchain_submission=False)))
        print('Check the stage requirements in docs/operational-research-connection-v1.md. No default data, permission or readiness was supplied.', file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
