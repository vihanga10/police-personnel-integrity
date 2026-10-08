"""Create dedicated keys, generate from captured evidence, or verify a saved commitment attempt."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from app.identity.bind_evidence_destinations import load_attempt, private_path
from app.identity.destination_binding import POLICY as DESTINATION_POLICY, require
from app.identity.evidence_bundle_v2 import open_artifact, seal_artifact
from app.identity.inspect_stage2_coverage import ROWS
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS
from app.identity.protected_commitment import POLICY, KEY_POLICY, CommitmentKeys, generate, digest
from app.intake.registration_receipt import save_receipt


def private_output(path, repo):
    path = path.expanduser().absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)) and
            not path.resolve().is_relative_to(repo), 'Private output must be outside the repository without symlinks.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return private_path(path, True)


def load_keys(primary, backup, repo):
    paths = [private_path(p) for p in (primary, backup)]
    require(paths[0].resolve() != paths[1].resolve() and not os.path.samefile(*paths) and
            all(not p.resolve().is_relative_to(repo) for p in paths), 'Independent off-repository key copies required.')
    values = [json.loads(p.read_text()) for p in paths]
    keys = [CommitmentKeys(v) for v in values]
    require(values[0] == values[1], 'Commitment backup differs.')
    return keys[0]


def initialize_keys(primary, backup, repo):
    paths = [p.expanduser().absolute() for p in (primary, backup)]
    require(paths[0] != paths[1] and all(not p.exists() and not p.is_symlink() for p in paths),
            'New separate key paths required; existing keys are never replaced.')
    for path in paths:
        private_output(path.parent, repo)
    data = dict(policy=KEY_POLICY, version='commit-v1', content_key=base64.b64encode(os.urandom(32)).decode(),
                publication_key=base64.b64encode(os.urandom(32)).decode())
    CommitmentKeys(data)
    # Each copy is published atomically. If the second save fails, preserve the first for recovery.
    save_receipt(data, paths[0]); save_receipt(data, paths[1])
    load_keys(paths[0], paths[1], repo)


def load_binding(directory, manifest, bundle_directory, crypto, backup):
    directory = private_path(directory, True)
    summary = json.loads(private_path(directory/'PASSED.json').read_text())
    expected = dict(policy=DESTINATION_POLICY, status='PASSED', source_rows=167865, officers=6596,
                    sql_tables=35, sql_records=794200, mongo_collections=17, mongo_documents=154673)
    require(all(summary.get(k) == v for k, v in expected.items()), 'Passed destination binding required.')
    path = private_path(directory/'destination-bindings.encrypted.json')
    envelope = json.loads(path.read_text())
    binding = dict(artifact='DESTINATION_BINDINGS', destination_policy=DESTINATION_POLICY,
                   source_snapshot=manifest['snapshot'], collector_revision=summary['code_revision'])
    payload = open_artifact(crypto, envelope, binding)
    require(open_artifact(backup, envelope, binding) == payload and
            payload['collector_revision'] == summary['code_revision'] and
            payload['source_attempt_id'] == bundle_directory.name, 'Destination attempt binding differs.')
    require(set(payload) == {'policy', 'raw_bindings', 'officer_bindings', 'shared_bindings', 'sql_records',
                            'mongo_documents', 'source_snapshot', 'source_bundle_policy', 'source_attempt_id',
                            'collector_revision', 'collected_at', 'sql_table_counts'}, 'Destination artifact fields differ.')
    return payload, hashlib.sha256(path.read_bytes()).hexdigest()



def verify_saved(directory, crypto, backup, public, private, binding, expected_summary):
    directory = private_path(directory, True)
    summary = json.loads(private_path(directory/'PASSED.json').read_text())
    envelope = json.loads(private_path(directory/'commitments.encrypted.json').read_text())
    recovered = open_artifact(crypto, envelope, binding)
    require(open_artifact(backup, envelope, binding) == recovered == private, 'Saved protected commitments differ.')
    require(json.loads(private_path(directory/'public-commitments.json').read_text()) == public and
            summary == expected_summary, 'Saved publication payload or summary differs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--initialize-keys', action='store_true')
    mode.add_argument('--verify-attempt', type=Path)
    for name in ('commitment-key-file', 'backup-commitment-key-file'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('key-file', 'backup-key-file', 'bundle-attempt', 'binding-attempt', 'output-root'):
        parser.add_argument('--'+name, type=Path)
    args = parser.parse_args(); attempt = None
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(),
                'Commit source before execution.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        if args.initialize_keys:
            require(not any((args.key_file, args.backup_key_file, args.bundle_attempt, args.binding_attempt, args.output_root)),
                    'Key setup does not consume evidence.')
            initialize_keys(args.commitment_key_file, args.backup_commitment_key_file, repo)
            print('Dedicated commitment key setup: PASSED')
            print('Separate owner-only key copies verified. No database, evidence or blockchain changes.')
            return 0
        require(all((args.key_file, args.backup_key_file, args.bundle_attempt, args.binding_attempt)), 'Evidence/key paths required.')
        require(args.verify_attempt is not None or args.output_root is not None, 'Output root required.')
        require(not (args.verify_attempt and args.output_root), 'Choose verification or new output.')
        require(args.key_file.resolve() != args.backup_key_file.resolve(), 'Separate identity key copies required.')
        crypto, backup = private_key_file(private_path(args.key_file)), private_key_file(private_path(args.backup_key_file))
        verify_recovery(crypto, backup)
        keys = load_keys(args.commitment_key_file, args.backup_commitment_key_file, repo)
        keys.assert_separate(crypto); keys.assert_separate(backup)
        bundle_directory = private_path(args.bundle_attempt, True)
        manifest, catalog = load_attempt(bundle_directory, crypto, backup)
        bindings, binding_file_sha = load_binding(args.binding_attempt, manifest, bundle_directory, crypto, backup)
        counts = dict(SQL_COUNTS, **{'staging.intake_batch': 1, 'staging.intake_file': len(ROWS), 'staging.raw_record': sum(ROWS.values())})
        print('Captured evidence loaded; validating commitments for 6,596 officers.', flush=True)
        public, private = generate(manifest, catalog, bindings, keys, generator_revision=revision,
                                   sql_counts=counts, mongo_counts=MONGO_COUNTS)
        require(len(public['officers']) == 6596 and len(private['raw_commitments']) == 167865, 'Commitment coverage differs.')
        private.update(bundle_attempt_id=bundle_directory.name, binding_attempt_id=args.binding_attempt.name,
                       binding_artifact_sha256=binding_file_sha)
        binding = dict(artifact='PROTECTED_COMMITMENTS', policy=POLICY, context=private['context'])
        if args.verify_attempt:
            summary = dict(policy=POLICY, status='PASSED', officers=6596, source_rows=167865,
                           sql_records=794200, mongo_documents=154673, code_revision=revision, public_payload_sha256=digest(public))
            verify_saved(args.verify_attempt, crypto, backup, public, private, binding, summary)
            print('Protected commitment replay verification: PASSED')
        else:
            output = private_output(args.output_root, repo)
            attempt = output/str(uuid4()); attempt.mkdir(mode=0o700)
            save_receipt(dict(policy=POLICY, status='STARTED', created_at=datetime.now(timezone.utc).isoformat()), attempt/'STARTED.json')
            print('Protected commitment attempt directory:', attempt, flush=True)
            envelope = seal_artifact(crypto, backup, private, binding)
            save_receipt(envelope, attempt/'commitments.encrypted.json')
            # This publication-only file contains keyed digests and opaque handles, never UUIDs or source cells.
            save_receipt(public, attempt/'public-commitments.json')
            summary = dict(policy=POLICY, status='PASSED', officers=6596, source_rows=167865,
                           sql_records=794200, mongo_documents=154673, code_revision=revision, public_payload_sha256=digest(public))
            save_receipt(summary, attempt/'PASSED.json')
            print('Protected commitment generation: PASSED'); print(json.dumps(summary, sort_keys=True))
        print('All source rows and scoped destinations covered; shared/reference evidence protected. Classification remains UNASSESSED.')
        print('Captured-snapshot verification only; no live database check, blockchain submission, audit or human disclosure.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY, status='STOPPED', error_type=type(error).__name__), attempt/'STOPPED.json')
        print('Protected commitment workflow stopped:', type(error).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
