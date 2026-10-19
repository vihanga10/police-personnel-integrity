"""Authenticate saved commitments, freshly reconcile both stores and compare exact fingerprints."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import text
from database import create_identity_engine
from settings import Settings
from app.identity.bind_evidence_destinations import private_path, load_attempt, collect_sql, collect_mongo
from app.identity.generate_protected_commitments import private_output, load_keys, load_binding, verify_saved
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.protected_commitment import POLICY as COMMITMENT_POLICY, generate, digest
from app.identity.evidence_bundle_v2 import seal_artifact
from app.identity.inspect_stage2_coverage import ROWS
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS, check_counts
from app.identity.destination_binding import require
from app.identity.anchor_gate import POLICY, compare_live, publication_plan
from app.intake.registration_receipt import save_receipt


def authenticate_commitments(directory, manifest, catalog, captured, binding_sha, bundle_directory,
                              binding_directory, crypto, backup, keys):
    directory = private_path(directory, True)
    summary = json.loads(private_path(directory/'PASSED.json').read_text())
    require(summary.get('status') == 'PASSED' and summary.get('policy') == COMMITMENT_POLICY and
            re.fullmatch(r'[0-9a-f]{40}', summary.get('code_revision', '')), 'Passed commitment attempt required.')
    # Keep the original generator revision: advancing Git must not rewrite historical commitment values.
    original_revision = summary['code_revision']
    counts = dict(SQL_COUNTS, **{'staging.intake_batch': 1, 'staging.intake_file': len(ROWS), 'staging.raw_record': sum(ROWS.values())})
    public, private = generate(manifest, catalog, captured, keys, generator_revision=original_revision,
                               sql_counts=counts, mongo_counts=MONGO_COUNTS)
    private.update(bundle_attempt_id=bundle_directory.name, binding_attempt_id=binding_directory.name,
                   binding_artifact_sha256=binding_sha)
    binding = dict(artifact='PROTECTED_COMMITMENTS', policy=COMMITMENT_POLICY, context=private['context'])
    expected_summary = dict(policy=COMMITMENT_POLICY, status='PASSED', officers=6596, source_rows=167865,
                            sql_records=794200, mongo_documents=154673, code_revision=original_revision, public_payload_sha256=digest(public))
    verify_saved(directory, crypto, backup, public, private, binding, expected_summary)
    return public, publication_plan(public)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
                 'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'credential-root', 'output-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); engine = None; attempt = None
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(), 'Commit source before live gate.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        require(args.key_file.resolve() != args.backup_key_file.resolve(), 'Separate identity key copies required.')
        crypto, backup = private_key_file(private_path(args.key_file)), private_key_file(private_path(args.backup_key_file))
        verify_recovery(crypto, backup)
        keys = load_keys(args.commitment_key_file, args.backup_commitment_key_file, repo)
        keys.assert_separate(crypto); keys.assert_separate(backup)
        bundle_directory, binding_directory = private_path(args.bundle_attempt, True), private_path(args.binding_attempt, True)
        manifest, catalog = load_attempt(bundle_directory, crypto, backup)
        captured, binding_sha = load_binding(binding_directory, manifest, bundle_directory, crypto, backup)
        public, plan = authenticate_commitments(args.commitment_attempt, manifest, catalog, captured, binding_sha,
                                                bundle_directory, binding_directory, crypto, backup, keys)
        output = private_output(args.output_root, repo); attempt = output/str(uuid4()); attempt.mkdir(mode=0o700)
        save_receipt(dict(policy=POLICY, status='STARTED'), attempt/'STARTED.json')
        print('Live anchor gate attempt directory:', attempt, flush=True)
        result = subprocess.run([sys.executable, '-u', '-m', 'app.identity.review_stage2', '--key-file', str(args.key_file),
            '--backup-key-file', str(args.backup_key_file), '--credential-root', str(args.credential_root),
            '--attempt-root', str(attempt/'reconciliation')], cwd=repo/'backend')
        require(result.returncode == 0, 'Fresh reconciliation failed; no anchoring readiness.')
        settings = Settings()
        require((settings.host, settings.port, settings.name, settings.user) == ('127.0.0.1', 5432, 'police_identity', 'police_identity_app'), 'Unexpected SQL target.')
        fingerprint_started_at = datetime.now(timezone.utc).isoformat()
        engine = create_identity_engine(settings)
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user,current_database()')).one()) == ('police_identity_app', 'police_identity'), 'Connected SQL target differs.')
                inventory, counts = collect_sql(connection, catalog, manifest, crypto, backup)
                collect_mongo(inventory, args.credential_root)
                compare_live(captured, inventory.finish(), counts)
        check_counts(args.credential_root)
        gate = dict(policy=POLICY, status='PASSED', checked_at=fingerprint_started_at, completed_at=datetime.now(timezone.utc).isoformat(),
            code_revision=revision, commitment_attempt_id=args.commitment_attempt.name,
            public_payload_sha256=digest(public), scope=dict(officers=6596, source_rows=167865, sql_records=794200, mongo_documents=154673),
            binding_artifact_sha256=binding_sha, plan=plan, historical_claims='UNASSESSED', max_age_seconds=600)
        envelope = seal_artifact(crypto, backup, gate, dict(artifact='LIVE_ANCHOR_GATE', policy=POLICY, public_payload_sha256=digest(public)))
        save_receipt(envelope, attempt/'live-gate.encrypted.json')
        save_receipt(plan, attempt/'publication-plan.json')
        summary = dict(policy=POLICY, status='PASSED', officers=6596, source_rows=167865, sql_records=794200,
                       mongo_documents=154673, public_payload_sha256=digest(public), chunks=66, planned_transactions=68, code_revision=revision)
        save_receipt(summary, attempt/'PASSED.json')
        print('Live evidence anchor gate: PASSED'); print(json.dumps(summary, sort_keys=True))
        print('Captured source/membership/destination versions match freshly reconciled stores. Original commitments remain unchanged.')
        print('No database writes, Fabric network setup, blockchain submissions, audit or human disclosure. Gate freshness limit: 10 minutes; rerun before future submission.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY, status='STOPPED', error_type=type(error).__name__), attempt/'STOPPED.json')
        print('Live evidence gate stopped:', type(error).__name__)
        return 1
    finally:
        if engine is not None: engine.dispose()


if __name__ == '__main__': raise SystemExit(main())
