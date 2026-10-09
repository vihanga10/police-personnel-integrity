"""Permit-gated reconstruction of reported candidates; encrypted output only."""
import argparse
from collections import Counter
from dataclasses import asdict
from datetime import date, datetime
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from app.identity.audit_gate import require_audit_permit
from app.identity.bind_evidence_destinations import load_attempt, private_path
from app.identity.evidence_bundle_v2 import open_artifact, seal_artifact
from app.identity.generate_protected_commitments import load_binding, load_keys, private_output, verify_saved
from app.identity.historical_reconstruction import POLICY, reconstruct, require
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.inspect_stage2_coverage import ROWS
from app.identity.protected_commitment import generate, digest, POLICY as COMMITMENT_POLICY
from app.identity.public_anchor_authorization import PUBLIC_SHA
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS
from app.intake.registration_receipt import save_receipt


# Require explicit evidence paths and a research date rather than invent defaults.
def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
        'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'audit-gate-attempt', 'output-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--on', type=date.fromisoformat, required=True,
        help='Requested reported-state date, YYYY-MM-DD; no accepted state is inferred.')
    return parser.parse_args(argv)


def subject_index(manifest, catalog):
    # Linear scan rather than scanning all 167,865 rows once per officer.
    buckets = {b['officer_uid']: {} for b in manifest['bundles']}
    for raw, row in catalog.items():
        if row['filename'] in HEADERS:
            for link in row['candidate_links']:
                if link['role'] == 'officer_nic_no':
                    require(link['officer_uid'] in buckets and raw not in buckets[link['officer_uid']],
                        'Subject indexing differs.')
                    buckets[link['officer_uid']][raw] = row
    return buckets


def permitted_projection(officer, claims, *, on, captured_at, envelope, crypto, backup, public, context, now=None):
    # Reject stale or mismatched authorization before interpreting any personnel claims.
    require_audit_permit(envelope, crypto, backup, public, context, now=now)
    values = reconstruct(officer, claims, on=on, captured_at=captured_at)
    # Recheck after computation so expiry cannot yield an authorized result.
    require_audit_permit(envelope, crypto, backup, public, context, now=now)
    return values


def main(argv=None):
    args = arguments(argv); attempt = None
    # New directories/files must be accessible only to the operating account.
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[3]
        # Bind execution to a committed source revision that a fresh permit can identify.
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(),
            'Commit reviewed source first.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        # Exercise recovery before processing; two paths must not be the same key file.
        primary_path, backup_path = private_path(args.key_file), private_path(args.backup_key_file)
        require(not os.path.samefile(primary_path, backup_path), 'Separate recovery key copies required.')
        crypto, backup = private_key_file(primary_path), private_key_file(backup_path)
        verify_recovery(crypto, backup)
        # The pinned publication digest identifies the exact already-anchored batch.
        public = json.loads(private_path(args.commitment_attempt / 'public-commitments.json').read_text())
        require(digest(public) == PUBLIC_SHA, 'Exact original publication required.')
        permit_envelope = json.loads(private_path(args.audit_gate_attempt / 'audit-permit.encrypted.json').read_text())
        # Bind current code, chosen attempt IDs and the exact encrypted destination artifact.
        import hashlib
        binding_sha = hashlib.sha256(private_path(args.binding_attempt / 'destination-bindings.encrypted.json').read_bytes()).hexdigest()
        context = dict(code_revision=revision, bundle_attempt_id=args.bundle_attempt.name,
            binding_attempt_id=args.binding_attempt.name, commitment_attempt_id=args.commitment_attempt.name,
            binding_artifact_sha256=binding_sha)
        require_audit_permit(permit_envelope, crypto, backup, public, context)
        keys = load_keys(args.commitment_key_file, args.backup_commitment_key_file, repo)
        keys.assert_separate(crypto); keys.assert_separate(backup)
        manifest, catalog = load_attempt(args.bundle_attempt, crypto, backup)
        bindings, actual_sha = load_binding(args.binding_attempt, manifest, args.bundle_attempt, crypto, backup)
        require(actual_sha == binding_sha, 'Destination artifact changed during loading.')
        # Recover the original generation context using both protected key copies.
        saved_envelope = json.loads(private_path(args.commitment_attempt / 'commitments.encrypted.json').read_text())
        saved = open_artifact(crypto, saved_envelope, saved_envelope['binding'])
        require(open_artifact(backup, saved_envelope, saved_envelope['binding']) == saved, 'Commitment recovery differs.')
        # Reproduce original commitments with their original generator revision, not this runner's revision.
        original_revision = saved['context']['generator_revision']
        counts = dict(SQL_COUNTS, **{'staging.intake_batch': 1, 'staging.intake_file': len(ROWS), 'staging.raw_record': sum(ROWS.values())})
        regenerated, private = generate(manifest, catalog, bindings, keys, generator_revision=original_revision,
            sql_counts=counts, mongo_counts=MONGO_COUNTS)
        # Integrity requires matching all original commitments, not merely matching counts.
        require(regenerated == public and digest(regenerated) == PUBLIC_SHA, 'Captured evidence differs from anchored commitments.')
        private.update(bundle_attempt_id=args.bundle_attempt.name, binding_attempt_id=args.binding_attempt.name,
            binding_artifact_sha256=binding_sha)
        summary = dict(policy=COMMITMENT_POLICY, status='PASSED', officers=6596, source_rows=167865,
            sql_records=794200, mongo_documents=154673, code_revision=original_revision, public_payload_sha256=PUBLIC_SHA)
        verify_saved(args.commitment_attempt, crypto, backup, public, private, saved_envelope['binding'], summary)
        require_audit_permit(permit_envelope, crypto, backup, public, context)
        buckets = subject_index(manifest, catalog)
        require(len(buckets) == 6596, 'Complete officer coverage required.')
        # This is the source snapshot's capture label, not an accepted transaction history.
        captured_at = datetime.fromisoformat(manifest['snapshot']['collection_started_at'])
        attempt = private_output(args.output_root, repo) / str(uuid4()); attempt.mkdir(mode=0o700)
        print('Historical reconstruction attempt directory:', attempt, flush=True)
        aggregate, chunk, files = Counter(), [], 0
        # Process all officers in deterministic order and retain unresolved answers.
        for number, (officer, selected) in enumerate(sorted(buckets.items()), 1):
            values = permitted_projection(officer, source_claims(officer, selected, bindings['raw_bindings']),
                on=args.on, captured_at=captured_at, envelope=permit_envelope, crypto=crypto, backup=backup,
                public=public, context=context)
            chunk.append(dict(officer_uid=officer, projections=[asdict(v) for v in values]))
            aggregate.update(v.dimension + ':' + v.status for v in values)
            if len(chunk) == 100 or number == len(buckets):
                artifact_binding = dict(artifact='REPORTED_HISTORY', policy=POLICY, context=context,
                    public_payload_sha256=PUBLIC_SHA, on=args.on.isoformat(), chunk=files)
                # JSON encode dates explicitly; no source text normalization.
                payload = json.loads(json.dumps(dict(policy=POLICY, on=args.on.isoformat(),
                    known_snapshot_capture=captured_at.isoformat(), context=context, results=chunk),
                    default=lambda v: v.isoformat()))
                # Verify encrypted primary/backup recovery before publishing a private artifact.
                encrypted = seal_artifact(crypto, backup, payload, artifact_binding)
                require_audit_permit(permit_envelope, crypto, backup, public, context)
                save_receipt(encrypted, attempt / ('history-%03d.encrypted.json' % files))
                files += 1; chunk = []
            if number % 500 == 0 or number == len(buckets):
                print('Reported history progress:', number, '/', len(buckets), flush=True)
        require_audit_permit(permit_envelope, crypto, backup, public, context)
        # PASSED records complete processing; it does not certify historical truth.
        save_receipt(dict(policy=POLICY, status='PASSED', code_revision=revision, officers=len(buckets),
            on=args.on.isoformat(), aggregate=dict(sorted(aggregate.items())), encrypted_artifacts=files,
            accepted_state_claim=False, classification='UNASSESSED', public_payload_sha256=PUBLIC_SHA,
            context=context), attempt / 'PASSED.json')
        print('Reported historical reconstruction: PASSED')
        print(json.dumps(dict(sorted(aggregate.items()))))
        print('Reported candidates and uncertainty only; encrypted outputs. No accepted state, authority decision, database or blockchain writes.')
        return 0
    # Keep incomplete private artifacts for diagnosis; never label a partial run complete.
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY, status='STOPPED', error_type=type(error).__name__,
                completed=False, classification='UNASSESSED'), attempt / 'STOPPED.json')
        print('Historical reconstruction stopped:', type(error).__name__)
        print('No completed result issued. Private partial artifacts and original evidence preserved.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
