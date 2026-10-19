"""Authenticate the exact committed research snapshot before algorithm execution.

This loader reads private artifacts. Live readiness is supplied by the existing
short-lived dual-chain audit permit; this function never invents a new permit.
"""
from datetime import datetime
import json
import os

from app.identity.audit_gate import require_audit_permit
from app.identity.bind_evidence_destinations import load_attempt, private_path
from app.identity.evidence_bundle_v2 import open_artifact
from app.identity.generate_protected_commitments import load_binding, load_keys, verify_saved
from app.identity.historical_reconstruction import require
from app.identity.inspect_stage2_coverage import ROWS
from app.identity.protected_commitment import generate, digest, POLICY as COMMITMENT_POLICY
from app.identity.public_anchor_authorization import PUBLIC_SHA
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS



def load_verified_snapshot(args, repo, revision):
    """Both-key recovery and all-officer commitment replay cannot be bypassed."""
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
    captured_at = datetime.fromisoformat(manifest['snapshot']['collection_started_at'])
    return dict(crypto=crypto, backup=backup, public=public, context=context,
        envelope=permit_envelope, manifest=manifest, catalog=catalog, bindings=bindings,
        captured_at=captured_at)
