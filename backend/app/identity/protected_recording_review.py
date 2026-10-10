"""Permit-guarded review of bound recording metadata, not historical visibility.

Trusted backend API only. The public entry loads and replays the original
anchored snapshot. No database, chain, source or accepted-state writes occur.
"""
from copy import deepcopy
from pathlib import Path
import json
import os
import tempfile

from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.bitemporal_timestamp_binding import verify_recording_timestamp, payload
from app.identity.evidence_bundle_v2 import seal_artifact, open_artifact
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY = 'PROTECTED_BOUND_RECORDING_REVIEW_V1'


def review_recording_rows(args, repo, revision, rows, raw_ids, destination):
    """Use the existing full replay and live-readiness loader without waivers."""
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot = load_verified_snapshot(args, repo, revision)
    return review_loaded_snapshot(snapshot, rows, raw_ids, destination, repo)


def review_loaded_snapshot(snapshot, rows, raw_ids, destination, repo):
    """Internal trusted-runner boundary: snapshot MUST come from full replay.

    A permit alone does not authenticate catalog/binding dictionaries. Never
    expose this function to request-supplied snapshots or receipt hints.
    Selection completeness means only the explicitly selected raw IDs.
    """
    permit = AlgorithmPermit(snapshot)
    permit.check(snapshot)
    selected = tuple(raw_ids)
    require(bool(selected) and len(set(selected)) == len(selected),
            'Unique nonempty recording selection required.')
    catalog, bindings = snapshot['catalog'], snapshot['bindings']['raw_bindings']
    require(all(raw in catalog and raw in bindings for raw in selected),
            'Recording selection outside captured evidence.')
    # Detect changes after entry; full anchored replay is the loader's job.
    source_digest = digest(dict(catalog=catalog, bindings=bindings))
    expected = {raw: (deepcopy(catalog[raw]), deepcopy(bindings[raw])) for raw in selected}
    verified = {}
    for row in rows:
        permit.check(snapshot)
        raw = row['raw_record_id']
        require(raw in expected and raw not in verified, 'Recording row selection differs.')
        item, bound = expected[raw]
        verified[raw] = payload(verify_recording_timestamp(deepcopy(row), item, {raw: bound}))
    require(set(verified) == set(selected), 'Recording selection incomplete.')
    require(digest(dict(catalog=catalog, bindings=bindings)) == source_digest,
            'Captured recording evidence changed.')
    result = dict(policy=POLICY, scope='EXPLICIT_SELECTED_ROWS_ONLY',
        selected_rows=len(selected), records=[verified[raw] for raw in sorted(selected)],
        visibility_time_established=False, complete_history_established=False,
        historical_known_as_of_supported=False, accepted_state=None)
    binding = dict(artifact='PROTECTED_BOUND_RECORDING_REVIEW', policy=POLICY,
        source_context=deepcopy(snapshot['context']), result_sha256=digest(result))
    envelope = seal_artifact(snapshot['crypto'], snapshot['backup'], result, binding)
    require(open_artifact(snapshot['crypto'], envelope, binding) == result and
        open_artifact(snapshot['backup'], envelope, binding) == result,
        'Protected recording review recovery differs.')
    permit.check(snapshot)
    destination = Path(destination).expanduser().absolute()
    repo = Path(repo).expanduser().resolve()
    require(not destination.is_relative_to(repo), 'Private review output must be outside repository.')
    require(not any(p.is_symlink() for p in (destination, *destination.parents)),
            'Private review output symlink refused.')
    parent = destination.parent
    require(parent.is_dir() and not parent.stat().st_mode & 0o077 and
        parent.stat().st_uid == os.getuid(), 'Existing owner-only output directory required.')
    data = (json.dumps(envelope, sort_keys=True, allow_nan=False) + '\n').encode()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=parent, prefix='.recording-review-', delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Recheck after encryption and staging, immediately before publication.
        permit.check(snapshot)
        os.link(temporary, destination)
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    # No personnel identifiers or ciphertext in terminal-facing summary.
    return dict(policy=POLICY, selected_rows=len(selected),
        historical_known_as_of_supported=False)
