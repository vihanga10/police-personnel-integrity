"""Trusted backend contradiction-history runner; no CLI or public request endpoint.

Public entry requires the original full anchored replay and configured mTLS.
The loaded entry is internal only: never accept a request-supplied snapshot,
registry, key map, transport, permit or destination.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import date, datetime
from pathlib import Path
import json
import os
import tempfile

from app.identity.algorithm_permit import AlgorithmPermit
from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import recording_checkpoint_registry as R
from app.identity.witness_secure_transport import HTTPSWitnessTransport
from app.identity.evidence_bundle_v2 import canonical, seal_artifact, open_artifact
from app.identity.historical_reconstruction import require
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.protected_commitment import digest

POLICY = 'PROTECTED_OBSERVED_CONTRADICTIONS_V1'
from app.identity.bitemporal_contradictions import compare_history


def run_contradiction_query(args, repo, revision, adapter, *, officer_uid,
        effective_on, known_at, destination):
    """Backend-configured adapter only; preserves the existing readiness gate."""
    require(type(adapter) is W.WitnessedCheckpointRegistry and
        type(adapter.client) is W.WitnessClient and
        type(adapter.client.exchange) is HTTPSWitnessTransport,
        'Configured mutual-TLS witness transport required.')
    transport = adapter.client.exchange
    require(Path(transport.repo).expanduser().resolve() == Path(repo).expanduser().resolve() and
        all(transport.profile[k] == adapter.client.scope[k] for k in W.SCOPE) and
        transport.writer_key_id == adapter.client.key_id and
        transport.profile['writer_keys_sha256'] == W._key_digest(adapter.client.writer_keys) and
        transport.profile['witness_keys_sha256'] == W._key_digest(adapter.client.witness_keys),
        'Secure transport witness scope or key pins differ.')
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot = load_verified_snapshot(args, repo, revision)
    return run_loaded_comparison(snapshot, repo, adapter, officer_uid=officer_uid,
        effective_on=effective_on, known_at=known_at, destination=destination)


def _wire(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError('Unsupported protected result value.')


def run_loaded_comparison(snapshot, repo, adapter, *, officer_uid,
        effective_on, known_at, destination):
    """Internal full-replay boundary; in-process transports are test fixtures only.

    Fresh witness reads authenticate the selected tip at validation instants,
    not a permanent claim that no later observation exists. Output is an
    immutable encrypted comparison receipt, not accepted state or anchored findings.
    """
    require(type(adapter) is W.WitnessedCheckpointRegistry and
        type(adapter.registry) is R.CheckpointRegistry and
        type(adapter.client) is W.WitnessClient, 'Trusted witnessed registry required.')
    permit = AlgorithmPermit(snapshot)
    permit.check(snapshot)
    repo = Path(repo).expanduser().resolve()
    registry = adapter.registry
    require(registry.repo == repo, 'Registry repository differs.')
    destination = Path(destination).expanduser().absolute()
    require('..' not in destination.parts, 'Query output traversal refused.')
    parent = J._private_root(destination.parent, repo)
    require(not destination.is_symlink() and not destination.exists(),
        'New private query output required.')
    for root in (registry.root, registry.journal_root):
        require(not parent.is_relative_to(root) and not root.is_relative_to(parent),
            'Query output must be separate from protected stores.')
    source = dict(catalog=deepcopy(snapshot['catalog']),
        bindings=deepcopy(snapshot['bindings']['raw_bindings']))
    source_sha = digest(source)
    context = deepcopy(snapshot['context'])
    publication_sha = digest(snapshot['public'])
    scope = deepcopy(adapter.client.scope)
    key_pins = (W._key_digest(adapter.client.writer_keys), W._key_digest(adapter.client.witness_keys))
    # Revalidate adapter configuration (including its key-domain separation).
    W.WitnessedCheckpointRegistry(registry, adapter.client)
    tip = adapter.client.head()
    temporary = None
    with registry._locked():
        selection = registry._selection(registry._entries(tip), tip)
        state = selection['state']
        base = state['baseline']
        require(base['scope']['officer_uid'] == officer_uid,
            'Requested officer differs from authenticated journal.')
        # Code can advance between recording and querying; evidence attempt and
        # destination pins must remain identical to the replayed original batch.
        baseline_context = dict(base['source_context'])
        current_context = dict(context)
        baseline_context.pop('code_revision', None)
        current_context.pop('code_revision', None)
        require(baseline_context == current_context and
            base['original_publication_sha256'] == publication_sha and
            base['source_registry_sha256'] == digest({k: sorted(v) for k, v in HEADERS.items()}),
            'Journal baseline differs from replayed anchored evidence.')
        claims = source_claims(officer_uid, source['catalog'], source['bindings'])
        expected = [dict(claim=J._wire(c), source_key=json.loads(c.source_reference)['filename'])
            for c in claims]
        require(sorted(map(canonical, expected)) == sorted(map(canonical, base['claims'])),
            'Baseline claims differ from original source replay.')
        wrapped = J.query_observed_journal(state, effective_on=effective_on, known_at=known_at)
        # Date conversion is confined to output serialization, not source cells.
        query = json.loads(json.dumps(asdict(wrapped['result']), default=_wire, allow_nan=False))
        comparison = compare_history(state['history'], effective_on=effective_on, known_at=known_at)
        require(comparison.query_digest == wrapped['result'].query_digest,
            'Comparison and authenticated query history differ.')
        comparison = json.loads(json.dumps(asdict(comparison), default=_wire, allow_nan=False))
        result = dict(policy=POLICY, officer_uid=officer_uid, query=query, comparison=comparison,
            accepted_contradiction=False, findings_anchored=False,
            coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',
            earlier_knowledge_supported=False, source_change_completeness_established=False,
            accepted_state=None, authenticated_journal_replay=True,
            witness_scope=scope, registry_tip=deepcopy(tip),
            checkpoint_file=selection['checkpoint_file'],
            checkpoint_sha256=selection['checkpoint_sha256'],
            coverage_start=state['history'].coverage_start.isoformat(),
            coverage_end=state['history'].coverage_end.isoformat())
        binding = dict(artifact='PROTECTED_OBSERVED_CONTRADICTIONS', policy=POLICY,
            source_context=context, original_publication_sha256=publication_sha,
            journal_anchor=registry.anchor, registry_tip=deepcopy(tip),
            result_sha256=digest(result))
        envelope = seal_artifact(snapshot['crypto'], snapshot['backup'], result, binding)
        require(open_artifact(snapshot['crypto'], envelope, binding) == result and
            open_artifact(snapshot['backup'], envelope, binding) == result,
            'Protected query recovery differs.')

        def check():
            permit.check(snapshot)
            require(digest(dict(catalog=snapshot['catalog'],
                bindings=snapshot['bindings']['raw_bindings'])) == source_sha,
                'Replayed query source changed.')
            require(adapter.client.scope == scope, 'Witness scope changed.')
            require((W._key_digest(adapter.client.writer_keys),
                W._key_digest(adapter.client.witness_keys)) == key_pins, 'Witness key pins changed.')
            require(adapter.client.head() == tip, 'Witness advanced during query.')
            require(registry._selection(registry._entries(tip), tip) == selection,
                'Selected query history changed.')
            J._private_root(parent, repo)
            require(not destination.is_symlink() and not destination.exists(),
                'Query output appeared during publication.')
            permit.check(snapshot)

        try:
            with tempfile.NamedTemporaryFile(dir=parent, prefix='.contradiction-query-', delete=False) as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), 0o600)
                stream.write((canonical(envelope) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            check()
            os.link(temporary, destination)
            fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    # No officer IDs, source values, paths, ciphertext or raw query in console.
    return dict(policy=POLICY, status='PUBLISHED', coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',
        source_change_completeness_established=False, accepted_state=None,
        accepted_contradiction=False, findings_anchored=False)
