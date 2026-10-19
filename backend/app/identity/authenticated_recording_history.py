"""Verify recorder-signed version events and an independently pinned checkpoint.

No receipt issuer or live runner is provided. Signatures attest recorder claims,
not source truth or independent completeness. Trusted inputs belong to backend
configuration/readiness, never fields copied from supplied receipt envelopes.
"""
import base64
from datetime import date, datetime, timezone
import re
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.historical_reconstruction import Claim, DIMENSIONS, instant, require
from app.identity.protected_commitment import digest
from app.identity.evidence_bundle_v2 import canonical

POLICY = 'AUTHENTICATED_RECORDING_HISTORY_V1'
EVENT_FIELDS = {'policy', 'kind', 'receipt_id', 'sequence', 'previous_receipt_sha256',
    'context', 'scope', 'version_id', 'source_key', 'claim', 'recorded_at',
    'issued_at', 'timestamp_semantics', 'supersedes', 'withdrawn'}
COVERAGE_FIELDS = {'policy', 'kind', 'receipt_id', 'context', 'scope',
    'coverage_start', 'coverage_end', 'issued_at', 'baseline', 'event_receipt_sha256',
    'checkpoint_reference', 'completeness_statement'}
CLAIM_FIELDS = {'claim_id', 'officer_uid', 'dimension', 'value', 'source_reference',
    'destination_digest', 'mode', 'start', 'end', 'issues'}


def _text(value):
    require(isinstance(value, str) and bool(value.strip()), 'Recording receipt text differs.')


def _hash(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None,
            'Recording checkpoint digest differs.')


def _time(value):
    require(isinstance(value, str), 'Recorded receipt timestamp required.')
    try:
        result = instant(datetime.fromisoformat(value))
    except (TypeError, ValueError):
        raise ValueError('Recorded receipt timestamp differs.') from None
    # One canonical UTC representation avoids signature/identity ambiguities.
    require(result.isoformat() == value, 'Canonical UTC receipt timestamp required.')
    return result


def _signed(envelope, trusted_keys, fields, kind):
    require(type(envelope) is dict and set(envelope) == {'key_id', 'payload', 'signature'},
            'Signed recording receipt shape differs.')
    key_id = envelope['key_id']; _text(key_id)
    require(key_id in trusted_keys, 'Untrusted recording receipt signer.')
    key = trusted_keys[key_id]
    require(type(key) is bytes and len(key) == 32, 'Pinned recorder public key required.')
    value = envelope['payload']
    require(type(value) is dict and set(value) == fields and value['policy'] == POLICY and
            value['kind'] == kind, 'Recording receipt policy or fields differ.')
    try:
        signature = base64.b64decode(envelope['signature'], validate=True)
        require(len(signature) == 64, 'Recording receipt signature differs.')
        message = canonical([POLICY, key_id, value]).encode('utf-8')
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except (InvalidSignature, TypeError, ValueError):
        raise ValueError('Recording receipt signature verification failed.') from None
    _text(value['receipt_id'])
    return value


def _scope(scope):
    require(type(scope) is dict and set(scope) == {'officer_uid', 'source_keys', 'dimensions'},
            'Explicit recording scope required.')
    require(isinstance(scope['officer_uid'], str) and
        str(UUID(scope['officer_uid'])) == scope['officer_uid'], 'Recording scope officer differs.')
    for name in ('source_keys', 'dimensions'):
        values = scope[name]
        require(type(values) is list and bool(values) and
            all(isinstance(v, str) and bool(v.strip()) for v in values) and
            values == sorted(set(values)), 'Canonical recording scope required.')
    require(set(scope['dimensions']) == set(DIMENSIONS), 'Full reconstruction dimension scope required.')


def _claim(value):
    require(type(value) is dict and set(value) == CLAIM_FIELDS, 'Recording claim shape differs.')
    value = dict(value)
    for name in ('start', 'end'):
        if value[name] is not None:
            require(isinstance(value[name], str), 'Reported effective date differs.')
            try:
                parsed = date.fromisoformat(value[name])
            except ValueError:
                raise ValueError('Reported effective date differs.') from None
            require(parsed.isoformat() == value[name], 'Canonical effective date required.')
            value[name] = parsed
    require(type(value['issues']) is list, 'Recording claim issues differ.')
    value['issues'] = tuple(value['issues'])
    return Claim(**value)


def authenticate_recording_history(receipts, coverage, *, trusted_keys,
        expected_context, expected_scope, expected_coverage_digest, now=None):
    """Authenticate exact event inventory, chain, scope and correction lineage.

    The coverage digest MUST originate in an independent trusted checkpoint.
    This v1 supports only an attested EMPTY_AT_START journal. Existing datasets
    with unknown earlier history must fail, not be relabeled as an empty origin.
    Caller must separately authorize any real research execution/evidence epoch.
    """
    _scope(expected_scope)
    require(type(expected_context) is dict and set(expected_context) ==
        {'journal_id', 'recorder_policy_sha256', 'source_registry_sha256'},
        'Independent recording context required.')
    _text(expected_context['journal_id'])
    _hash(expected_context['recorder_policy_sha256']); _hash(expected_context['source_registry_sha256'])
    _hash(expected_coverage_digest)
    require(digest(coverage) == expected_coverage_digest, 'Recording checkpoint pin differs.')
    current = instant(now if now is not None else datetime.now(timezone.utc))
    checkpoint = _signed(coverage, trusted_keys, COVERAGE_FIELDS, 'COVERAGE')
    require(checkpoint['context'] == expected_context and checkpoint['scope'] == expected_scope,
            'Recording coverage context or scope differs.')
    require(checkpoint['baseline'] == 'EMPTY_AT_START' and
        checkpoint['completeness_statement'] == 'ALL_COMMITTED_VERSION_EVENTS_IN_SCOPE',
        'Established empty origin and explicit coverage attestation required.')
    _text(checkpoint['checkpoint_reference'])
    start, end, issued = (_time(checkpoint[k]) for k in
        ('coverage_start', 'coverage_end', 'issued_at'))
    require(start <= end <= issued <= current, 'Recording coverage time order differs.')
    require(type(receipts) in (list, tuple), 'Complete recording receipt inventory required.')
    inventory = checkpoint['event_receipt_sha256']
    require(type(inventory) is list and all(isinstance(v, str) for v in inventory),
            'Checkpoint event inventory differs.')
    for value in inventory: _hash(value)
    require(len(set(inventory)) == len(inventory) and
        [digest(receipt) for receipt in receipts] == inventory,
        'Complete ordered checkpoint event inventory required.')
    versions, ids, previous, last_time = [], {checkpoint['receipt_id']}, None, start
    for index, envelope in enumerate(receipts, 1):
        event = _signed(envelope, trusted_keys, EVENT_FIELDS, 'VERSION')
        require(event['context'] == expected_context and event['scope'] == expected_scope,
                'Recording event context or scope differs.')
        require(event['receipt_id'] not in ids, 'Repeated recording receipt identifier.')
        ids.add(event['receipt_id'])
        require(type(event['sequence']) is int and event['sequence'] == index and
            event['previous_receipt_sha256'] == previous, 'Recording event chain gap or fork.')
        recorded, emitted = _time(event['recorded_at']), _time(event['issued_at'])
        require(start < recorded and last_time <= recorded <= end and recorded <= emitted <= issued,
                'Recording event time order differs.')
        require(event['timestamp_semantics'] == 'RECORDER_OBSERVED_COMMITTED_VERSION',
                'Committed-version observation timestamp required.')
        require(event['source_key'] in expected_scope['source_keys'], 'Recording source outside scope.')
        claim = _claim(event['claim'])
        require(claim.officer_uid == expected_scope['officer_uid'], 'Recording event officer differs.')
        versions.append(EvidenceVersion(event['version_id'], claim, event['source_key'], recorded,
            event['receipt_id'], inventory[index-1], event['supersedes'], event['withdrawn']))
        previous, last_time = inventory[index-1], recorded
    return RecordingHistory(expected_scope['officer_uid'], start, end,
        checkpoint['checkpoint_reference'], expected_coverage_digest, tuple(versions))
