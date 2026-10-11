"""Bounded presentation contracts. Web permissions never constitute action authority.

Only private administrative imports can supply signed history and disclosure
grants. A presentation is a time-limited observed copy, not a fresh live run.
"""
import base64
from copy import deepcopy
from datetime import date, datetime, timezone
import hashlib
import json
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.access.policy import encoded, require, uid
from app.identity.historical_reconstruction import Claim
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.security.record_protection import AssignmentProtection, RecordClassification

POLICY = 'RESEARCH_WORKSPACE_V1'
DECISIONS = ('NEEDS_MORE_EVIDENCE', 'REPORTED_DISAGREEMENT_SUPPORTED', 'REPORTED_DISAGREEMENT_NOT_SUPPORTED')
FIELDS = {'rank': {'to_rank', 'entry_rank', 'current_rank', 'floor_rank'}, 'police_number': {'police_no', 'number_type', 'entry_police_no', 'current_police_no'},
          'posting': {'to_unit_name', 'to_station_code', 'to_station_name', 'to_unit_type', 'entry_station_name', 'current_unit_name',
                      'current_station_code', 'current_station', 'first_posted_police_station_code', 'first_posted_police_station_name', 'entry_unit_name'},
          'service_status': {'service_status', 'status'},
          'restrictions': {'restriction_id', 'restriction_category', 'restriction_effect', 'restriction_scope'}}

def sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'Digest required')
    return value

def fingerprint(value): return hashlib.sha256(encoded(value)).hexdigest()

def text(value, maximum=1200):
    require(type(value) is str and 1 <= len(value.strip()) <= maximum and
            not any(ord(c) < 32 and c not in '\n\t' for c in value), 'Bounded text required')
    return value

def instant(value):
    require(type(value) is str, 'Timestamp string required')
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None and result.utcoffset() is not None, 'Timezone required')
    return result.astimezone(timezone.utc)

def signed(envelope, keys, kind, now):
    require(type(envelope) is dict and set(envelope) == {'key_id', 'payload', 'signature'}, 'Signed workspace envelope required')
    require(envelope['key_id'] in keys, 'Unconfigured workspace authority')
    p = envelope['payload']
    require(type(p) is dict and p.get('policy') == POLICY and p.get('kind') == kind, 'Workspace signing domain differs')
    require(type(p.get('issued_at')) is int and type(p.get('expires_at')) is int and
            p['issued_at'] <= now < p['expires_at'] <= p['issued_at'] + 3600, 'Current workspace attestation required')
    Ed25519PublicKey.from_public_bytes(keys[envelope['key_id']]).verify(
        base64.b64decode(envelope['signature'], validate=True), encoded(p))
    return deepcopy(p)

def history(value, officer):
    require(type(value) is dict and set(value) == {'coverage_start', 'coverage_end', 'coverage_reference', 'coverage_digest', 'versions'}, 'History fields differ')
    sha(value['coverage_digest']); text(value['coverage_reference'], 300)
    require(type(value['versions']) is list and len(value['versions']) <= 20000, 'Bounded history required')
    versions = []
    for v in value['versions']:
        require(type(v) is dict and set(v) == {'version_id', 'claim', 'source_key', 'recorded_at', 'receipt_reference', 'receipt_digest', 'supersedes', 'withdrawn'}, 'Version fields differ')
        c = deepcopy(v['claim'])
        require(type(c) is dict and set(c) == {'claim_id', 'officer_uid', 'dimension', 'value', 'source_reference', 'destination_digest', 'mode', 'start', 'end', 'issues'}, 'Claim fields differ')
        require(c['officer_uid'] == officer and len(c['value']) <= 20000 and len(c['source_reference']) <= 20000, 'Claim scope/size differs')
        for k in ('start', 'end'): c[k] = date.fromisoformat(c[k]) if c[k] is not None else None
        c['issues'] = tuple(c['issues'])
        versions.append(EvidenceVersion(**{**v, 'claim': Claim(**c), 'recorded_at': instant(v['recorded_at'])}))
    return RecordingHistory(officer, instant(value['coverage_start']), instant(value['coverage_end']),
                            value['coverage_reference'], value['coverage_digest'], tuple(versions))

def packet(envelope, keys, now):
    p = signed(envelope, keys, 'PRESENTATION', now)
    require(set(p) == {'policy', 'kind', 'issued_at', 'expires_at', 'officer_uid', 'generation',
        'source_public_sha256', 'observed_at', 'recording_tip_sha256', 'history', 'findings', 'authority', 'anchoring'}, 'Presentation fields differ')
    uid(p['officer_uid']); sha(p['source_public_sha256']); sha(p['recording_tip_sha256'])
    require(type(p['generation']) is int and p['generation'] > 0, 'Positive generation required')
    require(instant(p['observed_at']).timestamp() <= p['issued_at'], 'Observation is in the future')
    h = history(p['history'], p['officer_uid'])
    require(h.coverage_end <= instant(p['observed_at']), 'Coverage exceeds observation')
    require(type(p['findings']) is list and len(p['findings']) <= 1000, 'Bounded findings required')
    seen = set()
    for f in p['findings']:
        require(type(f) is dict and set(f) == {'finding_id', 'head_sha256', 'status', 'dimension', 'effective_on', 'known_at', 'versions'}, 'Finding projection fields differ')
        uid(f['finding_id']); sha(f['head_sha256']); require(f['finding_id'] not in seen, 'Duplicate finding'); seen.add(f['finding_id'])
        require(f['status'] in ('REPORTED_CONTRADICTION_CANDIDATE', 'UNRESOLVED_COMPARISON', 'REPORTED_AGREEMENT', 'NO_REPORTED_CONFLICT_AT_POINT'), 'Finding status differs')
        require(f['dimension'] in (*FIELDS, 'combined'), 'Finding dimension differs')
        date.fromisoformat(f['effective_on']); instant(f['known_at'])
        require(type(f['versions']) is list and 1 <= len(f['versions']) <= 100, 'Finding history required')
        previous = None; last_time = None; entries = set()
        for v in f['versions']:
            require(type(v) is dict and set(v) == {'kind', 'entry_sha256', 'supersedes', 'recorded_at', 'decision', 'reason'}, 'Finding version fields differ')
            require(v['kind'] in ('FINDING', 'CORRECTION', 'REVIEW'), 'Finding kind differs'); sha(v['entry_sha256']); at=instant(v['recorded_at']); text(v['reason'])
            require(v['entry_sha256'] not in entries and (last_time is None or at > last_time), 'Finding order differs')
            entries.add(v['entry_sha256']); last_time=at
            if v['kind']=='FINDING': require(previous is None and v['supersedes'] is None, 'Initial finding lineage differs')
            elif v['kind']=='CORRECTION': require(previous is not None and v['supersedes']==previous, 'Correction target differs')
            else: require(previous is not None and v['supersedes'] is None, 'A review does not supersede the finding')
            require(v['decision'] in (None, *DECISIONS), 'Review decision differs')
            if v['kind'] != 'REVIEW': previous = v['entry_sha256']
        require(previous == f['head_sha256'], 'Finding head differs')
    require(type(p['authority']) is list and len(p['authority']) <= 1000, 'Bounded authority summary required')
    for a in p['authority']:
        require(type(a) is dict and set(a) == {'action_id', 'action_type', 'action_on', 'status', 'reasons', 'assessment_receipt_sha256'}, 'Authority fields differ')
        sha(a['action_id']); text(a['action_type'], 100)
        if a['action_on'] is not None: date.fromisoformat(a['action_on'])
        require(a['status'] in ('VALID', 'INVALID', 'CANNOT_VERIFY'), 'Authority status differs')
        require(type(a['reasons']) is list and 1 <= len(a['reasons']) <= 50, 'Authority reasons required')
        for r in a['reasons']: text(r, 150)
        if a['status'] != 'CANNOT_VERIFY': sha(a['assessment_receipt_sha256'])
        else: require(a['assessment_receipt_sha256'] is None, 'Unassessed authority cannot carry approval')
    require(type(p['anchoring']) is dict and set(p['anchoring']) == {'fabric', 'public', 'recovery'}, 'Anchoring sections differ')
    for value in p['anchoring'].values():
        require(type(value) is dict and set(value) == {'status', 'receipt_sha256'}, 'Anchoring projection differs')
        require(value['status'] in ('NOT_CONFIGURED', 'OBSERVED_VALID', 'FINALITY_PENDING', 'ISOLATED_ONLY', 'PENDING', 'ERROR'), 'Anchoring status differs')
        if value['receipt_sha256'] is not None: sha(value['receipt_sha256'])
        require(value['status'] != 'OBSERVED_VALID' or value['receipt_sha256'] is not None, 'Observed receipt required')
    return p

def grant(envelope, keys, now):
    p = signed(envelope, keys, 'DISCLOSURE', now)
    require(set(p) == {'policy', 'kind', 'issued_at', 'expires_at', 'user_id', 'account_version', 'officer_uid',
        'source_public_sha256', 'assignment', 'classification', 'restricted_clearance', 'request_reviews', 'reviewer_uid'}, 'Disclosure fields differ')
    uid(p['user_id']); uid(p['officer_uid']); sha(p['source_public_sha256'])
    require(type(p['account_version']) is int and p['account_version'] > 0, 'Account version required')
    AssignmentProtection(p['assignment']); RecordClassification(p['classification'])
    require(type(p['restricted_clearance']) is bool and type(p['request_reviews']) is bool, 'Explicit permissions required')
    if p['request_reviews']: uid(p['reviewer_uid'])
    else: require(p['reviewer_uid'] is None, 'Nonreviewer cannot select an actor')
    return p

def claim_projection(claim):
    """Never return whole evidence rows, source references or linked-person values."""
    try: value = json.loads(claim.value)
    except Exception: value = {}
    fields = {k: v for k, v in value.items() if k in FIELDS[claim.dimension] and type(v) is str and len(v) <= 200} if type(value) is dict else {}
    from app.identity.historical_source_claims import HEADERS
    try: source = json.loads(claim.source_reference)
    except Exception: source = {}
    dataset = source.get('filename') if type(source) is dict else None
    # Only known dataset names can be disclosed; arbitrary provenance text can
    # contain linked-person information, private paths or source document IDs.
    dataset = dataset if type(dataset) is str and dataset in HEADERS else None
    return dict(reference=fingerprint({'claim_id': claim.claim_id}), dimension=claim.dimension,
                fields=fields, effective_from=claim.start.isoformat() if claim.start else None,
                effective_until=claim.end.isoformat() if claim.end else None, mode=claim.mode,
                reasons=list(claim.issues), reported_dataset=dataset,
                provenance_sha256=fingerprint({'source': claim.source_reference}),
                source_independence_verified=False)
