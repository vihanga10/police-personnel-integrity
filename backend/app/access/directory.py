"""Signed current scope map plus an authenticated original name/NIC projection.

A map describes current WEB access membership only. Never infer it from CSV
posting text, rank, NIC, historical events or a user-supplied query date.
"""
from copy import deepcopy
from app.access.policy import POLICY, LEVELS, encoded, label, require, signed, uid, name
from app.identity.normalization import normalize_identifier


def validate_directory(envelope, keys, *, now=None):
    p = signed(envelope, keys, 'DIRECTORY', now=now)
    require(set(p) == {'policy', 'kind', 'issued_at', 'expires_at', 'generation',
                      'source_public_sha256', 'officers', 'review_reference'}, 'Directory fields differ')
    require(type(p['generation']) is int and p['generation'] > 0, 'Positive directory generation required')
    import re
    require(type(p['source_public_sha256']) is str and re.fullmatch('[0-9a-f]{64}', p['source_public_sha256']), 'Source digest required')
    label(p['review_reference'])
    require(type(p['officers']) is list and 0 < len(p['officers']) <= 10000, 'Bounded officer directory required')
    seen = set()
    for o in p['officers']:
        require(type(o) is dict and set(o) == {'officer_uid', 'nic', 'names', 'membership', 'source_raw_id'}, 'Identity-only directory required')
        uid(o['officer_uid']); require(o['officer_uid'] not in seen, 'Duplicate officer'); seen.add(o['officer_uid'])
        require(type(o['nic']) is str and len(o['nic']) <= 64 and
                normalize_identifier(o['nic'], identifier_type='NIC').value == o['nic'], 'Exact NIC required')
        require(type(o['names']) is list and 1 <= len(o['names']) <= 2, 'Reported names required')
        for n in o['names']: require(bool(name(n)), 'Name empty')
        require(type(o['membership']) is dict and set(o['membership']) == set(LEVELS), 'Explicit current membership required')
        for value in o['membership'].values():
            if value is not None: label(value)
        require(type(o['source_raw_id']) is str and re.fullmatch('[0-9a-f]{64}', o['source_raw_id']), 'Source reference required')
    # A canonical scope ID must have one unambiguous parent within this directory.
    for child, parent in (('DISTRICT','PROVINCE'), ('DIVISION','DISTRICT'), ('STATION','DIVISION')):
        parents = {}
        for o in p['officers']:
            c, v = o['membership'][child], o['membership'][parent]
            if c is not None:
                require(v is not None, 'A scoped membership requires its parent')
                require(c not in parents or parents[c] == v, 'Conflicting scope hierarchy')
                parents[c] = v
    return deepcopy(p)


def export_directory(args, repo, revision, membership_envelope, keys, *, generation):
    """Public trusted entry uses the unchanged full replay loader; no callback waiver.

    Returns a private signing draft. A configured directory administrator must
    separately sign its exact bytes before import. Neither account nor geography
    is auto-provisioned. Snapshot candidate linkage remains explicitly unaccepted.
    """
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot = load_verified_snapshot(args, repo, revision)
    return _from_loaded_snapshot(snapshot, membership_envelope, keys, generation=generation)


def _from_loaded_snapshot(snapshot, membership_envelope, keys, *, generation):
    """Internal only: caller must have obtained snapshot from full anchored replay."""
    from app.identity.algorithm_permit import AlgorithmPermit
    from app.identity.protected_commitment import digest
    import time
    permit = AlgorithmPermit(snapshot); permit.check(snapshot)
    m = signed(membership_envelope, keys, 'MEMBERSHIP')
    require(set(m) == {'policy','kind','issued_at','expires_at','source_public_sha256','officers','review_reference'}, 'Membership fields differ')
    require(m['source_public_sha256'] == digest(snapshot['public']), 'Membership refers to another source batch')
    require(type(m['officers']) is list, 'Membership list required')
    members = {x['officer_uid']: x['membership'] for x in m['officers']}
    require(len(members) == len(m['officers']), 'Duplicate current membership')
    universe = {x['officer_uid'] for x in snapshot['manifest']['bundles']}
    require(set(members) == universe, 'Every anchored officer needs explicit membership, including unknowns')
    officers = []
    for raw, item in snapshot['catalog'].items():
        if item['filename'] != 'officer_personal_information.csv': continue
        links = [x for x in item['candidate_links'] if x['role'] == 'officer_nic_no']
        require(len(links) == 1 and links[0]['state'] == 'CANDIDATE_NOT_ACCEPTED', 'Profile subject unresolved')
        officer = links[0]['officer_uid']
        require(officer in universe and raw == item['raw_record_id'] and
                item['delivery']['complete'] is True and snapshot['bindings']['raw_bindings'].get(raw), 'Profile binding incomplete')
        original = item['original']; columns, values = original['columns'], original['values']
        require(len(columns) == len(set(columns)) == len(values) and all(type(x) is str for x in columns+values), 'Original row differs')
        row = dict(zip(columns, values))
        nic = normalize_identifier(row['officer_nic_no'], identifier_type='NIC').value
        names = [row[k] for k in ('full_name','name_with_initials') if row.get(k,'').strip()]
        officers.append(dict(officer_uid=officer, nic=nic, names=names, membership=deepcopy(members[officer]), source_raw_id=raw))
    require(len(officers) == len(universe) and {x['officer_uid'] for x in officers} == universe, 'One profile per anchored officer required')
    permit.check(snapshot)
    return dict(policy=POLICY, kind='DIRECTORY', issued_at=int(time.time()), expires_at=m['expires_at'],
                generation=generation, source_public_sha256=m['source_public_sha256'], officers=officers,
                review_reference=m['review_reference'])
