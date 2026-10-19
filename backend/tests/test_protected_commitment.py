"""Commitments detect content, membership and destination tampering without public identifiers."""
import base64
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
from uuid import UUID

import pytest
from app.identity.protected_commitment import CommitmentKeys, KEY_POLICY, POLICY, generate, merkle_root, encoded
from app.identity.evidence_bundle_v2 import BundleInventory, seal_artifact, open_artifact
from app.identity.destination_binding import DestinationInventory, row_binding
from app.security.identity_crypto import IdentityCrypto

REVISION = 'a' * 40
OFFICERS = [str(UUID(int=1)), str(UUID(int=2))]
SNAPSHOT = dict(batch_id='fixture', archive_sha256='a'*64, confirmation_sha256='b'*64,
                code_revision='c'*40, collection_started_at='2026-10-08T00:00:00+00:00')


def key_data():
    return dict(policy=KEY_POLICY, version='commit-v1', content_key=base64.b64encode(b'C'*32).decode(),
                publication_key=base64.b64encode(b'P'*32).decode())


def fixture():
    files = {'promotion.csv': 1, 'operations.csv': 1, 'station.csv': 1}
    inv = BundleInventory(OFFICERS, files)
    for index, (filename, roles) in enumerate([('promotion.csv', [(OFFICERS[0], 'SUBJECT')]),
                            ('operations.csv', [(o, 'REPORTED_PARTICIPANT') for o in OFFICERS]), ('station.csv', [])], 1):
        raw = '%064x' % index
        inv.add(filename, raw, dict(columns=['officer_nic_no', 'note'], values=['123456789V', 'original promotion']),
                dict(source_row_number=1, source_file_sha256='d'*64, import_file_id=str(UUID(int=index+10)), reported_source='SRB'), roles)
        inv.bind_receipt(raw, dict(raw_record_id=raw, assertion_id=str(UUID(int=index+20)), complete=True),
                         dict(source_assertion_id=str(UUID(int=index+20)), source_file_name=filename))
    manifest = inv.finish(SNAPSHOT); manifest['court_membership_policy'] = 'COURT_PARTICIPANT_MEMBERSHIP_V1'
    catalog = {raw: dict(row, filename=filename) for filename, rows in inv.catalog.items() for raw, row in rows.items()}
    destinations = DestinationInventory(catalog, OFFICERS)
    for index, raw in enumerate(catalog):
        destinations.add_sql(row_binding('fixture.raw', ['id'], dict(id=index, encrypted=b'payload', version=1)), raw_id=raw)
    for index, officer in enumerate(OFFICERS):
        destinations.add_sql(row_binding('fixture.officer', ['id'], dict(id=index, officer_uid=UUID(officer))), officer_uid=officer)
    destinations.add_sql(row_binding('fixture.shared', ['id'], dict(id=1, source='reported')))
    for index, raw in enumerate(list(catalog)[:2]):
        doc = dict(_id=str(index), raw_record_id=raw, ciphertext='protected')
        from bson import BSON
        fingerprint = hashlib.sha256(BSON.encode(doc)).hexdigest()
        destinations.expect_mongo('events', str(index), raw, fingerprint)
        destinations.add_mongo('events', doc, BSON.encode)
    binding = destinations.finish()
    sql = {'fixture.raw': 3, 'fixture.officer': 2, 'fixture.shared': 1}
    mongo = {'events': 2}
    binding.update(source_snapshot=SNAPSHOT, source_bundle_policy=manifest['policy'], sql_table_counts=sql,
                   collector_revision='e'*40, collected_at='2026-10-08T01:00:00+00:00', source_attempt_id='fixture')
    return manifest, catalog, binding, sql, mongo


def calculate(data, keys=None, revision=REVISION):
    manifest, catalog, binding, sql, mongo = data
    return generate(manifest, catalog, binding, keys or CommitmentKeys(key_data()), generator_revision=revision,
                    sql_counts=sql, mongo_counts=mongo)


def officer_commitments(public):
    return {r['publication_id']: r['commitment'] for r in public['officers']}


def test_known_hmac_framing_and_dedicated_domains():
    keys = CommitmentKeys(key_data())
    payload = {'note': 'preserved'}
    assert keys.commit('SOURCE_ROW', payload) == hmac.new(b'C'*32, encoded([POLICY, 'commit-v1', 'SOURCE_ROW', payload]), hashlib.sha256).hexdigest()
    assert len({keys.commit('SOURCE_ROW', payload), keys.commit('OFFICER_BUNDLE', payload), keys.handle('SOURCE_ROW', payload)}) == 3


def test_exact_replay_and_public_payload_has_no_source_identifiers():
    data = fixture(); public, private = calculate(data)
    assert calculate(deepcopy(data)) == (public, private)
    text = json.dumps(public)
    for secret in [*OFFICERS, '123456789V', 'original promotion', 'promotion.csv', 'raw_record_id', 'candidate_roles']:
        assert secret not in text
    assert len(public['officers']) == 2 and len(private['raw_commitments']) == 3
    assert all(set(r) == {'publication_id', 'commitment_version', 'commitment'} for r in public['officers'])


def test_inventory_order_is_irrelevant_but_original_order_is_preserved():
    data = fixture(); expected = calculate(data)
    shuffled = deepcopy(data); manifest, catalog, binding, _, _ = shuffled
    manifest['bundles'].reverse()
    for bundle in manifest['bundles']: bundle['evidence'].reverse()
    for row in catalog.values(): row['candidate_links'].reverse()
    for bucket in binding['raw_bindings'].values(): bucket.reverse()
    assert calculate(shuffled) == expected


@pytest.mark.parametrize('kind', ['source_value', 'column_name', 'source_order', 'provenance', 'assertion', 'receipt',
                                  'uncertainty', 'sql_cipher_hash', 'mongo_cipher_hash', 'sql_column_set'])
def test_changed_promotion_contents_and_versions_change_owner_commitment(kind):
    data = fixture(); expected, _ = calculate(data); changed = deepcopy(data)
    row = changed[1]['%064x' % 1]; destinations = changed[2]['raw_bindings']['%064x' % 1]
    if kind == 'source_value': row['original']['values'][1] += '!'
    elif kind == 'column_name': row['original']['columns'][1] = 'other_field'
    elif kind == 'source_order':
        row['original']['values'].reverse(); row['original']['columns'].reverse()
    elif kind == 'provenance': row['provenance']['source_file_sha256'] = 'f'*64
    elif kind == 'assertion': row['assertion']['source_assertion_id'] = str(UUID(int=100))
    elif kind == 'receipt': row['delivery']['assertion_id'] = str(UUID(int=100))
    elif kind == 'uncertainty': row['uncertainty'].append('UNRESOLVED_REFERENCE')
    elif kind == 'sql_cipher_hash': next(x for x in destinations if 'table' in x)['row_sha256'] = 'f'*64
    elif kind == 'mongo_cipher_hash': next(x for x in destinations if 'store' in x)['document_sha256'] = 'f'*64
    elif kind == 'sql_column_set': next(x for x in destinations if 'table' in x)['columns'].append('zz_new')
    actual, _ = calculate(changed)
    before, after = officer_commitments(expected), officer_commitments(actual)
    changed_handles = {k for k in before if before[k] != after[k]}
    assert len(changed_handles) == 1  # Other officer has no membership in this promotion.
    assert expected['merkle_root'] != actual['merkle_root']


def test_shared_operation_change_affects_both_participants():
    data = fixture(); expected, _ = calculate(data)
    data[1]['%064x' % 2]['original']['values'][1] = 'changed shared operation'
    actual, _ = calculate(data)
    assert all(officer_commitments(expected)[k] != v for k, v in officer_commitments(actual).items())


@pytest.mark.parametrize('kind', ['role', 'add_member', 'remove_member'])
def test_consistent_membership_changes_alter_commitments(kind):
    data = fixture(); expected, _ = calculate(data)
    row = data[1]['%064x' % 1]
    if kind == 'role':
        row['candidate_links'][0]['role'] = 'REPORTED_AUTHORITY'
        data[0]['bundles'][0]['evidence'][1]['candidate_roles'] = ['REPORTED_AUTHORITY']
    elif kind == 'add_member':
        row['candidate_links'].append(dict(officer_uid=OFFICERS[1], role='SUBJECT', state='CANDIDATE_NOT_ACCEPTED'))
        data[0]['bundles'][1]['evidence'].append(dict(filename='promotion.csv', raw_record_id='%064x' % 1,
                                                      candidate_roles=['SUBJECT'], linkage_accepted=False))
    else:
        row['candidate_links'] = []
        data[0]['bundles'][0]['evidence'] = [e for e in data[0]['bundles'][0]['evidence'] if e['filename'] != 'promotion.csv']
        data[0]['associated_rows'] -= 1; data[0]['unassigned_rows'] += 1
    assert calculate(data)[0] != expected


@pytest.mark.parametrize('kind', ['reference', 'shared_sql', 'officer_sql', 'generator_revision', 'participant_order'])
def test_shared_reference_and_context_are_covered(kind):
    data = fixture(); expected, _ = calculate(data)
    if kind == 'reference': data[1]['%064x' % 3]['original']['values'][1] = 'station change'
    elif kind == 'shared_sql': data[2]['shared_bindings'][0]['row_sha256'] = 'f'*64
    elif kind == 'officer_sql': data[2]['officer_bindings'][OFFICERS[0]][0]['row_sha256'] = 'f'*64
    elif kind == 'generator_revision':
        assert calculate(data, revision='f'*40)[0] != expected; return
    else:
        row = data[1]['%064x' % 2]
        row['court_membership'] = {'participants': [{'position': 1, 'descriptor': 'A'}, {'position': 2, 'descriptor': 'B'}]}
    assert calculate(data)[0] != expected


@pytest.mark.parametrize('kind', ['missing_source', 'extra_source', 'missing_destination', 'extra_destination',
                                  'duplicate_sql', 'duplicate_mongo', 'missing_officer', 'duplicate_officer',
                                  'unmatched_role', 'accepted_link', 'wrong_snapshot', 'wrong_count', 'incomplete_receipt'])
def test_structural_tampering_is_rejected(kind):
    data = fixture(); manifest, catalog, binding, _, _ = data
    raw = '%064x' % 1
    if kind == 'missing_source': del catalog[raw]
    elif kind == 'extra_source': catalog['f'*64] = deepcopy(catalog[raw])
    elif kind == 'missing_destination': binding['raw_bindings'][raw] = []
    elif kind == 'extra_destination': binding['raw_bindings']['f'*64] = []
    elif kind == 'duplicate_sql': binding['shared_bindings'].append(deepcopy(binding['shared_bindings'][0]))
    elif kind == 'duplicate_mongo': binding['raw_bindings'][raw].append(deepcopy(next(x for x in binding['raw_bindings'][raw] if 'store' in x)))
    elif kind == 'missing_officer': manifest['bundles'].pop()
    elif kind == 'duplicate_officer': manifest['bundles'].append(deepcopy(manifest['bundles'][0]))
    elif kind == 'unmatched_role': catalog[raw]['candidate_links'][0]['role'] = 'other'
    elif kind == 'accepted_link': manifest['bundles'][0]['evidence'][0]['linkage_accepted'] = True
    elif kind == 'wrong_snapshot': binding['source_snapshot'] = dict(SNAPSHOT, batch_id='wrong')
    elif kind == 'wrong_count': binding['sql_records'] += 1
    elif kind == 'incomplete_receipt': catalog[raw]['delivery']['complete'] = False
    with pytest.raises(ValueError): calculate(data)


@pytest.mark.parametrize('kind', ['short', 'same', 'wrong_policy', 'wrong_version', 'extra', 'bad_base64'])
def test_malformed_or_reused_key_configuration_rejected(kind):
    data = key_data()
    if kind == 'short': data['content_key'] = base64.b64encode(b'short').decode()
    elif kind == 'same': data['publication_key'] = data['content_key']
    elif kind == 'wrong_policy': data['policy'] = 'wrong'
    elif kind == 'wrong_version': data['version'] = 'changed'
    elif kind == 'extra': data['extra'] = True
    elif kind == 'bad_base64': data['content_key'] = '!'
    with pytest.raises(ValueError): CommitmentKeys(data)


def identity_crypto(tmp_path):
    path = tmp_path/'identity.json'
    path.write_text(json.dumps(dict(active_encryption_key_version='enc', active_lookup_key_version='lookup',
                                   encryption_keys={'enc': base64.b64encode(b'E'*32).decode()},
                                   lookup_keys={'lookup': base64.b64encode(b'L'*32).decode()})))
    path.chmod(0o600)
    return IdentityCrypto(path)


def test_identity_key_reuse_rejected_and_different_commitment_keys_change_values(tmp_path):
    crypto = identity_crypto(tmp_path); keys = CommitmentKeys(key_data()); keys.assert_separate(crypto)
    for label in ['content_key', 'publication_key']:
        for key in [b'E'*32, b'L'*32]:
            data = key_data(); data[label] = base64.b64encode(key).decode()
            with pytest.raises(ValueError): CommitmentKeys(data).assert_separate(crypto)
    data = key_data(); data['content_key'] = base64.b64encode(b'D'*32).decode()
    assert calculate(fixture(), keys)[0] != calculate(fixture(), CommitmentKeys(data))[0]


def test_encrypted_mapping_recovery_and_ciphertext_tampering(tmp_path):
    crypto = identity_crypto(tmp_path); public, private = calculate(fixture())
    binding = dict(artifact='PROTECTED_COMMITMENTS', context=private['context'])
    sealed = seal_artifact(crypto, crypto, private, binding)
    assert '123456789V' not in json.dumps(sealed) and OFFICERS[0] not in json.dumps(sealed)
    assert open_artifact(crypto, sealed, binding)['public'] == public
    damaged = dict(sealed); raw = bytearray(base64.b64decode(damaged['ciphertext'])); raw[-1] ^= 1
    damaged['ciphertext'] = base64.b64encode(raw).decode()
    with pytest.raises(Exception): open_artifact(crypto, damaged, binding)


@pytest.mark.parametrize('count', [1, 2, 3, 4, 7])
def test_merkle_tree_framing_order_and_odd_node_rule(count):
    leaves = [{'number': i} for i in range(count)]
    nodes = [hashlib.sha256(b'\x00'+encoded(x)).digest() for x in leaves]
    while len(nodes) > 1:
        nodes = [hashlib.sha256(b'\x01'+nodes[i]+nodes[min(i+1, len(nodes)-1)]).digest() for i in range(0, len(nodes), 2)]
    assert merkle_root(leaves) == nodes[0].hex()
    if count > 1: assert merkle_root(list(reversed(leaves))) != merkle_root(leaves)
    with pytest.raises(ValueError): merkle_root([])


def test_key_setup_no_overwrite_backup_mismatch_symlink_and_permissions(tmp_path):
    from app.identity.generate_protected_commitments import initialize_keys, load_keys
    repo = tmp_path/'repo'; repo.mkdir()
    first, second = tmp_path/'private-a'/'keys.json', tmp_path/'private-b'/'keys.json'
    initialize_keys(first, second, repo)
    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_mode & 0o077 == second.stat().st_mode & 0o077 == 0
    original = first.read_bytes()
    with pytest.raises(ValueError): initialize_keys(first, second, repo)
    assert first.read_bytes() == original
    data = json.loads(second.read_text()); data['content_key'] = base64.b64encode(b'X'*32).decode()
    second.write_text(json.dumps(data))
    with pytest.raises(ValueError): load_keys(first, second, repo)
    second.write_bytes(original); second.chmod(0o644)
    with pytest.raises(ValueError): load_keys(first, second, repo)
    second.chmod(0o600)
    link = tmp_path/'alias'; link.symlink_to(second)
    with pytest.raises(ValueError): load_keys(first, link, repo)
    inside = repo/'private'; inside.mkdir(mode=0o700)
    with pytest.raises(ValueError): initialize_keys(inside/'a', inside/'b', repo)


def test_public_mutation_changes_digest_and_batch_tree():
    from app.identity.protected_commitment import digest
    public, _ = calculate(fixture()); altered = deepcopy(public)
    altered['officers'][0]['commitment'] = 'f'*64
    assert digest(public) != digest(altered)
    leaves = [dict(kind='OFFICER', **r) for r in altered['officers']] + [dict(kind='BATCH', publication_id=public['batch_publication_id'], commitment=public['batch_commitment'])]
    assert merkle_root(leaves) != public['merkle_root']


@pytest.mark.parametrize('kind', ['valid', 'public', 'summary', 'private', 'missing', 'wrong_key'])
def test_saved_attempt_replay_is_required_to_match_all_artifacts(tmp_path, kind):
    from app.intake.registration_receipt import save_receipt
    from app.identity.generate_protected_commitments import verify_saved
    from app.identity.protected_commitment import digest
    crypto = identity_crypto(tmp_path); public, private = calculate(fixture())
    attempt = tmp_path/'attempt'; attempt.mkdir(mode=0o700)
    binding = dict(artifact='PROTECTED_COMMITMENTS', context=private['context'])
    summary = dict(status='PASSED', public_payload_sha256=digest(public))
    artifact_private = deepcopy(private)
    if kind == 'private': artifact_private['officers'][0]['officer_uid'] = str(UUID(int=999))
    save_receipt(seal_artifact(crypto, crypto, artifact_private, binding), attempt/'commitments.encrypted.json')
    altered = deepcopy(public)
    if kind == 'public': altered['officers'][0]['commitment'] = 'f'*64
    save_receipt(altered, attempt/'public-commitments.json')
    save_receipt(dict(summary, status='STOPPED') if kind == 'summary' else summary, attempt/'PASSED.json')
    if kind == 'missing': (attempt/'public-commitments.json').unlink()
    if kind == 'wrong_key': crypto.encryption_keys['enc'] = b'W'*32
    if kind == 'valid': verify_saved(attempt, crypto, crypto, public, private, binding, summary)
    else:
        with pytest.raises(Exception): verify_saved(attempt, crypto, crypto, public, private, binding, summary)


def test_all_6596_officers_receive_distinct_publications_for_one_shared_record():
    officers = [str(UUID(int=i+1)) for i in range(6596)]
    inv = BundleInventory(officers, {'shared.csv': 1}); raw = 'f'*64
    inv.add('shared.csv', raw, dict(columns=['value'], values=['synthetic']), dict(source_row_number=1),
            [(o, 'REPORTED_PARTICIPANT') for o in officers])
    inv.bind_receipt(raw, dict(complete=True), dict(source_assertion_id=str(UUID(int=7000))))
    manifest = inv.finish(SNAPSHOT); manifest['court_membership_policy'] = 'COURT_PARTICIPANT_MEMBERSHIP_V1'
    catalog = {raw: dict(inv.by_raw[raw], filename='shared.csv')}
    dest = DestinationInventory([raw], officers)
    dest.add_sql(row_binding('fixture.raw', ['id'], dict(id=1)), raw_id=raw)
    binding = dest.finish(); binding.update(source_snapshot=SNAPSHOT, source_bundle_policy=manifest['policy'],
        collector_revision='e'*40, collected_at='2026-10-08', source_attempt_id='fixture', sql_table_counts={'fixture.raw': 1})
    public, private = generate(manifest, catalog, binding, CommitmentKeys(key_data()), generator_revision=REVISION,
                               sql_counts={'fixture.raw': 1}, mongo_counts={})
    assert len(public['officers']) == len(private['officers']) == 6596
    assert len({r['publication_id'] for r in public['officers']}) == len({r['commitment'] for r in public['officers']}) == 6596
    assert len(encoded(public)) < 2_000_000


def test_empty_classification_table_remains_in_commitment_scope():
    data = fixture(); expected, _ = calculate(data)
    data[3]['identity.source_assertion_classification'] = 0
    actual, _ = calculate(data)
    assert actual != expected
    assert data[2]['sql_records'] == sum(data[3].values())


def test_binding_loader_authenticates_the_specific_bundle_attempt(tmp_path):
    from app.identity.generate_protected_commitments import load_binding
    from app.identity.destination_binding import POLICY as DESTINATION_POLICY
    from app.intake.registration_receipt import save_receipt
    crypto = identity_crypto(tmp_path); manifest, _, binding, _, _ = fixture()
    directory = tmp_path/'binding'; directory.mkdir(mode=0o700)
    bundle_directory = tmp_path/'fixture'; bundle_directory.mkdir(mode=0o700)
    summary = dict(policy=DESTINATION_POLICY, status='PASSED', source_rows=167865, officers=6596,
                   sql_tables=35, sql_records=794200, mongo_collections=17, mongo_documents=154673, code_revision='e'*40)
    envelope_binding = dict(artifact='DESTINATION_BINDINGS', destination_policy=DESTINATION_POLICY,
                            source_snapshot=manifest['snapshot'], collector_revision='e'*40)
    save_receipt(summary, directory/'PASSED.json')
    save_receipt(seal_artifact(crypto, crypto, binding, envelope_binding), directory/'destination-bindings.encrypted.json')
    recovered, file_sha = load_binding(directory, manifest, bundle_directory, crypto, crypto)
    assert recovered == binding and len(file_sha) == 64
    other = tmp_path/'other'; other.mkdir(mode=0o700)
    with pytest.raises(ValueError): load_binding(directory, manifest, other, crypto, crypto)
    with pytest.raises(ValueError): load_binding(directory, dict(manifest, snapshot=dict(SNAPSHOT, batch_id='other')), bundle_directory, crypto, crypto)
