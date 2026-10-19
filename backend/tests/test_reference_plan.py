"""Reference source preservation, ambiguity and real authenticated recovery."""
import base64
import copy
import json
import os
from pathlib import Path
from uuid import uuid4
import pytest
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL
from app.identity.reference_plan import ReferenceCandidates, plan_reference, validate_payload, validate_routing, ReferencePlan
from app.identity.reference_plan_crypto import seal_reference_plan, open_reference_plan, context
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.security.identity_crypto import IdentityCrypto

A, B, C = 'a'*64, 'b'*64, 'c'*64


def master(code='001', name='Example', si='උදාහරණ'):
    row = dict.fromkeys(HEADERS[MASTER], '')
    row.update(station_code=code, station_name=name, station_name_si=si, division='Division', province='Province', latitude='6.90', longitude='79.90')
    return row


def sinhala(label='Example (උදාහරණ)'):
    row = dict.fromkeys(HEADERS[SINHALA], '')
    row.update({LABEL: label, 'Province ': 'Province (පළාත)', 'Division': 'Division (අංශය)', 'Latitude': '6.90', 'Longitude': '79.90'})
    return row


def planned(filename=SINHALA, row=None, masters=None):
    masters = masters or [(A, master())]
    index = ReferenceCandidates(masters)
    return plan_reference(filename, row if row is not None else sinhala() if filename == SINHALA else masters[0][1],
                          raw_record_id=C if filename == SINHALA else masters[0][0], candidates=index)


@pytest.mark.parametrize('filename', [MASTER, SINHALA])
def test_every_original_field_preserved_in_order(filename):
    row = master() if filename == MASTER else sinhala()
    row[next(iter(row))] = '  PRIVATE_ORIGINAL  '
    p = planned(filename, row, [(A, row)] if filename == MASTER else None)
    assert [f['source_column'] for f in p.payload['fields']] == list(HEADERS[filename])
    assert [f['source_value'] for f in p.payload['fields']] == [row[n] for n in HEADERS[filename]]
    assert all(f['value'] == f['source_value'] for f in p.payload['fields'])
    assert 'PRIVATE_ORIGINAL' not in repr(p)
    assert p.payload['accepted_station_uid'] is None and p.payload['linkage_accepted'] is False


def test_unique_candidates_preserve_opaque_provenance_and_context():
    p = planned()
    assert not p.payload['needs_review']
    for c in p.payload['candidate_evidence']:
        assert c['joint_raw_ids'] == [A] and c['state'] == 'SINGLE_JOINT_CANDIDATE'
        assert set(c['reported_context'].values()) == {'SAME_REPORTED_TEXT'}


def test_unresolved_brackets_stay_preserved_without_guessing():
    row = sinhala('Example (North) (උදාහරණ)')
    p = planned(row=row)
    assert p.payload['needs_review']
    assert all(c['state'] == 'STRUCTURE_REVIEW_REQUIRED' and not c['joint_raw_ids'] for c in p.payload['candidate_evidence'])
    assert next(f for f in p.payload['fields'] if f['source_column'] == LABEL)['source_value'] == row[LABEL]


@pytest.mark.parametrize('rows,state', [([(A, master()), (B, master(code='002'))], 'MULTIPLE_JOINT_CANDIDATES'),
    ([(A, master(si='වෙනත්')), (B, master(name='Other', code='002'))], 'DISJOINT_CANDIDATES'),
    ([(A, master(si='වෙනත්'))], 'ONE_SIDED_CANDIDATES'),
    ([(A, master(name='Other', si='වෙනත්'))], 'NO_CANDIDATE')])
def test_ambiguity_is_review_not_accepted(rows, state):
    p = planned(masters=rows)
    assert p.payload['needs_review'] and all(c['state'] == state for c in p.payload['candidate_evidence'])


def test_code_reuse_and_sinhala_label_repeat_remain_review():
    p = planned(MASTER, masters=[(A, master()), (B, master())])
    assert p.payload['source_observations'] == dict(repeated_source_code=True, repeated_sinhala_label=True)
    assert {'REPEATED_SOURCE_CODE', 'REPEATED_SINHALA_LABEL'} <= set(p.payload['review_issues'])
    p = planned(MASTER, masters=[(A, master()), (B, master(code='1', name='Other'))])
    assert p.payload['source_observations']['repeated_source_code'] is False
    assert p.payload['fields'][0]['value'] == '001'


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '91', '-91', 'words'])
def test_coordinate_issues_preserved(value):
    row = master(); row['latitude'] = value
    p = planned(MASTER, row, [(A, row)])
    item = next(f for f in p.payload['fields'] if f['source_column'] == 'latitude')
    assert item['status'] == 'REVIEW_REQUIRED' and item['value'] == value
    assert 'COORDINATE_REFERENCE_SYSTEM_AND_ACCURACY_UNASSESSED' in p.payload['uncertainties']


def test_missing_coordinates_not_zero_and_source_confidence_not_probability():
    row = master(); row.update(latitude='', district_confidence='1000', province_matches_district='TRUE')
    p = planned(MASTER, row, [(A, row)])
    fields = {f['source_column']: f for f in p.payload['fields']}
    assert fields['latitude']['value'] == '' and fields['latitude']['status'] == 'MISSING'
    assert fields['district_confidence']['value'] == '1000' and fields['province_matches_district']['value'] == 'TRUE'


@pytest.mark.parametrize('column', ['station_code', 'station_name', 'station_name_si'])
def test_missing_required_fields_review(column):
    row = master(); row[column] = ''
    assert planned(MASTER, row, [(A, row)]).payload['needs_review']


def test_source_header_and_type_guards():
    row = sinhala(); row['Province'] = row.pop('Province ')
    with pytest.raises(ValueError): planned(row=row)
    with pytest.raises(ValueError): planned(row=dict(sinhala(), Latitude=1))
    with pytest.raises(ValueError): ReferenceCandidates([(A, master()), (A, master())])


def test_routing_matches_committed_document_and_rejects_destination_mutation():
    repo = Path(__file__).resolve().parents[2]
    document = json.loads((repo / 'docs/field-routing.json').read_text())
    validate_routing(document)
    target = next(f for f in document['files'] if f['filename'] == MASTER)
    target['fields'][0]['destination'] = 'other'
    with pytest.raises(ValueError): validate_routing(document)


def test_context_mismatch_is_review():
    row = sinhala(); row['Division'] = 'Other (අංශය)'
    assert 'REPORTED_HIERARCHY_CONTEXT_REQUIRES_REVIEW' in planned(row=row).payload['review_issues']


@pytest.fixture
def cryptos(tmp_path):
    data = dict(active_encryption_key_version='v1', active_lookup_key_version='v1',
                encryption_keys={'v1': base64.b64encode(os.urandom(32)).decode()},
                lookup_keys={'v1': base64.b64encode(os.urandom(32)).decode()})
    paths = [tmp_path/'primary.json', tmp_path/'backup.json']
    for p in paths: p.write_text(json.dumps(data))
    return tuple(IdentityCrypto(p) for p in paths)


def evidence():
    return dict(batch_id=BATCH, archive_sha256=ARCHIVE, confirmation_sha256=CONFIRMATION,
                source_system_code='POLICE_HR_IS', import_file_id=str(uuid4()), source_file_sha256='d'*64,
                source_row_number=1, master_import_file_id=str(uuid4()), master_file_sha256='e'*64, master_rows=607)


@pytest.mark.parametrize('filename', [MASTER, SINHALA])
def test_real_dual_key_recovery(cryptos, filename):
    primary, backup = cryptos; p = planned(filename); ev = evidence()
    cipher, version = seal_reference_plan(primary, p, evidence=ev)
    opening = dict(key_version=version, filename=filename, raw_record_id=p.payload['raw_record_id'], evidence=ev)
    recovered = open_reference_plan(primary, cipher, **opening)
    assert recovered == open_reference_plan(backup, cipher, **opening)
    assert recovered['plan'] == p.payload
    assert b'Example' not in cipher


@pytest.mark.parametrize('field,value', [('source_row_number',2),('source_file_sha256','f'*64),('master_file_sha256','f'*64),
    ('master_rows',606),('master_import_file_id',str(uuid4())),('import_file_id',str(uuid4()))])
def test_authenticated_provenance_rejects_rebinding(cryptos, field, value):
    primary, _ = cryptos; ev = evidence(); p = planned()
    cipher, version = seal_reference_plan(primary, p, evidence=ev)
    with pytest.raises(Exception):
        open_reference_plan(primary,cipher,key_version=version,filename=SINHALA,raw_record_id=C,evidence=dict(ev,**{field:value}))


def test_raw_file_and_cipher_rebinding_rejected(cryptos):
    primary, _ = cryptos; ev = evidence(); cipher, version = seal_reference_plan(primary,planned(),evidence=ev)
    for filename, rid, data in ((SINHALA,A,cipher),(MASTER,C,cipher),(SINHALA,C,bytes([cipher[0]^1])+cipher[1:])):
        with pytest.raises(Exception): open_reference_plan(primary,data,key_version=version,filename=filename,raw_record_id=rid,evidence=ev)


@pytest.mark.parametrize('field,value', [('linkage_accepted',True),('accepted_station_uid','station'),('valid_from','2020-01-01'),
    ('authority_result','VALID'),('record_classification','ORDINARY'),('needs_review',True),('uncertainties',[])])
def test_unapproved_semantics_rejected_even_before_sealing(cryptos, field, value):
    p = planned(); payload = copy.deepcopy(p.payload); payload[field] = value
    with pytest.raises(ValueError): seal_reference_plan(cryptos[0],ReferencePlan(payload),evidence=evidence())


def test_routing_coverage_and_intersection_mutations_rejected():
    for edit in ('field', 'order', 'value', 'joint', 'extra'):
        payload = copy.deepcopy(planned().payload)
        if edit == 'field': payload['fields'].pop()
        if edit == 'order': payload['fields'].reverse()
        if edit == 'value': payload['fields'][0]['value'] = 'changed'
        if edit == 'joint': payload['candidate_evidence'][0]['joint_raw_ids'] = [B]
        if edit == 'extra': payload['unexpected'] = True
        with pytest.raises(ValueError): validate_payload(payload)


@pytest.mark.parametrize('field,value', [('source_system_code','PF_REGISTRY'),('batch_id','OTHER'),('source_row_number',True),
    ('source_row_number',0),('master_rows',False),('source_file_sha256','bad')])
def test_invalid_envelope_metadata_rejected(field,value):
    with pytest.raises(ValueError): context(SINHALA,C,dict(evidence(),**{field:value}))


def test_authenticated_but_unapproved_payload_is_rejected_on_open(cryptos):
    primary, _ = cryptos
    ev = evidence(); payload = copy.deepcopy(planned().payload)
    payload['linkage_accepted'] = True
    cipher, version = primary.encrypt_assertion(dict(plan=payload,evidence=ev),context=context(SINHALA,C,ev))
    with pytest.raises(ValueError):
        open_reference_plan(primary,cipher,key_version=version,filename=SINHALA,raw_record_id=C,evidence=ev)
