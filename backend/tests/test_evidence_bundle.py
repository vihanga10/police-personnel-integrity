"""Inventory membership and real AES recovery using ephemeral fixture keys."""
import base64
import copy
import json
from uuid import uuid4
import pytest
from app.identity.evidence_bundle import BundleInventory, canonical, seal_artifact, open_artifact
from app.security.identity_crypto import IdentityCrypto

A, B = str(uuid4()), str(uuid4())
R, S = 'a'*64, 'b'*64
SNAP = dict(batch_id='fixture', archive_sha256='c'*64, confirmation_sha256='d'*64,
    code_revision='e'*40, collection_started_at='2026-10-08T00:00:00+00:00')


def inventory(order=(A, B)):
    return BundleInventory(order, {'shared.csv': 1, 'unresolved.csv': 1})


def add(inv, name='shared.csv', raw=R, associations=((A,'participant'),(B,'commander'))):
    inv.add(name,raw,dict(columns=['name','code'],values=['  PRIVATE_VALUE  ','001']),
        dict(source_row_number=1,import_file_id=str(uuid4())),associations)
    inv.bind_receipt(raw,dict(complete=True,assertion_id=str(uuid4())),dict(assertion_type='CLAIM'))


def test_shared_and_unresolved_rows_never_dropped():
    inv=inventory();add(inv);add(inv,'unresolved.csv',S,())
    manifest=inv.finish(SNAP)
    assert manifest['received_rows']==2 and manifest['unassigned_rows']==1
    assert len(inv.catalog['shared.csv'])==1
    assert all(len(b['evidence'])==1 for b in manifest['bundles'])
    assert inv.catalog['shared.csv'][R]['original']['values']==['  PRIVATE_VALUE  ','001']
    assert all(not e['linkage_accepted'] for b in manifest['bundles'] for e in b['evidence'])


def test_duplicate_raw_id_across_files_rejected():
    inv=inventory();add(inv)
    with pytest.raises(ValueError):add(inv,'unresolved.csv',R,())


def test_unknown_officer_is_not_guessed():
    inv=inventory()
    with pytest.raises(ValueError):add(inv,associations=((str(uuid4()),'subject'),))


def test_missing_row_and_missing_receipt_block_finish():
    inv=inventory();add(inv)
    with pytest.raises(ValueError):inv.finish(SNAP)
    inv.add('unresolved.csv',S,dict(columns=['x'],values=['']),dict(source_row_number=1),())
    with pytest.raises(ValueError):inv.finish(SNAP)


def test_duplicate_or_incomplete_receipt_rejected():
    inv=inventory();add(inv)
    with pytest.raises(ValueError):inv.bind_receipt(R,dict(complete=True),{})
    with pytest.raises(ValueError):inv.bind_receipt(S,dict(complete=False),{})


def test_candidate_roles_deduplicated():
    inv=inventory();add(inv,associations=((A,'subject'),(A,'subject'),(A,'actor')));add(inv,'unresolved.csv',S,())
    manifest=inv.finish(SNAP)
    bundle=next(b for b in manifest['bundles'] if b['officer_uid']==A)
    assert bundle['evidence'][0]['candidate_roles']==['actor','subject']


def test_profile_coverage_cannot_be_empty():
    inv=BundleInventory([A],{'officer_personal_information.csv':1})
    add(inv,'officer_personal_information.csv',R,())
    with pytest.raises(ValueError):inv.finish(SNAP)


@pytest.mark.parametrize('original',[
    dict(columns=['x','x'],values=['1','2']),dict(columns=['x'],values=[1]),
    dict(columns=['x'],values=[]),dict(columns=['x'],values=['x'],extra=True)])
def test_original_shape_rejected(original):
    inv=inventory()
    with pytest.raises(ValueError):inv.add('shared.csv',R,original,dict(source_row_number=1),())


def test_order_is_deterministic_and_changes_are_visible():
    assert canonical({'b':2,'a':1})==canonical({'a':1,'b':2})
    inv=inventory((B,A));add(inv);add(inv,'unresolved.csv',S,())
    m=inv.finish(SNAP)
    assert [b['officer_uid'] for b in m['bundles']]==sorted([A,B])
    altered=copy.deepcopy(m);altered['bundles'][0]['bundle_version']=2
    assert canonical(m)!=canonical(altered)


@pytest.fixture
def crypto(tmp_path):
    data=dict(active_encryption_key_version='v1',active_lookup_key_version='v1',
        encryption_keys={'v1':base64.b64encode(bytes(range(32))).decode()},
        lookup_keys={'v1':base64.b64encode(bytes(reversed(range(32)))).decode()})
    path=tmp_path/'keys.json';path.write_text(json.dumps(data))
    return IdentityCrypto(path)


def test_encryption_hides_cells_and_wrong_context_fails(crypto):
    payload=dict(original='PRIVATE_VALUE',officer_uid=A)
    binding=dict(artifact='fixture')
    envelope=seal_artifact(crypto,crypto,payload,binding)
    assert 'PRIVATE_VALUE' not in json.dumps(envelope) and A not in json.dumps(envelope)
    assert open_artifact(crypto,envelope,binding)==payload
    with pytest.raises(ValueError):open_artifact(crypto,envelope,dict(artifact='other'))
    changed=copy.deepcopy(envelope)
    cipher=bytearray(base64.b64decode(changed['ciphertext']));cipher[-1]^=1
    changed['ciphertext']=base64.b64encode(cipher).decode()
    with pytest.raises(Exception):open_artifact(crypto,changed,binding)


def test_wrong_backup_blocks_export(crypto,tmp_path):
    data=json.loads((tmp_path/'keys.json').read_text())
    data['encryption_keys']['v1']=base64.b64encode(b'Z'*32).decode()
    path=tmp_path/'wrong.json';path.write_text(json.dumps(data))
    with pytest.raises(Exception):seal_artifact(crypto,IdentityCrypto(path),dict(x=1),dict(artifact='fixture'))
