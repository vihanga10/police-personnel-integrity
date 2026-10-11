"""Real AEAD/audit-permit fixtures; original full-batch loader substituted only in test."""
from copy import deepcopy
import time
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.directory import export_directory,validate_directory
from app.access.policy import POLICY
from app.identity.protected_commitment import digest
from test_protected_recording_review import verified,source,keys,setup_review
from scoped_access_fixture import sign

@pytest.fixture
def export_setup(setup_review,monkeypatch):
    snapshot,row,dest,repo=setup_review
    officer=str(row['officer_uid']);raw=row['raw_record_id']
    snapshot['manifest']={'bundles':[{'officer_uid':officer}]}
    item=snapshot['catalog'][raw]
    item.update(filename='officer_personal_information.csv',original={'columns':['officer_nic_no','full_name','name_with_initials'],
        'values':['000000001V','Reported Name','R. Name']})
    key=Ed25519PrivateKey.generate();trust={'test-admin':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    now=int(time.time());payload=dict(policy=POLICY,kind='MEMBERSHIP',issued_at=now-1,expires_at=now+600,
        source_public_sha256=digest(snapshot['public']),officers=[{'officer_uid':officer,'membership':
        {'PROVINCE':'P1','DISTRICT':'D1','DIVISION':'V1','STATION':'S1'}}],review_reference='TEST_MEMBERSHIP')
    calls=[]
    def loader(args,repo,rev):calls.append((args,repo,rev));return snapshot
    import app.identity.algorithm_snapshot as A
    monkeypatch.setattr(A,'load_verified_snapshot',loader)
    return snapshot,key,trust,payload,repo,calls

def test_export_uses_full_loader_then_separately_signed_directory(export_setup):
    s,k,trust,p,repo,calls=export_setup;args=SimpleNamespace()
    draft=export_directory(args,repo,'a'*40,sign(k,p),trust,generation=1)
    assert calls==[(args,repo,'a'*40)]
    verified=validate_directory(sign(k,draft),trust)
    assert verified['officers'][0]['nic']=='000000001V' and verified['officers'][0]['names']==['Reported Name','R. Name']
    assert 'signature' not in draft # Offline approval remains a separate administrator action.

@pytest.mark.parametrize('fault',['source-digest','missing-member','duplicate-member','profile-link','binding','delivery'])
def test_export_never_guesses_membership_or_profile_link(export_setup,fault):
    s,k,trust,p,repo,calls=export_setup
    if fault=='source-digest':p['source_public_sha256']='f'*64
    if fault=='missing-member':p['officers']=[]
    if fault=='duplicate-member':p['officers']+=deepcopy(p['officers'])
    raw=next(iter(s['catalog']));item=s['catalog'][raw]
    if fault=='profile-link':item['candidate_links'][0]['state']='UNRESOLVED'
    if fault=='binding':s['bindings']['raw_bindings']={}
    if fault=='delivery':item['delivery']['complete']=False
    with pytest.raises(ValueError):export_directory(None,repo,'a'*40,sign(k,p),trust,generation=1)


def test_real_aead_permit_tampering_blocks_export(export_setup):
    s,k,trust,p,repo,calls=export_setup
    s['envelope']['unexpected']='tampered'
    with pytest.raises(Exception):export_directory(None,repo,'a'*40,sign(k,p),trust,generation=1)
