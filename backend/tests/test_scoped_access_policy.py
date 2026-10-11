import base64
from copy import deepcopy
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.policy import account,permitted,name
from app.access.directory import validate_directory
from scoped_access_fixture import ROLE_SCOPES,grant,catalog,sign

@pytest.fixture
def authority():
    key=Ed25519PrivateKey.generate()
    return key,{'test-admin':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}

@pytest.mark.parametrize('role,level,scope,expected',[
    ('IGP','ALL',None,6),('HQ_ADMIN','ALL',None,6),('SDIG','PROVINCE','P1',4),
    ('DIG','DISTRICT','D1',3),('SSP','DIVISION','V1',2),('SP','DIVISION','V1',2),
    ('STATION_OIC','STATION','S1',1)])
def test_role_matrix(authority,role,level,scope,expected):
    key,keys=authority;p=account(grant(key,role,level,scope),keys);d=validate_directory(catalog(key),keys)
    assert sum(permitted(p,o) for o in d['officers'])==expected

@pytest.mark.parametrize('role,level,scope',[
    ('CONSTABLE','STATION','S1'),('SI','STATION','S1'),('SP','ALL',None),
    ('STATION_OIC','PROVINCE','P1'),('SDIG','ALL',None),('IGP','DISTRICT','D1'),
    ('STATION_OIC','STATION',None),('HQ_ADMIN','ALL','P1')])
def test_forbidden_role_or_scope(authority,role,level,scope):
    key,keys=authority
    with pytest.raises(ValueError):account(grant(key,role,level,scope),keys)

@pytest.mark.parametrize('fault',['signature','key','expired','future','long','extra','wrong-kind','zero-version'])
def test_grant_failures(authority,fault):
    key,keys=authority;e=grant(key);p=e['payload'];now=int(time.time())
    if fault=='key':e['key_id']='unknown'
    elif fault=='signature':e['signature']=base64.b64encode(b'x'*64).decode()
    else:
        if fault=='expired':p['expires_at']=now-1
        if fault=='future':p['issued_at']=now+10
        if fault=='long':p['expires_at']=p['issued_at']+86401
        if fault=='extra':p['rank']='IGP'
        if fault=='wrong-kind':p['kind']='RESEARCH_APPROVAL'
        if fault=='zero-version':p['version']=0
        e=sign(key,p)
    with pytest.raises(Exception):account(e,keys)

@pytest.mark.parametrize('fault',['duplicate','extra-narrative','bad-parent','conflicting-parent','name-control','numeric-nic','bad-uuid','duplicate-name-field'])
def test_directory_failures(authority,fault):
    key,keys=authority;e=catalog(key);p=e['payload'];o=p['officers'][0]
    if fault=='duplicate':p['officers'].append(deepcopy(o))
    if fault=='extra-narrative':o['findings']='private narrative'
    if fault=='bad-parent':o['membership']['DIVISION']=None
    if fault=='conflicting-parent':p['officers'][1]['membership']['PROVINCE']='P2'
    if fault=='name-control':o['names']=['bad\x00name']
    if fault=='numeric-nic':o['nic']=123
    if fault=='bad-uuid':o['officer_uid']='not-uuid'
    if fault=='duplicate-name-field':o['names']=[]
    with pytest.raises(Exception):validate_directory(sign(key,p),keys)

def test_sinhala_casefold_and_whitespace():
    assert name('  Same   NAME ')==name('same name')
    assert name('ශ්‍රී ලංකා')=='ශ්‍රී ලංකා'

@pytest.mark.parametrize('assignment',['ORDINARY','CID_CCIB','UNRESOLVED'])
def test_existing_classification_keeps_only_name_nic_projection(assignment):
    from app.security.record_protection import required_protection,AssignmentProtection,RecordClassification,DisclosureCategory,ProtectionLevel
    assert required_protection(assignment=AssignmentProtection[assignment],
        record_classification=RecordClassification.UNASSESSED,category=DisclosureCategory.OFFICER_NAME_NIC).level is ProtectionLevel.NORMAL
    # NORMAL still requires permitted() base scope; no personnel-details route is provided.
