"""BSON recovery, least-privilege contracts and private reference credentials."""
from copy import deepcopy
from datetime import timedelta, datetime
import json
import os
import pytest
from bson import BSON
from bson.codec_options import CodecOptions
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.storage.check_reference_mongo import fixture
from app.storage.reference_mongo_contract import COLLECTION_POLICIES, privileges, validator, encryption_context
from app.storage.reference_mongo_connection import reference_password
from app.storage import setup_reference_mongo as setup


@pytest.mark.parametrize('collection', list(COLLECTION_POLICIES))
def test_exact_original_payload_after_bson_roundtrip(collection):
    doc,key,plain=fixture(collection)
    recovered=BSON.encode(doc).decode(codec_options=CodecOptions(tz_aware=True))
    cipher=bytes(recovered['payload_ciphertext'])
    assert AESGCM(key).decrypt(cipher[:12],cipher[12:],encryption_context(collection,recovered).encode())==plain
    payload=json.loads(plain)
    assert payload['fields'][0]['value']=='00012'
    assert payload['fields'][1]['source_value']=='  EXAMPLE  '
    assert payload['fields'][2]['value']==''
    assert payload['accepted_station_uid'] is None and payload['linkage_accepted'] is False
    recovered['recorded_at']+=timedelta(milliseconds=1)
    with pytest.raises(InvalidTag): AESGCM(key).decrypt(cipher[:12],cipher[12:],encryption_context(collection,recovered).encode())


@pytest.mark.parametrize('field,value',[('_id','0'*36),('source_assertion_uid','0'*36),('raw_record_id','0'*64),
    ('writer_policy','CHANGED'),('schema_version',2),('classification','ORDINARY'),('payload_key_version','CHANGED')])
def test_metadata_rebinding_rejected(field,value):
    doc,key,_=fixture('station_reference_records'); cipher=bytes(doc['payload_ciphertext']); doc[field]=value
    with pytest.raises(InvalidTag): AESGCM(key).decrypt(cipher[:12],cipher[12:],encryption_context('station_reference_records',doc).encode())


def test_cross_collection_and_cipher_tampering_rejected():
    doc,key,_=fixture('station_reference_records'); cipher=bytes(doc['payload_ciphertext'])
    with pytest.raises(InvalidTag): AESGCM(key).decrypt(cipher[:12],cipher[12:],encryption_context('station_sinhala_reference_records',doc).encode())
    with pytest.raises(InvalidTag): AESGCM(key).decrypt(cipher[:12],cipher[12:-1]+bytes([cipher[-1]^1]),encryption_context('station_reference_records',doc).encode())
    doc['recorded_at']=datetime.now()
    with pytest.raises(ValueError): encryption_context('station_reference_records',doc)


def test_contract_only_opaque_metadata_and_encrypted_payload():
    for collection,policy in COLLECTION_POLICIES.items():
        schema=validator(collection)['$and'][0]['$jsonSchema']
        assert schema['additionalProperties'] is False
        assert set(schema['required'])==set(schema['properties'])
        assert schema['properties']['writer_policy']=={'enum':[policy]}
        assert schema['properties']['classification']=={'enum':['UNASSESSED']}
        assert schema['properties']['payload_ciphertext']=={'bsonType':'binData'}
        assert not {'officer_uid','station_code','station_name','candidate_mappings'} & set(schema['properties'])
        schema['properties']['writer_policy']['enum'].append('BAD')
        assert validator(collection)['$and'][0]['$jsonSchema']['properties']['writer_policy']=={'enum':[policy]}
    assert {p['resource']['collection'] for p in privileges()}==set(COLLECTION_POLICIES)
    assert all(p['actions']==['find','insert'] for p in privileges())
    assert {p['resource']['db'] for p in privileges('disposable')}=={'disposable'}


@pytest.mark.parametrize('collection',['service_status_events','education_records','unknown'])
def test_wrong_collection_rejected(collection):
    with pytest.raises(ValueError): validator(collection)


def test_credentials_private_and_stable(tmp_path):
    path=tmp_path/'reference'
    password=reference_password(path,create=True)
    assert reference_password(path,create=True)==password and len(password)>=32
    assert path.stat().st_mode & 0o077==0 and (path/'credentials.json').stat().st_mode & 0o077==0


@pytest.mark.parametrize('target',['directory','file'])
def test_permissive_credentials_rejected(tmp_path,target):
    path=tmp_path/'reference'; reference_password(path,create=True)
    (path if target=='directory' else path/'credentials.json').chmod(0o755 if target=='directory' else 0o644)
    with pytest.raises(ValueError): reference_password(path)


@pytest.mark.parametrize('target',['directory','file','ancestor'])
def test_symlink_credentials_rejected(tmp_path,target):
    path=tmp_path/'reference'; reference_password(path,create=True)
    if target=='file':
        (path/'credentials.json').rename(path/'saved'); os.symlink(path/'saved',path/'credentials.json')
    elif target=='directory':
        path.rename(tmp_path/'saved'); os.symlink(tmp_path/'saved',path)
    else:
        os.symlink(tmp_path,tmp_path/'link'); path=tmp_path/'link'/'reference'
    with pytest.raises(ValueError): reference_password(path)


def test_credential_directories_must_be_distinct(tmp_path):
    with pytest.raises(ValueError): setup.previous.separate_directories(tmp_path/'bootstrap',tmp_path/'same',tmp_path/'same')


@pytest.mark.parametrize('change',[None,'broader_reference','broader_remaining','inherited_role','extra_user','extra_role','missing_old_user','duplicate_role','wrong_assignment'])
def test_exact_accounts_preserved(change):
    roles={role:dict(role=role,roles=[],privileges=deepcopy(priv())) for user,role,priv in setup.ACCOUNT_DEFINITIONS}
    users=[dict(user=user,roles=[dict(role=role,db=setup.DATABASE)]) for user,role,priv in setup.ACCOUNT_DEFINITIONS]
    if change in {'broader_reference','broader_remaining'}: roles[setup.ROLE if change=='broader_reference' else setup.REMAINING_ROLE]['privileges'][0]['actions'].append('update')
    elif change=='inherited_role': roles[setup.ROLE]['roles']=[dict(role='readWrite',db=setup.DATABASE)]
    elif change=='extra_user': users.append(dict(user='unexpected',roles=[]))
    elif change=='extra_role': roles['unexpected']=dict(role='unexpected',roles=[],privileges=[])
    elif change=='missing_old_user': users.pop(0)
    elif change=='wrong_assignment': users[-1]['roles']=[dict(role=setup.REMAINING_ROLE,db=setup.DATABASE)]
    class Database:
        def command(self,kind,name,**kw):
            if kind=='usersInfo': return {'users':users}
            result=list(roles.values()) if name==1 else [roles[name]]
            if change=='duplicate_role' and name==1: result.append(deepcopy(roles[setup.ROLE]))
            return {'roles':result}
    if change is None: assert setup.verify_accounts(Database(),require_reference=True)==(True,True)
    else:
        with pytest.raises(RuntimeError): setup.verify_accounts(Database(),require_reference=True)


def test_optional_new_account_does_not_make_old_accounts_optional():
    roles={role:dict(role=role,roles=[],privileges=deepcopy(priv())) for user,role,priv in setup.ACCOUNT_DEFINITIONS if user!=setup.APP_USER}
    users=[dict(user=user,roles=[dict(role=role,db=setup.DATABASE)]) for user,role,priv in setup.ACCOUNT_DEFINITIONS if user!=setup.APP_USER]
    class Database:
        def command(self,kind,name,**kw):
            return {'users':users} if kind=='usersInfo' else {'roles':list(roles.values()) if name==1 else [roles[name]]}
    assert setup.verify_accounts(Database(),require_reference=False)==(False,False)
    with pytest.raises(RuntimeError): setup.verify_accounts(Database(),require_reference=True)


@pytest.mark.parametrize('extra',[None,'expireAfterSeconds','partialFilterExpression','sparse','hidden','collation','changed_key'])
def test_index_contract_rejects_retention_and_other_changes(extra):
    name='station_reference_records'
    indexes=[dict(name=key,key=dict(keys),**({'unique':True} if unique else {})) for key,(keys,unique) in setup.INDEXES.items()]
    if extra=='changed_key': indexes[-1]['key']={'station_code':1}
    elif extra: indexes[-1][extra]=1
    class Database:
        def list_collections(self,**kw):return [dict(type='collection',options=dict(validator=validator(name),validationLevel='strict',validationAction='error'))]
        def __getitem__(self,name):return self
        def list_indexes(self):return indexes
    if extra:
        with pytest.raises(RuntimeError): setup.verify_reference_collection(Database(),name)
    else: setup.verify_reference_collection(Database(),name)


def test_prior_count_checkpoint_has_all_fifteen_collections():
    assert len(setup.EXISTING_COUNTS)==15
    assert setup.EXISTING_COUNTS['education_records']==6596 and setup.EXISTING_COUNTS['operation_records']==19554
    assert not set(setup.EXISTING_COUNTS)&set(COLLECTION_POLICIES)
    assert len('police_ref_smoke_'+'a'*32)<64
