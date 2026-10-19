"""Disposable identities and authority; never a research source or default login."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import time
from uuid import UUID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.policy import POLICY,encoded
from app.access.store import AccessStore

PASSWORD='isolated-test-password-2026'
ROLE_SCOPES=[('IGP','ALL',None),('HQ_ADMIN','ALL',None),('SDIG','PROVINCE','P1'),
             ('DIG','DISTRICT','D1'),('SSP','DIVISION','V1'),('SP','DIVISION','V1'),
             ('STATION_OIC','STATION','S1')]

def identifier(n):return str(UUID(int=n))

def sign(key,payload):
    return {'key_id':'test-admin','payload':deepcopy(payload),'signature':base64.b64encode(key.sign(encoded(payload))).decode()}

def grant(key,role='STATION_OIC',scope_type='STATION',scope_id='S1',login='station.one',version=1,now=None,active=True):
    now=int(time.time()) if now is None else int(now)
    return sign(key,dict(policy=POLICY,kind='ACCOUNT',issued_at=now-1,expires_at=now+3600,user_id=identifier(100),
                        username=login,role=role,scope_type=scope_type,scope_id=scope_id,version=version,
                        active=active,review_reference='TEST_ONLY_APPOINTMENT'))

def catalog(key,now=None,generation=1):
    now=int(time.time()) if now is None else int(now)
    members=[('P1','D1','V1','S1'),('P1','D1','V1','S2'),('P1','D1','V2','S3'),
             ('P1','D2','V3','S4'),('P2','D3','V4','S5'),(None,None,None,None)]
    officers=[]
    for n,m in enumerate(members,1):
        officers.append(dict(officer_uid=identifier(n),nic='00000000'+str(n)+'V',
            names=['Same Reported Name '+str(n),'විහඟ මධුෂාමිණී '+str(n)],
            membership=dict(zip(('PROVINCE','DISTRICT','DIVISION','STATION'),m)),source_raw_id=f'{n:064x}'))
    return sign(key,dict(policy=POLICY,kind='DIRECTORY',issued_at=now-1,expires_at=now+3600,generation=generation,
                        source_public_sha256='a'*64,officers=officers,review_reference='TEST_ONLY_MEMBERSHIP'))

def setup(root,*,clock=time.time):
    root=Path(root).resolve();root.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(root,0o700)
    key=Ed25519PrivateKey.generate();keys={'test-admin':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    keyfile=root/'access.key';keyfile.write_bytes(os.urandom(32));keyfile.chmod(0o600)
    state=root/'state';state.mkdir(mode=0o700)
    repo=root/'repo';repo.mkdir()
    store=AccessStore(state,keyfile,keys,repo=repo,create=True,clock=clock)
    config=dict(policy='SCOPED_ACCESS_CONFIG_V1',repository=str(repo),state_directory=str(state),key_file=str(keyfile),
        authority_keys={k:base64.b64encode(v).decode() for k,v in keys.items()},origin='https://access.test:9443')
    configfile=root/'access-config.json';configfile.write_text(json.dumps(config));configfile.chmod(0o600)
    return store,key,configfile
