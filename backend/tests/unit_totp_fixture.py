import sys
sys.dont_write_bytecode=True
import base64,hashlib,importlib.util,json,os,sqlite3,time
from pathlib import Path
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'backend'),str(REPO/'backend/tests')]
from app.access.store import AccessStore
from app.access.research_store import ResearchStore
from app.access.accountability import AccountabilityStore
from app.access import policy as A,research_policy as P
from research_workspace_fixture import presentation,disclosure
spec=importlib.util.spec_from_file_location('renewal',REPO/'backend/scripts/_unit_setup_support.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
PASSWORD='invented-private-fixture-password'

@pytest.fixture
def setup(tmp_path):
    app=tmp_path/'app';app.mkdir(mode=0o700)
    for folder in ('keys','key-backup','access','workspace','logs'):(app/folder).mkdir(mode=0o700)
    def write(path,value):
        path.write_bytes(value if isinstance(value,bytes) else A.encoded(value));path.chmod(0o600);return path
    ak,wk,lk=(os.urandom(32) for _ in range(3))
    ask,wsk=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    for name,key in [('research-access-signer.key',ask),('research-presentation-signer.key',wsk)]:
        for folder in ('keys','key-backup'):write(app/folder/name,key.private_bytes_raw())
    write(app/'keys/access.key',ak);write(app/'keys/workspace.key',wk);write(app/'keys/log.key',lk)
    now=int(time.time());old=now-90000
    a=AccessStore(app/'access',app/'keys/access.key',{'access-test':ask.public_key().public_bytes_raw()},repo=REPO,create=True,clock=lambda:old)
    w=ResearchStore(app/'workspace',app/'keys/workspace.key',{'workspace-test':wsk.public_key().public_bytes_raw()},access=a,create=True)
    l=AccountabilityStore(app/'logs',app/'keys/log.key',access=a,create=True)
    members=[];officers=[str(uuid4()),str(uuid4())]
    for i,uid in enumerate(officers):
        members.append(dict(officer_uid=uid,nic=f'90000000{i+1}V',names=[f'Invented Fixture Officer {i+1}'],source_raw_id=str(i+1)*64,
            membership=dict(PROVINCE='P',DISTRICT='D',DIVISION='A' if i==0 else 'B',STATION='SA' if i==0 else 'SB')))
        e=presentation(wsk,officer=uid,now=old)
        e['payload'].update(policy=P.RETAINED_POLICY,expires_at=None,record_origin='GENERATED_RESEARCH_RECORDS',full_records=[])
        w.import_packet(M.sign(wsk,'workspace-test',e['payload']))
    directory=dict(policy=A.RETAINED_DIRECTORY_POLICY,kind='DIRECTORY',issued_at=old-1,expires_at=None,generation=1,
        source_public_sha256='a'*64,officers=members,review_reference='FIXTURE_DIRECTORY',record_origin='GENERATED_RESEARCH_RECORDS')
    a.put_directory(M.sign(ask,'access-test',directory))
    roles=[('igp','IGP','ALL',None,True),('hq','HQ_ADMIN','ALL',None,True),('sdig','SDIG','PROVINCE','P',True),
        ('dig.a','DIG','DIVISION','A',True),('dig.b.inactive','DIG','DIVISION','B',False),
        ('ssp.a','SSP','DIVISION','A',True),('ssp.b','SSP','DIVISION','B',True),('sp.a','SP','DIVISION','A',True),
        ('oic.a','STATION_OIC','STATION','SA',True),('oic.b','STATION_OIC','STATION','SB',True)]
    accounts=[]
    for name,role,scope,ident,active in roles:
        p=dict(policy=A.POLICY,kind='ACCOUNT',issued_at=old-1,expires_at=old+86398,user_id=str(uuid4()),username='research.'+name,
            role=role,scope_type=scope,scope_id=ident,version=1,active=active,review_reference='GENERATED_FIXTURE')
        a.put_account(M.sign(ask,'access-test',p),PASSWORD);accounts.append(p)
        if active:
            for o in members:
                if A.permitted(p,o):
                    d=disclosure(wsk,user=p['user_id'],officer=o['officer_uid'],now=old,reviews=name=='igp' and o==members[0])
                    d['payload'].update(policy=P.RETAINED_POLICY,expires_at=old+86398)
                    w.import_grant(M.sign(wsk,'workspace-test',d['payload']))
    reader=app/'hq-reader.json'
    write(reader,M.sign(ask,'access-test',dict(policy='PERSONNEL_ACCOUNTABILITY_V1',kind='READ_ACCESS_LOGS',user_id=accounts[1]['user_id'],
        account_version=1,issued_at=old-1,expires_at=old+86398,review_reference='HQ_READER_FIXTURE')))
    l.grant_files=(reader,);l.append(dict(action='LOGIN',phase='COMPLETED',status=401,outcome='DENIED',method='POST'))
    ac=dict(policy='SCOPED_ACCESS_CONFIG_V1',repository=str(REPO),state_directory=str(a.root),key_file=str(a.key_path),
        authority_keys={'access-test':base64.b64encode(ask.public_key().public_bytes_raw()).decode()},origin='https://127.0.0.1:61099')
    lc=dict(policy='ACCOUNTABILITY_CONFIG_V1',state_directory=str(l.root),key_file=str(l.key_path),reader_grants=[str(reader)])
    wc=dict(policy='RESEARCH_WEB_CONFIG_V1',access_config=str(app/'access-config.json'),state_directory=str(w.root),key_file=str(app/'keys/workspace.key'),
        presentation_keys={'workspace-test':base64.b64encode(wsk.public_key().public_bytes_raw()).decode()},accountability_config=str(app/'accountability-config.json'))
    write(app/'access-config.json',ac);write(app/'workspace-config.json',wc);write(app/'accountability-config.json',lc)
    write(app/'accounts.json',dict(record_origin='GENERATED_RESEARCH_RECORDS',accounts=accounts));write(app/'credentials.json',{p['username']:PASSWORD for p in accounts})
    with sqlite3.connect(w.path) as c:
        c.execute('CREATE TABLE application_review_entries(seq INTEGER PRIMARY KEY, value BLOB)')
        c.execute('INSERT INTO application_review_entries VALUES(1,?)',(b'unchanged-encrypted-review-evidence',))
    return dict(app=app,a=a,w=w,l=l,ask=ask,wsk=wsk,accounts=accounts,members=members)

