import asyncio
import json
import pytest
from app.access.api import COOKIE,create_app,origin_url
from scoped_access_fixture import PASSWORD,setup,grant,catalog,identifier

class Client:
    def __init__(self,app):self.app=app;self.cookie='';self.csrf=''
    def request(self,path,method='GET',body=None,*,scheme='https',host='access.test:9443',
                origin='https://access.test:9443',cookie=None,csrf=None,raw=None,headers=(),query=b''):
        cookie=self.cookie if cookie is None else cookie
        csrf=self.csrf if csrf is None else csrf
        h=[(b'host',host.encode()),(b'content-type',b'application/json')]
        if origin is not None:h.append((b'origin',origin.encode()))
        if cookie:h.append((b'cookie',cookie.encode()))
        if csrf:h.append((b'x-csrf-token',csrf.encode()))
        h.extend(headers)
        payload=raw if raw is not None else json.dumps(body).encode() if body is not None else b''
        scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','scheme':scheme,'method':method,
               'path':path,'raw_path':path.encode(),'query_string':query,'headers':h,
               'client':('fixture-peer',1),'server':('access.test',9443),'root_path':''}
        async def call():
            events=[]
            async def receive():return {'type':'http.request','body':payload,'more_body':False}
            async def send(event):events.append(event)
            try:await self.app(scope,receive,send)
            except Exception:
                if not events:raise
            first=next(x for x in events if x['type']=='http.response.start')
            data=b''.join(x.get('body',b'') for x in events if x['type']=='http.response.body')
            return first['status'],[(k.decode(),v.decode()) for k,v in first['headers']],json.loads(data)
        return asyncio.run(call())
    def login(self):
        status,headers,b=self.request('/api/auth/login','POST',{'username':'station.one','password':PASSWORD},cookie='',csrf='')
        assert status==200
        value=next(v for k,v in headers if k=='set-cookie');self.cookie=value.split(';')[0];self.csrf=b['csrf_token']
        return value

@pytest.fixture(scope='module')
def client(tmp_path_factory):
    s,key,config=setup(tmp_path_factory.mktemp('asgi-access'))
    s.put_account(grant(key),PASSWORD);s.put_directory(catalog(key))
    c=Client(create_app(s,origin='https://access.test:9443'));c.login();return c

def test_secure_cookie_headers_and_session(client):
    value=client.login()
    for flag in ('HttpOnly','Secure','SameSite=strict','Path=/','Max-Age=1800'):assert flag in value
    assert value.startswith(COOKIE+'=') and 'Domain=' not in value
    status,h,b=client.request('/api/auth/session')
    assert status==200 and b['role']=='STATION_OIC' and b['scope_id']=='S1'
    assert ('cache-control','no-store') in h

@pytest.mark.parametrize('fault,expected',[
    ('http',403),('host',403),('origin',403),('missing-origin',403),('query',400),
    ('bearer',400),('cookie-duplicate',400),('csrf-duplicate',400),('oversize',413),('form',415)])
def test_outer_http_boundary(client,fault,expected):
    args={};headers=[]
    if fault=='http':args['scheme']='http'
    if fault=='host':args['host']='evil.test'
    if fault=='origin':args['origin']='https://evil.test'
    if fault=='missing-origin':args['origin']=None
    if fault=='query':args['query']=b'nic=private-value'
    if fault=='bearer':headers.append((b'authorization',b'Bearer fake'))
    if fault=='cookie-duplicate':headers.append((b'cookie',b'other=1'))
    if fault=='csrf-duplicate':headers.append((b'x-csrf-token',b'forged'))
    if fault=='oversize':args['raw']=b'x'*4097
    if fault=='form':headers.append((b'content-type',b'application/x-www-form-urlencoded'))
    status,h,b=client.request('/api/officers/search','POST',{'kind':'NIC','query':'000000001V'},headers=headers,**args)
    assert status==expected and ('cache-control','no-store') in h
    assert 'private-value' not in json.dumps(b)

@pytest.mark.parametrize('payload',[
    {'kind':'NAME','query':'reported','role':'IGP'}, {'kind':'NAME','query':'reported','scope_id':'S5'},
    {'kind':'NAME','query':'reported','effective_on':'1900-01-01'}, {'kind':'NIC','query':123},
    {'kind':'NAME','query':'a'}, {'kind':'NAME','query':'reported','limit':True},
    {'kind':'NAME','query':'reported','offset':-1}, {'kind':'FULL_EXPORT','query':'reported'}])
def test_untrusted_search_cannot_override_scope(client,payload):
    status,h,b=client.request('/api/officers/search','POST',payload)
    assert status==400

@pytest.mark.parametrize('raw',[b'{"kind":"NIC","kind":"NAME","query":"reported"}',b'{bad}',b'[]',b'null'])
def test_json_schema_never_echoes_sensitive_body(client,raw):
    status,h,b=client.request('/api/officers/search','POST',raw=raw)
    assert status==400 and b=={'error':'INVALID_REQUEST'}

def test_search_and_direct_id_only_permitted_projection(client):
    status,h,b=client.request('/api/officers/search','POST',{'kind':'NAME','query':'reported'})
    assert status==200 and b['total']==1 and b['items'][0]['officer_uid']==identifier(1)
    assert client.request('/api/officers/'+identifier(1))[0]==200
    a=client.request('/api/officers/'+identifier(5));b=client.request('/api/officers/'+identifier(999))
    assert a[0]==b[0]==404 and a[2]==b[2]=={'error':'NOT_FOUND'}

@pytest.mark.parametrize('cookie',['',COOKIE+'=forged',COOKIE+'=a; '+COOKIE+'=b'])
def test_no_client_identity_is_trusted(client,cookie):
    status,h,b=client.request('/api/auth/session',cookie=cookie)
    assert status==401

def test_missing_csrf_blocks_search_and_logout(client):
    assert client.request('/api/officers/search','POST',{'kind':'NIC','query':'000000001V'},csrf='')[0]==403
    assert client.request('/api/auth/logout','POST',{},csrf='wrong')[0]==403

def test_unknown_user_and_wrong_password_same_response(client):
    responses=[]
    for user,password in [('unknown.login',PASSWORD),('station.one','incorrect-password-long')]:
        responses.append(client.request('/api/auth/login','POST',{'username':user,'password':password},cookie='')[2])
    assert responses==[{'error':'INVALID_CREDENTIALS'}]*2

def test_no_registration_or_research_execution_route(client):
    for path in ('/api/auth/register','/api/admin/users','/api/findings','/api/anchor','/docs','/openapi.json'):
        assert client.request(path)[0]==404

@pytest.mark.parametrize('value',['http://access.test','https://access.test/','https://u:p@access.test','https://access.test?q=1','https://access.test#f'])
def test_factory_refuses_unsafe_origin(value):
    with pytest.raises(ValueError):origin_url(value)
