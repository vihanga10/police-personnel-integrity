"""Configured HTTPS ASGI backend for login and scope-filtered name/NIC search.

No registration, arbitrary scope override, personnel/finding disclosure, algorithm
execution or chain submission endpoint. Identity-only disclosure preserves the
existing CID/CCIB protection policy; it still needs base officer-scope access.
"""
import base64
import json
import os
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from app.access.policy import AccessError, require
from app.access.store import AccessStore, private

COOKIE = '__Host-ppi-session'


def origin_url(value):
    u = urlsplit(value)
    require(u.scheme == 'https' and u.hostname and u.path == '' and not u.username and
            not u.password and not u.query and not u.fragment and value == 'https://'+u.netloc,
            'Exact HTTPS origin required')
    require(u.hostname == u.hostname.lower(), 'Canonical hostname required')
    return value


def configured_store(config_file, *, create=False):
    f = private(config_file)
    config = json.loads(f.read_text())
    require(type(config) is dict and {'policy','repository','state_directory','key_file','authority_keys','origin'}<=set(config)<={'policy','repository','state_directory','key_file','authority_keys','origin','totp_required'}, 'Access config fields differ')
    require(config['policy']=='SCOPED_ACCESS_CONFIG_V1','Access config policy differs')
    private(f,repo=config['repository'])
    keys={k:base64.b64decode(v,validate=True) for k,v in config['authority_keys'].items()}
    origin=origin_url(config['origin'])
    require('totp_required' not in config or config['totp_required'] is True,'Mandatory TOTP configuration differs')
    store=AccessStore(config['state_directory'],config['key_file'],keys,repo=config['repository'],create=create)
    store.require_totp=config.get('totp_required',False)
    from app.access import totp
    with store.transaction() as c:totp.required(store,c)
    return store,origin


def _json_object(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise ValueError('Duplicate JSON field')
        result[k]=v
    return result


class RequestBoundary:
    """Outer ASGI guard bounds bodies and applies headers even to server errors."""
    def __init__(self,app,origin):
        self.app,self.origin=app,origin

    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        headers=scope['headers']
        values=lambda key:[v.decode('latin1') for k,v in headers if k.lower()==key]
        hosts=values(b'host'); origins=values(b'origin')
        status=None;code=None
        if scope['scheme']!='https' or hosts!=[urlsplit(self.origin).netloc]: status,code=403,'HTTPS_OR_HOST_REQUIRED'
        elif scope.get('query_string'): status,code=400,'QUERY_PARAMETERS_FORBIDDEN'
        elif scope['method']=='POST' and origins!=[self.origin]: status,code=403,'ORIGIN_REQUIRED'
        elif len(values(b'cookie'))>1 or len(values(b'x-csrf-token'))>1: status,code=400,'AMBIGUOUS_HEADERS'
        elif values(b'authorization'): status,code=400,'COOKIE_AUTH_REQUIRED'
        elif scope['method']=='POST' and values(b'content-type') not in (['application/json'],['application/json; charset=utf-8']): status,code=415,'JSON_REQUIRED'
        body=b''
        if status is None:
            while True:
                event=await receive()
                if event['type']=='http.disconnect': return
                body+=event.get('body',b'')
                if len(body)>4096: status,code=413,'BODY_TOO_LARGE';break
                if not event.get('more_body'): break
        async def security_send(event):
            if event['type']=='http.response.start':
                event=dict(event);event['headers']=list(event.get('headers',[]))+[
                    (b'cache-control',b'no-store'),(b'pragma',b'no-cache'),
                    (b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),
                    (b'content-security-policy',b"default-src 'none'; frame-ancestors 'none'"),
                    (b'referrer-policy',b'no-referrer'),
                    (b'strict-transport-security',b'max-age=31536000')]
            await send(event)
        if status is not None:
            return await JSONResponse({'error':code},status_code=status)(scope,receive,security_send)
        sent=False
        async def buffered_receive():
            nonlocal sent
            if not sent: sent=True;return {'type':'http.request','body':body,'more_body':False}
            return await receive()
        await self.app(scope,buffered_receive,security_send)


def create_app(store, *, origin):
    """Trusted application factory. Caller owns private configuration, never HTTP."""
    require(type(store) is AccessStore,'Exact configured store required');origin_url(origin)
    app=FastAPI(title='Scoped Police Personnel Access',docs_url=None,redoc_url=None,openapi_url=None)

    @app.exception_handler(AccessError)
    async def denied(request,exc): return JSONResponse({'error':exc.code},status_code=exc.status)

    @app.exception_handler(Exception)
    async def failed(request,exc): return JSONResponse({'error':'ACCESS_SERVICE_UNAVAILABLE'},status_code=503)

    def token(request):
        # Reject duplicate same-name cookies instead of accepting the last one.
        cookies=request.headers.get('cookie','').split(';')
        if sum(x.strip().startswith(COOKIE+'=') for x in cookies)>1: raise AccessError(401,'LOGIN_REQUIRED')
        return request.cookies.get(COOKIE)

    async def body(request,fields,optional=()):
        try:
            result=json.loads(await request.body(),object_pairs_hook=_json_object,
                              parse_constant=lambda x:(_ for _ in ()).throw(ValueError()))
            if type(result) is not dict or not set(fields)<=set(result) or set(result)-set(fields)-set(optional): raise ValueError()
            return result
        except Exception: raise AccessError(400,'INVALID_REQUEST') from None

    @app.post('/api/auth/login')
    async def login(request:Request):
        b=await body(request,{'username','password'},{'totp_code'})
        t,c=await run_in_threadpool(store.login,b['username'],b['password'],request.client.host if request.client else 'unknown',token(request),b.get('totp_code'))
        response=JSONResponse({'authenticated':True,'csrf_token':c})
        response.set_cookie(COOKIE,t,max_age=1800,secure=True,httponly=True,samesite='strict',path='/')
        return response

    @app.get('/api/auth/session')
    async def session(request:Request): return await run_in_threadpool(store.session,token(request))

    @app.post('/api/auth/logout')
    async def logout(request:Request):
        await body(request,set())
        await run_in_threadpool(store.logout,token(request),request.headers.get('x-csrf-token',''))
        response=JSONResponse({'authenticated':False})
        response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='strict')
        return response

    @app.post('/api/officers/search')
    async def search(request:Request):
        b=await body(request,{'kind','query'}, {'limit','offset'})
        return await run_in_threadpool(store.search,token(request),request.headers.get('x-csrf-token',''),
            b['kind'],b['query'],b.get('limit',20),b.get('offset',0))

    @app.get('/api/officers/{officer_uid}')
    async def officer(officer_uid:str,request:Request):
        return await run_in_threadpool(store.officer,token(request),officer_uid)

    return RequestBoundary(app,origin)


def application():
    """uvicorn factory: no default credentials/state/origin and no automatic setup."""
    file=os.environ.get('PPI_ACCESS_CONFIG')
    require(file,'Set PPI_ACCESS_CONFIG to private reviewed config')
    store,origin=configured_store(file)
    return create_app(store,origin=origin)
