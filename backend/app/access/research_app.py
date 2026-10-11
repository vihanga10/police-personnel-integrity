"""Same-origin HTTPS UI + scoped research facade. No arbitrary runner routes."""
import base64
import json
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from app.access.api import COOKIE, RequestBoundary, configured_store, create_app as identity_app, _json_object
from app.access.policy import AccessError, require
from app.access.store import private
from app.access.research_store import ResearchStore
from app.access.research_service import ResearchService

ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/assets/app.js': ('app.js', 'text/javascript; charset=utf-8'),
          '/assets/styles.css': ('styles.css', 'text/css; charset=utf-8')}

def configured(config_file, *, create=False):
    file = private(config_file); config = json.loads(file.read_text())
    require(type(config) is dict and set(config) == {'policy','access_config','state_directory','key_file','presentation_keys'}, 'Workspace config fields differ')
    require(config['policy'] == 'RESEARCH_WEB_CONFIG_V1', 'Workspace config policy differs')
    access, origin = configured_store(config['access_config'])
    private(file, repo=access.repo)
    keys = {k: base64.b64decode(v, validate=True) for k,v in config['presentation_keys'].items()}
    return ResearchStore(config['state_directory'], config['key_file'], keys, access=access, create=create), origin

def create_app(store, *, origin, assets=None):
    require(type(store) is ResearchStore, 'Exact configured workspace store required')
    service = ResearchService(store)
    assets = Path(assets) if assets else Path(__file__).resolve().parents[3] / 'frontend' / 'research'
    # Load only fixed committed UI files; no path supplied through requests.
    files = {url: (assets.joinpath(file).read_bytes(), media) for url,(file,media) in ASSETS.items()}
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @api.exception_handler(AccessError)
    async def denied(request, exc): return JSONResponse({'error':exc.code}, status_code=exc.status)
    @api.exception_handler(Exception)
    async def unavailable(request, exc): return JSONResponse({'error':'RESEARCH_SERVICE_UNAVAILABLE'}, status_code=503)

    def token(request):
        if sum(c.strip().startswith(COOKIE+'=') for c in request.headers.get('cookie','').split(';')) > 1:
            raise AccessError(401, 'LOGIN_REQUIRED')
        return request.cookies.get(COOKIE)

    async def body(request, fields):
        try:
            value = json.loads(await request.body(), object_pairs_hook=_json_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            require(type(value) is dict and set(value) == fields)
            return value
        except Exception: raise AccessError(400, 'INVALID_REQUEST') from None

    @api.get('/api/research/officers/{officer_uid}')
    async def workspace(officer_uid:str, request:Request):
        return await run_in_threadpool(service.workspace, token(request), officer_uid)

    @api.get('/api/research/officers/{officer_uid}/requests')
    async def recent_requests(officer_uid:str, request:Request):
        return await run_in_threadpool(service.recent_requests, token(request), officer_uid)

    @api.post('/api/research/history')
    async def history(request:Request):
        b = await body(request, {'officer_uid','effective_on','known_at'})
        return await run_in_threadpool(service.history, token(request), request.headers.get('x-csrf-token',''),
            b['officer_uid'], b['effective_on'], b['known_at'])

    @api.post('/api/research/requests')
    async def review(request:Request):
        b = await body(request, {'officer_uid','operation_id','finding_id','target_head_sha256','generation','kind','decision','reason','evidence_references'})
        return await run_in_threadpool(service.request_review, token(request), request.headers.get('x-csrf-token',''), b)

    @api.get('/api/research/requests/{operation_id}')
    async def status(operation_id:str, request:Request):
        return await run_in_threadpool(service.request_status, token(request), operation_id)

    research = RequestBoundary(api, origin); identity = identity_app(store.access, origin=origin)
    async def static(scope, receive, send):
        if scope['method'] != 'GET': return await JSONResponse({'error':'NOT_FOUND'}, status_code=404)(scope, receive, send)
        data, media = files[scope['path']]
        await Response(data, headers={'content-type':media})(scope, receive, send)
    static_boundary = RequestBoundary(static, origin)
    async def application(scope, receive, send):
        if scope['type'] != 'http': return await identity(scope, receive, send)
        if scope['path'] in files:
            async def static_send(event):
                if event['type'] == 'http.response.start':
                    event = dict(event); event['headers'] = [(k,v) for k,v in event['headers'] if k.lower() != b'content-security-policy']
                    event['headers'].append((b'content-security-policy', b"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"))
                    event['headers'].append((b'permissions-policy', b'camera=(), microphone=(), geolocation=()'))
                await send(event)
            return await static_boundary(scope, receive, static_send)
        if scope['path'].startswith('/api/research/'): return await research(scope, receive, send)
        return await identity(scope, receive, send)
    return application

def application():
    require(os.environ.get('PPI_RESEARCH_CONFIG'), 'Private PPI_RESEARCH_CONFIG required')
    store, origin = configured(os.environ['PPI_RESEARCH_CONFIG'])
    return create_app(store, origin=origin)
