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
LOG_ASSETS = {'/accountability': ('accountability.html', 'text/html; charset=utf-8'),
              '/assets/accountability.js': ('accountability.js', 'text/javascript; charset=utf-8'),
              '/assets/accountability.css': ('accountability.css', 'text/css; charset=utf-8')}

def configured(config_file, *, create=False):
    file = private(config_file); config = json.loads(file.read_text())
    fields = {'policy','access_config','state_directory','key_file','presentation_keys'}
    require(type(config) is dict and fields<=set(config)<=fields|{'accountability_config','workflow_assessment_keys','review_workflow_keys'}, 'Workspace config fields differ')
    require(config['policy'] == 'RESEARCH_WEB_CONFIG_V1', 'Workspace config policy differs')
    access, origin = configured_store(config['access_config'])
    private(file, repo=access.repo)
    keys = {k: base64.b64decode(v, validate=True) for k,v in config['presentation_keys'].items()}
    store = ResearchStore(config['state_directory'], config['key_file'], keys, access=access, create=create)
    from app.access.research_connection_runtime import public_keys
    store.workflow_keys=public_keys(config['workflow_assessment_keys']) if 'workflow_assessment_keys' in config else {}
    require(len(store.workflow_keys)<=16,'Bounded workflow assessor trust required')
    require(not (set(store.workflow_keys.values()) & (set(keys.values())|set(access.keys.values()))), 'Separate workflow assessor key required')
    store.review_keys=public_keys(config['review_workflow_keys']) if 'review_workflow_keys' in config else {}
    require(len(store.review_keys)<=16 and not set(store.review_keys.values()) & (set(keys.values())|set(access.keys.values())|set(store.workflow_keys.values())), 'Separate review policy key required')
    store.accountability = None
    if 'accountability_config' in config:
        from app.access.accountability import configured as configured_accountability
        store.accountability = configured_accountability(config['accountability_config'], access=access,
                                                        workspace_key=config['key_file'], workspace_root=store.root)
    if store.review_keys:
        require(store.accountability is not None,'Review accountability required')
        from app.access.review_workflow import initialize
        initialize(store)
    return store, origin

def create_app(store, *, origin, assets=None):
    require(type(store) is ResearchStore, 'Exact configured workspace store required')
    service = ResearchService(store)
    from app.access.workflow_service import WorkflowService
    workflows=WorkflowService(service)
    from app.access.review_workflow import ReviewWorkflow
    reviews=ReviewWorkflow(service)
    assets = Path(assets) if assets else Path(__file__).resolve().parents[3] / 'frontend' / 'research'
    # Load only fixed committed UI files; no path supplied through requests.
    files = {url: (assets.joinpath(file).read_bytes(), media) for url,(file,media) in ASSETS.items()}
    accountability = getattr(store, 'accountability', None)
    if accountability is not None:
        files.update({url: (assets.joinpath(file).read_bytes(), media) for url,(file,media) in LOG_ASSETS.items()})
    for url,file,media in [('/reviews','reviews.html','text/html; charset=utf-8'),('/assets/reviews.js','reviews.js','text/javascript; charset=utf-8'),('/assets/reviews.css','reviews.css','text/css; charset=utf-8')]:files[url]=(assets.joinpath(file).read_bytes(),media)
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

    if accountability is not None:
        @api.get('/api/accountability/capabilities')
        async def log_capabilities(request:Request):
            await run_in_threadpool(accountability.reader, token(request))
            return {'can_read_access_logs':True, 'independently_anchored':False}

        @api.post('/api/accountability/session-signal')
        async def session_signal(request:Request):
            value=await body(request, {'event','page','persisted'})
            return await run_in_threadpool(accountability.session_signal,token(request),
                request.headers.get('x-csrf-token',''),value)

        @api.post('/api/accountability/logs')
        async def access_logs(request:Request):
            value=await body(request, {'limit','before_sequence','action','outcome'})
            return await run_in_threadpool(accountability.read, token(request),
                request.headers.get('x-csrf-token',''), value)

        @api.post('/api/accountability/legacy')
        async def legacy_logs(request:Request):
            value=await body(request, {'limit','before_sequence','action','outcome'})
            return await run_in_threadpool(accountability.read, token(request),
                request.headers.get('x-csrf-token',''), value, True)

    @api.get('/api/research/available')
    async def available(request:Request):
        return await run_in_threadpool(service.available, token(request))

    @api.post('/api/research/browse')
    async def browse(request:Request):
        value = await body(request, {'kind','query','availability','level','scope_id','limit','offset'})
        return await run_in_threadpool(service.browse, token(request),
            request.headers.get('x-csrf-token',''), value)

    @api.get('/api/research/officers/{officer_uid}')
    async def workspace(officer_uid:str, request:Request):
        return await run_in_threadpool(service.workspace, token(request), officer_uid)

    @api.get('/api/research/officers/{officer_uid}/requests')
    async def recent_requests(officer_uid:str, request:Request):
        return await run_in_threadpool(service.recent_requests, token(request), officer_uid)

    @api.get('/api/research/officers/{officer_uid}/application-anchoring')
    async def application_anchoring(officer_uid:str,request:Request):
        from app.access.application_anchor_observations import status
        return await run_in_threadpool(status,service,token(request),officer_uid)

    @api.post('/api/research/history')
    async def history(request:Request):
        b = await body(request, {'officer_uid','effective_on','known_at'})
        return await run_in_threadpool(service.history, token(request), request.headers.get('x-csrf-token',''),
            b['officer_uid'], b['effective_on'], b['known_at'])

    @api.post('/api/research/authority')
    async def authority(request:Request):
        b=await body(request,{'officer_uid','known_at','action_on','status','limit','offset'})
        return await run_in_threadpool(workflows.authority,token(request),request.headers.get('x-csrf-token',''),b)

    @api.post('/api/research/contradictions')
    async def contradictions(request:Request):
        b=await body(request,{'officer_uid','effective_on','known_at','dimension','status','relationship','limit','offset'})
        return await run_in_threadpool(workflows.contradictions,token(request),request.headers.get('x-csrf-token',''),b)

    @api.post('/api/research/requests')
    async def review(request:Request):
        b = await body(request, {'officer_uid','operation_id','finding_id','target_head_sha256','generation','kind','decision','reason','evidence_references'})
        return await run_in_threadpool(service.request_review, token(request), request.headers.get('x-csrf-token',''), b)

    @api.get('/api/research/requests/{operation_id}')
    async def status(operation_id:str, request:Request):
        return await run_in_threadpool(service.request_status, token(request), operation_id)

    @api.get('/api/research/reviews/capabilities')
    async def review_capabilities(request:Request):
        return await run_in_threadpool(reviews.capabilities,token(request))

    @api.post('/api/research/reviews/{kind}')
    async def review_operation(kind:str,request:Request):
        fields={'save':{'officer_uid','operation_id','finding_id','effective_on','known_at','reason'},'request':{'officer_uid','operation_id','finding_id','target_head','request_kind','effective_on','known_at','reason','prior_request'},'decide':{'officer_uid','operation_id','request_reference','decision','reason'},'inspect':{'officer_uid','status','offset'}}
        if kind not in fields:raise AccessError(404,'NOT_FOUND')
        b=await body(request,fields[kind]);csrf=request.headers.get('x-csrf-token','')
        if kind=='inspect':return await run_in_threadpool(reviews.inspect,token(request),csrf,b)
        return await run_in_threadpool(reviews.mutate,token(request),csrf,kind.upper(),b)

    @api.get('/api/research/reviews/operations/{operation}')
    async def recover_review(operation:str,request:Request):
        return await run_in_threadpool(reviews.recover,token(request),operation)

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
        if scope['path'].startswith(('/api/research/', '/api/accountability/')): return await research(scope, receive, send)
        return await identity(scope, receive, send)
    if accountability is not None:
        from app.access.accountability import AccountabilityBoundary
        return AccountabilityBoundary(application, accountability)
    return application

def application():
    require(os.environ.get('PPI_RESEARCH_CONFIG'), 'Private PPI_RESEARCH_CONFIG required')
    store, origin = configured(os.environ['PPI_RESEARCH_CONFIG'])
    return create_app(store, origin=origin)
