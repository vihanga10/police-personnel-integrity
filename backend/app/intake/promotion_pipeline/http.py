"""Optional promotion routes using the existing session and CSRF boundary."""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from app.access.policy import AccessError
from .core import IntakeError, COLUMNS, MAX_BYTES, MAX_ROWS

def register(api,runtime,token,body):
    # Extend request classification without changing the separately pinned
    # accountability anchoring implementation or its retained jobs.
    from app.access.accountability import ACTION_PATHS,ACTIONS
    additions={'/api/research/promotions/'+name:'PROMOTION_'+name.upper() for name in ('capabilities','preview','commit','decide','review','resume','batches')}
    ACTION_PATHS.update(additions);ACTIONS.update(additions.values())
    @api.exception_handler(IntakeError)
    async def invalid(request,exc):
        return JSONResponse({'error':exc.code},status_code=422)

    @api.get('/api/research/promotions/capabilities')
    async def capabilities(request:Request):
        if runtime is None:return {'configured':False,'can_upload':False,'can_inspect':False}
        await run_in_threadpool(runtime.service.actor,token(request))
        try:
            await run_in_threadpool(runtime.service.actor,token(request),upload=True)
            upload=True
        except AccessError:upload=False
        current=await run_in_threadpool(runtime.service.actor,token(request))
        return {'configured':True,'can_upload':upload,'can_inspect':True,
            'approver_account_version':current['version'] if runtime.service.approvals is not None and runtime.service.approvals.reviewer(current) else None,
            'pending_approval_count':await run_in_threadpool(runtime.service.approval_count,token(request)),
            'requires_igp_approval':runtime.service.approvals is not None,
            'can_approve':runtime.service.approvals is not None and runtime.service.approvals.reviewer(await run_in_threadpool(runtime.service.actor,token(request))),
            'columns':list(COLUMNS),'maximum_bytes':MAX_BYTES,'maximum_rows':MAX_ROWS}

    def required():
        if runtime is None:raise AccessError(503,'PROMOTION_INTAKE_NOT_CONFIGURED')
        runtime.check_pins()
        return runtime.service

    @api.post('/api/research/promotions/preview')
    async def preview(request:Request):
        service=required()
        value=await body(request,{'operation_id','filename','source_reference','csv_base64'})
        return await run_in_threadpool(service.preview,token(request),request.headers.get('x-csrf-token',''),value)

    @api.post('/api/research/promotions/commit')
    async def commit(request:Request):
        service=required()
        value=await body(request,{'batch_id','file_sha256'})
        return await run_in_threadpool(service.commit,token(request),request.headers.get('x-csrf-token',''),value)

    @api.post('/api/research/promotions/decide')
    async def decide(request:Request):
        service=required()
        value=await body(request,{'batch_id','file_sha256','operation_id','expected_version','decision','reason'})
        return await run_in_threadpool(service.decide,token(request),request.headers.get('x-csrf-token',''),value)

    @api.post('/api/research/promotions/review')
    async def review(request:Request):
        service=required()
        value=await body(request,{'batch_id','row','operation_id','expected_version','decision','reason','evidence_reference','evaluation_reference'})
        return await run_in_threadpool(service.review,token(request),request.headers.get('x-csrf-token',''),value)

    @api.post('/api/research/promotions/resume')
    async def resume(request:Request):
        service=required()
        value=await body(request,{'batch_id','file_sha256'})
        return await run_in_threadpool(service.resume,token(request),request.headers.get('x-csrf-token',''),value)

    @api.get('/api/research/promotions/batches')
    async def batches(request:Request):
        try:offset=int(request.query_params.get('offset','0'))
        except ValueError:raise AccessError(400,'INVALID_BATCH_PAGE') from None
        result=await run_in_threadpool(required().listing,token(request),offset)
        for item in result['items']:item['processing_issue']=runtime.errors.get(item['batch_id'])
        return result

    @api.get('/api/research/promotions/officers/{officer}')
    async def officer_promotions(officer:str,request:Request):
        return await run_in_threadpool(required().officer_rows,token(request),officer)
