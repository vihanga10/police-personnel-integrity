"""Optional dataset intake routes using the existing session, CSRF and audit boundary."""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from app.access.policy import AccessError
from .core import IntakeError

BASE = '/api/research/intake/'
ROUTES = ('capabilities', 'preview', 'commit', 'decide', 'review', 'resume')


def register(api, runtime, token, body):
    from app.access.accountability import ACTION_PATHS, ACTIONS
    additions = {BASE + name: 'DATASET_IMPORT_' + name.upper() for name in ROUTES}
    ACTION_PATHS.update(additions)
    ACTIONS.update(additions.values())
    ACTIONS.update({'DATASET_PREVIEW_RETAINED', 'DATASET_IMPORT_REAUTHORIZATION_RECEIVED', 'DATASET_PIPELINE_WORKER',
                    'PERSONNEL_INTAKE_DECISION_RETAINED',
                    'DATASET_IMPORT_BATCHES', 'DATASET_OFFICER_UPLOADS_READ'})

    @api.exception_handler(IntakeError)
    async def invalid(request, exc):
        return JSONResponse({'error': exc.code}, status_code=422)

    def required():
        if runtime is None:
            raise AccessError(503, 'DATASET_INTAKE_NOT_CONFIGURED')
        runtime.check_pins()
        return runtime.service

    @api.get(BASE + 'capabilities')
    async def capabilities(request: Request):
        if runtime is None:
            return {'configured': False, 'can_upload': False, 'can_inspect': False, 'datasets': []}
        return await run_in_threadpool(required().capabilities, token(request))

    @api.post(BASE + 'preview')
    async def preview(request: Request):
        service = required()
        value = await body(request, {'operation_id', 'dataset', 'filename', 'source_reference', 'source_system', 'csv_base64'})
        return await run_in_threadpool(service.preview, token(request), request.headers.get('x-csrf-token', ''), value)

    @api.post(BASE + 'commit')
    async def commit(request: Request):
        service = required()
        value = await body(request, {'batch_id', 'file_sha256'})
        return await run_in_threadpool(service.commit, token(request), request.headers.get('x-csrf-token', ''), value)

    @api.post(BASE + 'decide')
    async def decide(request: Request):
        service = required()
        value = await body(request, {'batch_id', 'file_sha256', 'operation_id', 'expected_version', 'decision', 'reason'})
        return await run_in_threadpool(service.decide, token(request), request.headers.get('x-csrf-token', ''), value)

    @api.post(BASE + 'review')
    async def review(request: Request):
        service = required()
        value = await body(request, {'batch_id', 'row', 'operation_id', 'expected_version', 'decision', 'reason',
                                     'evidence_reference', 'evaluation_reference'})
        return await run_in_threadpool(service.review, token(request), request.headers.get('x-csrf-token', ''), value)

    @api.post(BASE + 'resume')
    async def resume(request: Request):
        service = required()
        value = await body(request, {'batch_id', 'file_sha256'})
        return await run_in_threadpool(service.resume, token(request), request.headers.get('x-csrf-token', ''), value)

    # The request boundary forbids query strings, so paging lives in the path.
    @api.get(BASE + 'datasets/{code}/batches/{offset}')
    async def batches(code: str, offset: str, request: Request):
        if not offset.isdigit() or len(offset) > 4:
            raise AccessError(400, 'INVALID_BATCH_PAGE')
        offset = int(offset)
        from .registry import CODES
        if code not in CODES:
            raise AccessError(404, 'NOT_FOUND')
        result = await run_in_threadpool(required().listing, token(request), offset, code)
        for item in result['items']:
            item['processing_issue'] = runtime.errors.get(item['batch_id'])
        return result

    @api.get(BASE + 'officers/{officer}')
    async def officer_rows(officer: str, request: Request):
        return await run_in_threadpool(required().officer_rows, token(request), officer)
