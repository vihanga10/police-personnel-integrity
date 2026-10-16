"""Current-session authorization and bounded promotion upload interface."""
import base64
from datetime import datetime, timezone
from uuid import UUID
from app.access.policy import AccessError
from app.access import full_source_profiles as F
from .store import PHASES
from .core import IntakeError, check, parse, validate_rows, digest, opaque, MAX_BYTES, COLUMNS

class PromotionService:
    def __init__(self, research, store, config):
        self.research, self.workspace, self.access = research, research.store, research.access
        self.store, self.config = store, config

    def actor(self, token, csrf=None, *, upload=False):
        with self.access.transaction() as c:
            user, session = self.access._session(c,token,csrf)
            may_upload=(user['role']=='HQ_ADMIN' and user['scope_type']=='ALL' and user['user_id'] in self.config['importer_ids'])
            if upload and not may_upload:raise AccessError(403,'PROMOTION_IMPORT_FORBIDDEN')
            if not upload and not (may_upload or user['role']=='IGP' and user['scope_type']=='ALL'):
                raise AccessError(403,'PROMOTION_IMPORT_INSPECTION_FORBIDDEN')
            return user

    def audit(self,token,action,batch,operation_id):
        logs=getattr(self.workspace,'accountability',None)
        if logs is None:return  # direct isolated service fixtures only; Runtime requires logs
        from app.access.accountability import ACTIONS
        ACTIONS.add(action)
        actor=logs.actor(token)
        if not actor.get('authenticated'):raise AccessError(401,'LOGIN_REQUIRED')
        logs.append({'action':action,'phase':'ADMINISTRATION','method':'POST','status':None,'outcome':'ALLOWED',
            'actor':actor,'request_id':None,'operation_id':operation_id,'finding_id':None,'requested_officer_uid':None,
            'session_reference':logs.session_reference(token),'peer_reference':None,'reason':None,
            'promotion_batch_id':batch['batch_id'],'file_sha256':batch['file_sha256'],
            'row_count':len(batch['rows']),'basis':'AUTHENTICATED_RETAINED_INTAKE_OPERATION'})

    def source_state(self):
        with self.access.transaction() as c: directory=self.access._directory(c)
        self.store.verify_baseline(self.config['baseline_source_set_sha256'])
        metadata=F.active_set(self.workspace)
        check(metadata is not None and digest(metadata)==self.config['baseline_source_set_sha256'] and
              directory['source_public_sha256']==metadata['source_public_sha256'], 'BASELINE_SOURCE_CHANGED')
        return directory

    def preview(self, token, csrf, request):
        user=self.actor(token,csrf,upload=True)
        check(set(request)=={'operation_id','filename','source_reference','csv_base64'}, 'UPLOAD_FIELDS_DIFFER')
        try: valid_id=type(request['operation_id']) is str and str(UUID(request['operation_id']))==request['operation_id']
        except (ValueError,AttributeError,TypeError): valid_id=False
        check(valid_id, 'OPERATION_ID_INVALID')
        check(type(request['filename']) is str and 1<=len(request['filename'])<=100 and
            request['filename'].endswith('.csv') and '/' not in request['filename'] and '\\' not in request['filename'] and
            not any(ord(c)<32 for c in request['filename']), 'CSV_FILENAME_INVALID')
        reference=request['source_reference']
        check(type(reference) is str and 3<=len(reference.strip())<=200 and not any(ord(c)<32 for c in reference), 'SOURCE_REFERENCE_REQUIRED')
        check(type(request['csv_base64']) is str and len(request['csv_base64'])<=4*((MAX_BYTES+2)//3), 'CSV_SIZE_LIMIT')
        try: data=base64.b64decode(request['csv_base64'],validate=True)
        except Exception: raise IntakeError('CSV_ENCODING_INVALID') from None
        rows=parse(data)
        directory=self.source_state()
        by_nic={}
        for officer in directory['officers']:
            by_nic.setdefault(officer['nic'],[]).append(officer['officer_uid'])
        now=datetime.fromtimestamp(self.workspace.clock(),timezone.utc)
        results=validate_rows(rows,lambda nic:by_nic.get(nic,[]),self.store.duplicate,now=now)
        # Recheck authorization and source binding immediately before retention.
        check(self.actor(token,csrf,upload=True)==user,'ACCOUNT_CHANGED')
        check(self.source_state()==directory,'DIRECTORY_CHANGED')
        batch=self.store.create(data,{'actor':{'user_id':user['user_id'],'username':user['username'],
            'account_version':user['version']},'received_at':now.isoformat(), 'source_reference':reference,
            'filename':request['filename'],'baseline_source_set_sha256':self.config['baseline_source_set_sha256'],
            'rows':results}, request['operation_id'])
        self.actor(token,csrf,upload=True)
        self.audit(token,'PROMOTION_PREVIEW_RETAINED',batch,request['operation_id'])
        return self.summary(batch)

    def summary(self,batch):
        phases=[p for p in PHASES if self.store.phase(batch['batch_id'],p) is not None]
        status='NEEDS_REVIEW' if any(r['status']=='NEEDS_REVIEW' for r in batch['rows']) else 'DUPLICATES_ONLY' if all(r['status']=='DUPLICATE' for r in batch['rows']) else phases[-1] if phases else 'PREVIEW_READY'
        receipt=self.store.phase(batch['batch_id'],'CHAINS_VERIFIED')
        return {'batch_id':batch['batch_id'],'filename':batch['filename'],'received_at':batch['received_at'],
            'source_reference':batch['source_reference'],'status':status,'file_sha256':batch['file_sha256'],
            'ready_rows':sum(r['status']=='READY' for r in batch['rows']),
            'duplicate_rows':sum(r['status']=='DUPLICATE' for r in batch['rows']),
            'review_rows':sum(r['status']=='NEEDS_REVIEW' for r in batch['rows']),
            'rows':[{'row':r['row'],'status':r['status'],'issues':r['issues'],
                'officer_uid':r['officer_uid'],'nic':r['source']['officer_nic_no'],
                'promotion_id':r['source']['promotion_id'],'fields':r['source']} for r in batch['rows']],
            'publication':None if receipt is None else {
                'status':'BOTH_CHAINS_VERIFIED','publication_id':receipt['fabric']['payload']['publication_id'],'merkle_root':receipt['fabric']['payload']['merkle_root'],
                'observed_at':receipt['verification_observed_at'],'fabric_chaincode':receipt['fabric']['destination']['chaincode'],
                'public_contract':receipt['public']['destination']['contract'],'fabric_transaction_id':receipt['fabric']['transaction_id'],
                'public_transaction_id':receipt['public']['transaction_id'],
                'receipt_basis':'RETAINED_VERIFICATION_OBSERVATION'},
            'authority':'NOT_ASSESSED','accepted_current_rank_changed':False,'processing_observation':self.store.worker_status(batch['batch_id'])}

    def commit(self,token,csrf,request):
        user=self.actor(token,csrf,upload=True)
        check(set(request)=={'batch_id','file_sha256'},'COMMIT_FIELDS_DIFFER')
        batch=self.store.get(request['batch_id'])
        check(batch['actor']['user_id']==user['user_id'] and batch['actor']['account_version']==user['version'], 'UPLOADER_ACCOUNT_CHANGED')
        check(batch['file_sha256']==request['file_sha256'],'PREVIEW_FILE_CHANGED')
        self.source_state()
        # Scoped full-detail grants remain mandatory for every affected officer.
        for officer in sorted({r['officer_uid'] for r in batch['rows'] if r['status']=='READY'}):
            self.research.authorized(token,officer,csrf=csrf,charge=False)
        self.actor(token,csrf,upload=True)
        self.audit(token,'PROMOTION_IMPORT_CONFIRMATION_RECEIVED',batch,batch['batch_id'])
        self.store.queue(batch['batch_id'],{'actor':batch['actor'],'file_sha256':batch['file_sha256'],
            'baseline_source_set_sha256':batch['baseline_source_set_sha256']})
        return self.summary(batch)

    def resume(self,token,csrf,request):
        user=self.actor(token,csrf,upload=True)
        check(set(request)=={'batch_id','file_sha256'},'RESUME_FIELDS_DIFFER')
        batch=self.store.get(request['batch_id'])
        check(batch['actor']['user_id']==user['user_id'] and batch['file_sha256']==request['file_sha256'],'UPLOADER_IDENTITY_DIFFERS')
        self.source_state()
        for officer in sorted({r['officer_uid'] for r in batch['rows'] if r['status']=='READY'}):self.research.authorized(token,officer,csrf=csrf,charge=False)
        check(self.actor(token,csrf,upload=True)==user,'ACCOUNT_CHANGED')
        self.audit(token,'PROMOTION_IMPORT_REAUTHORIZATION_RECEIVED',batch,batch['batch_id'])
        self.store.renew_authorization(batch['batch_id'],{'user_id':user['user_id'],'username':user['username'],'account_version':user['version']})
        return self.summary(batch)

    def listing(self,token):
        self.actor(token)
        rows=[self.summary(b) for b in self.store.batches()[:20]]
        self.actor(token)
        return {'items':rows}

    def officer_rows(self,token,officer):
        self.research.authorized(token,officer,charge=False)
        result=[]
        for batch in self.store.officer_batches(officer):
            visible=self.store.phase(batch['batch_id'],'VISIBLE')
            if visible is None:continue
            for row in batch['rows']:
                if row['status']=='READY' and row['officer_uid']==officer:
                    result.append({'batch_id':batch['batch_id'],'raw_record_id':opaque(self.store.key,'SOURCE_ID',row['source']['promotion_id'].strip()),
                        'dataset':'promotion_history.csv','fields':row['source'],
                        'received_at':batch['received_at'],'publication':self.summary(batch)['publication']})
        self.research.authorized(token,officer,charge=False)
        return {'items':result,'authority':'NOT_ASSESSED','accepted_current_rank_changed':False}
