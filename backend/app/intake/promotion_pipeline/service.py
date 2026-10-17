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
        self.approvals=getattr(research,'promotion_acceptance',None)

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
        answer = {'batch_id':batch['batch_id'],'filename':batch['filename'],'received_at':batch['received_at'],
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
        analysis=getattr(self.research,'promotion_analysis',None)
        if analysis is not None:
            activation=analysis.journal.get(batch['batch_id'])
            answer['analysis_status']='CONNECTED_TO_ANALYSIS' if activation else 'WAITING_FOR_VERIFIED_AVAILABILITY'
            answer['analysis_recorded_at']=activation['available_at'] if activation else None
        if self.approvals is not None:
            decision=self.approvals.approval(batch)
            answer['processing_approval_reference']=digest(decision) if decision else None
            answer['processing_approval']=decision
            answer['processing_approval_version']=decision['version'] if decision else 0
            answer['legacy_processing']=batch['batch_id'] in self.approvals.config['legacy_queued']
            if decision and decision['kind']!='APPROVE':answer['status']={'SUBMIT':'AWAITING_IGP_APPROVAL','REJECT':'REJECTED','REQUEST_CHANGES':'CHANGES_REQUESTED'}[decision['kind']]
            heads=[self.approvals.journal.head('ROW:'+batch['batch_id']+':'+str(r['row'])) for r in batch['rows'] if r['status']=='READY']
            current={}
            for head in heads:
                if head is not None and head['result']['officer_uid'] not in current:
                    current[head['result']['officer_uid']]={r['raw_record_id']:r for r in self.approvals.evaluate_officer(head['result']['officer_uid'])}
            answer['promotion_acceptance']=[]
            for head in heads:
                if head is None:continue
                latest=current[head['result']['officer_uid']].get(head['result']['raw_record_id'])
                head['decision_reference']=digest(head)
                review=self.approvals.journal.head('REVIEW:'+batch['batch_id']+':'+str(head['result']['source_row']))
                head['row_review']=None if review is None else {k:review[k] for k in ('kind','version','recorded_at','reason','evidence_reference','actor')}
                head['row_review_version']=review['version'] if review else 0
                head['row_review_blocked']=sorted(set(head['result']['reasons'])&self.approvals.BLOCKING)
                head['current_evidence_matches']=latest is not None and head['result']=={k:v for k,v in latest.items() if k!='effective_now'}
                head['effective_now']=bool(latest and latest['effective_now'])
                answer['promotion_acceptance'].append(head)
            answer['accepted_current_rank_changed']=any(h['current_evidence_matches'] and h['effective_now'] and h['result']['status']=='ACCEPTED' for h in answer['promotion_acceptance'])
        return answer

    def decide(self,token,csrf,request):
        user=self.actor(token,csrf)
        if self.approvals is None:raise AccessError(503,'IGP_APPROVAL_NOT_CONFIGURED')
        if not self.approvals.reviewer(user):raise AccessError(403,'IGP_APPROVAL_FORBIDDEN')
        batch=self.store.get(request['batch_id'])
        self.source_state()
        for officer in sorted({r['officer_uid'] for r in batch['rows'] if r['status']=='READY'}):self.research.authorized(token,officer,csrf=csrf,charge=False)
        check(self.actor(token,csrf)==user,'ACCOUNT_CHANGED')
        decision=self.approvals.decide(batch,user,request)
        self.approvals.audit_outbox()
        if decision['kind']=='APPROVE':self.approvals.queue(batch)
        return self.summary(batch)

    def review(self,token,csrf,request):
        """Independent IGP row review of a pending acceptance; the uploader can never review."""
        user=self.actor(token,csrf)
        if self.approvals is None:raise AccessError(503,'IGP_APPROVAL_NOT_CONFIGURED')
        if not self.approvals.reviewer(user):raise AccessError(403,'IGP_APPROVAL_FORBIDDEN')
        batch=self.store.get(request['batch_id'])
        self.source_state()
        for officer in sorted({r['officer_uid'] for r in batch['rows'] if r['status']=='READY'}):self.research.authorized(token,officer,csrf=csrf,charge=False)
        check(self.actor(token,csrf)==user,'ACCOUNT_CHANGED')
        self.approvals.review_row(batch,user,request)
        self.approvals.synchronize()
        self.approvals.audit_outbox()
        return self.summary(batch)

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
        if self.approvals is not None:
            self.approvals.request(batch,user)
            self.approvals.audit_outbox()
            return self.summary(batch)
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

    def approval_count(self,token):
        user=self.actor(token)
        if self.approvals is None or not self.approvals.reviewer(user):return 0
        self.approvals.guard()
        count=sum((self.approvals.approval(b) or {}).get('kind')=='SUBMIT' for b in self.store.batches(limit=1000))
        check(self.actor(token)==user,'ACCOUNT_CHANGED');return count

    def listing(self,token,offset=0):
        user=self.actor(token)
        check(type(offset) is int and 0<=offset<=1000,'BATCH_PAGE_INVALID')
        batches=self.store.batches(limit=1000)
        if self.approvals is not None and self.approvals.reviewer(user):
            batches.sort(key=lambda b:0 if (self.approvals.approval(b) or {}).get('kind')=='SUBMIT' else 1)
        rows=[self.summary(b) for b in batches[offset:offset+20]]
        check(self.actor(token)==user,'ACCOUNT_CHANGED')
        return {'items':rows,'offset':offset,'total':len(batches),'next_offset':offset+len(rows) if offset+len(rows)<len(batches) else None}

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
        answer={'items':result,'authority':'NOT_ASSESSED','accepted_current_rank_changed':False}
        analysis=getattr(self.research,'promotion_analysis',None)
        if analysis is not None:
            reports=self.research.promotion_reports(officer)
            answer['analysis']=analysis.summary(reports)
            recorded={r['raw_record_id']:r['analysis_recorded_at'] for r in reports}
            for item in result:item['analysis_recorded_at']=recorded.get(item['raw_record_id'])
        if self.approvals is not None:
            answer['current_assignment']=self.approvals.current(officer)
            answer['accepted_current_rank_changed']=answer['current_assignment']['accepted_promotion'] is not None
        self.research.authorized(token,officer,charge=False)
        return answer
