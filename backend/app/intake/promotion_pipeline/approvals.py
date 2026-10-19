"""Independent intake approval and append-only, evidence-bound rank acceptance.

No rules, assessor signatures or police powers are created by this module.
Only an explicitly configured current IGP reviewer can authorize processing.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import date,datetime,timezone
import hmac,json,os,sqlite3
from pathlib import Path
from uuid import UUID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.store import private
from app.access.policy import AccessError,account
from app.access import research_policy as P,operational_authority as A,authority_case_store as S
from app.identity.service_values import RANKS
from .core import canonical,check,digest
from .analysis import verified_batch

POLICY='PROMOTION_INDEPENDENT_APPROVAL_V1'
ORDER=('IGP','SDIG','DIG','SSP','SP','ASP','CIP','IP','SI','PS_C1','PS_C2','PC_C1','PC_C2','PC_C3','PC_C4','PC')

def stamp(workspace):return datetime.fromtimestamp(workspace.clock(),timezone.utc).isoformat()
def actor(user):return {k:user[k] for k in ('user_id','username','role','scope_type','scope_id','version')}
def batch_binding(batch):return digest({k:batch[k] for k in ('batch_id','file_sha256','rows','actor','received_at','source_reference','baseline_source_set_sha256')})

class DecisionJournal:
    def __init__(self,root,key,*,repo,create=False):
        self.root=private(root,directory=True,repo=repo);self.path=self.root/'decisions.sqlite3'
        self.aead=AESGCM(hmac.digest(key,POLICY.encode(),'sha256'));self.repo=repo
        if create and not self.path.exists():
            with self.path.open('xb') as f:os.fchmod(f.fileno(),0o600)
            with self.transaction() as c:
                c.executescript('''CREATE TABLE events(seq INTEGER PRIMARY KEY,subject TEXT NOT NULL,version INTEGER NOT NULL,operation TEXT UNIQUE NOT NULL,value BLOB NOT NULL,UNIQUE(subject,version));
                CREATE TABLE audit_ack(seq INTEGER PRIMARY KEY REFERENCES events(seq),log_sequence INTEGER NOT NULL);
                PRAGMA user_version=1;''')
                for table in ('events','audit_ack'):
                    for op in ('UPDATE','DELETE'):
                        c.execute(f"CREATE TRIGGER no_{table}_{op} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable promotion decision'); END")
        private(self.path,repo=repo)
        with self.transaction() as c:check(c.execute('PRAGMA user_version').fetchone()[0]==1,'DECISION_SCHEMA_DIFFERS')
    @contextmanager
    def transaction(self):
        private(self.root,directory=True,repo=self.repo);private(self.path,repo=self.repo)
        with sqlite3.connect(self.path,timeout=10) as c:
            c.execute('PRAGMA synchronous=FULL');c.execute('PRAGMA foreign_keys=ON');c.execute('BEGIN IMMEDIATE');yield c
    def open(self,subject,version,blob):
        p=json.loads(self.aead.decrypt(blob[:12],blob[12:],canonical([POLICY,subject,version])))
        check(p['subject']==subject and p['version']==version and p['policy']==POLICY,'DECISION_BINDING_DIFFERS');return p
    def rows(self,subject):
        with self.transaction() as c:rows=c.execute('SELECT version,value FROM events WHERE subject=? ORDER BY version',(subject,)).fetchall()
        values=[self.open(subject,v,b) for v,b in rows]
        for n,v in enumerate(values,1):
            check(v['version']==n and v['supersedes']==(digest(values[n-2]) if n>1 else None),'DECISION_LINEAGE_DIFFERS')
        return values
    def head(self,subject):
        rows=self.rows(subject);return rows[-1] if rows else None
    def append(self,subject,operation,expected,value):
        fingerprint=digest(value)
        with self.transaction() as c:
            row=c.execute('SELECT subject,version,value FROM events WHERE operation=?',(operation,)).fetchone()
            if row:
                retained=self.open(*row);check(row[0]==subject and retained['intent']==fingerprint,'DECISION_OPERATION_CONFLICT');return retained
            row=c.execute('SELECT version,value FROM events WHERE subject=? ORDER BY version DESC LIMIT 1',(subject,)).fetchone()
            previous=self.open(subject,*row) if row else None
            check((previous['version'] if previous else 0)==expected,'DECISION_ADVANCED_REFRESH_REQUIRED')
            if previous:check(P.instant(value['recorded_at'])>=P.instant(previous['recorded_at']),'DECISION_CLOCK_ROLLBACK')
            version=expected+1;value={**deepcopy(value),'policy':POLICY,'subject':subject,'version':version,'supersedes':digest(previous) if previous else None,'intent':fingerprint}
            nonce=os.urandom(12);blob=nonce+self.aead.encrypt(nonce,canonical(value),canonical([POLICY,subject,version]))
            check(c.execute('SELECT COUNT(*) FROM events').fetchone()[0]<100000,'DECISION_CAPACITY_REACHED')
            c.execute('INSERT INTO events(subject,version,operation,value) VALUES(?,?,?,?)',(subject,version,operation,blob));return value
    def pending_audit(self):
        with self.transaction() as c:rows=c.execute('SELECT seq,subject,version,value FROM events WHERE seq NOT IN (SELECT seq FROM audit_ack) ORDER BY seq LIMIT 100').fetchall()
        return [(seq,self.open(s,v,b)) for seq,s,v,b in rows]
    def ack(self,seq,log_seq):
        with self.transaction() as c:
            old=c.execute('SELECT log_sequence FROM audit_ack WHERE seq=?',(seq,)).fetchone()
            if old:check(old[0]==log_seq,'DECISION_AUDIT_ACK_DIFFERS')
            else:c.execute('INSERT INTO audit_ack VALUES(?,?)',(seq,log_seq))

class ApprovalEngine:
    def __init__(self,workspace,analysis,file,*,create=False):
        check(analysis is not None,'PROMOTION_ANALYSIS_REQUIRED');self.workspace=workspace;self.analysis=analysis;self.intake=analysis.intake
        self.file=private(file,repo=workspace.repo);self.raw=self.file.read_bytes();self.config=json.loads(self.raw)
        check(set(self.config)=={'policy','decision_root','reviewer_ids','legacy_queued'} and self.config['policy']==POLICY,'APPROVAL_CONFIG_DIFFERS')
        check(type(self.config['reviewer_ids']) is list and 0<len(self.config['reviewer_ids'])<=5,'EXPLICIT_IGP_REVIEWERS_REQUIRED')
        for ident in self.config['reviewer_ids']:check(str(UUID(ident))==ident,'REVIEWER_ID_INVALID')
        check(type(self.config['legacy_queued']) is dict and len(self.config['legacy_queued'])<=1000,'LEGACY_INVENTORY_INVALID')
        self.journal=DecisionJournal(self.config['decision_root'],self.intake.key,repo=workspace.repo,create=create)
    def guard(self):
        self.analysis.guard();check(private(self.file,repo=self.workspace.repo).read_bytes()==self.raw,'APPROVAL_CONFIGURATION_CHANGED')
    def reviewer(self,user):return user['user_id'] in self.config['reviewer_ids'] and user['role']=='IGP' and user['scope_type']=='ALL' and user['active']
    def live_reviewer(self,decision):
        ident=decision['actor']['user_id'];access=self.workspace.access
        with access.transaction() as c:
            records=[]
            for uid,version,blob in c.execute('SELECT id,version,value FROM users'):
                value=access.open('USER',uid,version,blob);envelope=value.get('account',value.get('grant'))
                if envelope and envelope['payload']['user_id']==ident:records.append(envelope)
        check(len(records)==1,'REVIEWER_ACCOUNT_UNAVAILABLE')
        user=account(records[0],access.keys,now=access.clock())
        check(self.reviewer(user) and user['version']==decision['actor']['version'],'REVIEWER_AUTHORIZATION_CHANGED')
        return user
    def request(self,batch,user):
        self.guard();check(batch['actor']['user_id']==user['user_id'],'UPLOADER_IDENTITY_DIFFERS')
        check(not any(r['status']=='NEEDS_REVIEW' for r in batch['rows']) and any(r['status']=='READY' for r in batch['rows']),'ROWS_REQUIRE_REVIEW')
        check(self.intake.phase(batch['batch_id'],'QUEUED') is None,'BATCH_ALREADY_PROCESSING')
        subject='BATCH:'+batch['batch_id'];old=self.journal.head(subject)
        if old:
            check(old['binding']==batch_binding(batch),'APPROVAL_UPLOAD_CHANGED');return old
        return self.journal.append(subject,'submit:'+batch['batch_id'],0,dict(kind='SUBMIT',batch_id=batch['batch_id'],binding=batch_binding(batch),actor=actor(user),recorded_at=stamp(self.workspace),reason='HQ submitted exact validated upload for independent processing approval'))
    def decide(self,batch,user,request):
        self.guard();check(self.reviewer(user),'IGP_APPROVAL_FORBIDDEN')
        check(user['user_id']!=batch['actor']['user_id'],'SELF_APPROVAL_FORBIDDEN')
        check(set(request)=={'batch_id','file_sha256','operation_id','expected_version','decision','reason'},'APPROVAL_FIELDS_DIFFER')
        check(str(UUID(request['operation_id']))==request['operation_id'],'OPERATION_ID_INVALID')
        check(request['file_sha256']==batch['file_sha256'],'APPROVAL_FILE_CHANGED')
        check(request['decision'] in ('APPROVE','REJECT','REQUEST_CHANGES'),'APPROVAL_DECISION_INVALID')
        check(type(request['expected_version']) is int and request['expected_version']>=0,'APPROVAL_VERSION_INVALID')
        reason=request['reason'];check(type(reason) is str and 3<=len(reason.strip())<=1000 and not any(ord(c)<32 for c in reason),'APPROVAL_REASON_REQUIRED')
        subject='BATCH:'+batch['batch_id'];old=self.journal.head(subject)
        # Exact operation recovery is handled before state transitions; time is retained.
        previous=self.journal.rows(subject)
        replay=next((p for p in previous if p.get('operation_id')==request['operation_id']),None)
        if replay:
            check(replay['request']==request and replay['actor']==actor(user),'DECISION_OPERATION_CONFLICT');return replay
        legacy=self.config['legacy_queued'].get(batch['batch_id'])
        if old is None:check(legacy==batch_binding(batch),'SUBMIT_TO_IGP_FIRST')
        else:
            renewal=old['kind']=='APPROVE' and request['decision']=='APPROVE' and old['actor']['user_id']==user['user_id'] and old['actor']['version']<user['version']
            check((old['kind']=='SUBMIT' or renewal) and old['binding']==batch_binding(batch),'APPROVAL_ALREADY_DECIDED')
        check(not any(r['status']=='NEEDS_REVIEW' for r in batch['rows']) and any(r['status']=='READY' for r in batch['rows']),'ROWS_REQUIRE_REVIEW')
        return self.journal.append(subject,request['operation_id'],request['expected_version'],dict(kind=request['decision'],batch_id=batch['batch_id'],binding=batch_binding(batch),actor=actor(user),recorded_at=stamp(self.workspace),reason=reason.strip(),operation_id=request['operation_id'],request=request,legacy_processing_already_started=bool(legacy)))
    def approval(self,batch):
        value=self.journal.head('BATCH:'+batch['batch_id'])
        if value:check(value['binding']==batch_binding(batch),'APPROVAL_UPLOAD_CHANGED')
        return value
    def queue(self,batch):
        decision=self.approval(batch);check(decision is not None and decision['kind']=='APPROVE','IGP_APPROVAL_REQUIRED');self.live_reviewer(decision)
        existing=self.intake.phase(batch['batch_id'],'QUEUED')
        if existing is None:self.intake.queue(batch['batch_id'],{'actor':batch['actor'],'file_sha256':batch['file_sha256'],'baseline_source_set_sha256':batch['baseline_source_set_sha256'],'igp_approval_sha256':digest(decision)})
        else:
            check(self.config['legacy_queued'].get(batch['batch_id'])==batch_binding(batch) or existing.get('igp_approval_sha256') in {digest(d) for d in self.journal.rows('BATCH:'+batch['batch_id']) if d['kind']=='APPROVE'},'QUEUED_APPROVAL_DIFFERS')
    def processing_allowed(self,batch):
        self.guard();queued=self.intake.phase(batch['batch_id'],'QUEUED');check(queued is not None,'BATCH_NOT_QUEUED')
        if self.config['legacy_queued'].get(batch['batch_id'])==batch_binding(batch):return
        decision=self.approval(batch);check(decision is not None and decision['kind']=='APPROVE' and queued.get('igp_approval_sha256') in {digest(d) for d in self.journal.rows('BATCH:'+batch['batch_id']) if d['kind']=='APPROVE'},'IGP_APPROVAL_REQUIRED');self.live_reviewer(decision)
    # Sequence and conflict issues stay with the evidence; a reviewer cannot accept past them.
    BLOCKING=frozenset({'IGP_PROCESSING_APPROVAL_REQUIRED','EARLIER_PROMOTION_REQUIRES_REVIEW','RANK_EVIDENCE_UNRESOLVED',
        'FROM_RANK_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE','PROMOTION_MUST_INCREASE_RANK',
        'MULTIPLE_UPLOADED_PROMOTIONS_AT_SAME_EFFECTIVE_DATE','CONFLICTING_ORIGINAL_PROMOTION_AT_EFFECTIVE_DATE'})
    @staticmethod
    def review_core(batch_id,row,status,reasons,binding):
        """The exact automatic evaluation a reviewer saw; any evidence change voids the review."""
        return digest(dict(batch_id=batch_id,source_row=row,status=status,reasons=sorted(set(reasons)),binding=binding))
    def reviewed(self,batch_id,row,status,issues,binding):
        """Apply a retained independent row review only to its exact pending evaluation."""
        if status!='PENDING_REVIEW':return status,{}
        review=self.journal.head('REVIEW:'+batch_id+':'+str(row))
        if review is None or review['evaluation_sha256']!=self.review_core(batch_id,row,status,issues,binding):return status,{}
        try:self.live_reviewer(review)
        except Exception:
            issues.append('ROW_REVIEWER_AUTHORIZATION_CHANGED');return status,{}
        if review['kind']=='ROW_REJECT':return 'NOT_ACCEPTED',dict(acceptance_basis='INDEPENDENT_IGP_ROW_REVIEW',review_reference=digest(review))
        if set(issues)&self.BLOCKING:return status,{}
        return 'ACCEPTED',dict(acceptance_basis='INDEPENDENT_IGP_ROW_REVIEW',review_reference=digest(review))
    def review_row(self,batch,user,request):
        """Independent IGP decision on one pending row; never the uploader, never past a blocking issue."""
        self.guard();check(self.reviewer(user),'IGP_APPROVAL_FORBIDDEN')
        check(user['user_id']!=batch['actor']['user_id'],'SELF_APPROVAL_FORBIDDEN')
        check(set(request)=={'batch_id','row','operation_id','expected_version','decision','reason','evidence_reference','evaluation_reference'},'ROW_REVIEW_FIELDS_DIFFER')
        check(request['batch_id']==batch['batch_id'] and type(request['row']) is int and 0<request['row']<=len(batch['rows']),'ROW_REVIEW_TARGET_INVALID')
        check(str(UUID(request['operation_id']))==request['operation_id'],'OPERATION_ID_INVALID')
        check(request['decision'] in ('ACCEPT','REJECT'),'ROW_REVIEW_DECISION_INVALID')
        check(type(request['expected_version']) is int and request['expected_version']>=0,'APPROVAL_VERSION_INVALID')
        for field,low,high,code in (('reason',3,1000,'APPROVAL_REASON_REQUIRED'),('evidence_reference',3,200,'ROW_REVIEW_EVIDENCE_REQUIRED')):
            value=request[field];check(type(value) is str and low<=len(value.strip())<=high and not any(ord(c)<32 for c in value),code)
        subject='REVIEW:'+batch['batch_id']+':'+str(request['row'])
        replay=next((p for p in self.journal.rows(subject) if p.get('operation_id')==request['operation_id']),None)
        if replay:
            check(replay['request']==request and replay['actor']==actor(user),'DECISION_OPERATION_CONFLICT');return replay
        head=self.journal.head('ROW:'+batch['batch_id']+':'+str(request['row']))
        check(head is not None and head['result']['status']=='PENDING_REVIEW','ROW_NOT_AWAITING_REVIEW')
        check(digest(head)==request['evaluation_reference'],'ROW_EVALUATION_CHANGED')
        result=head['result']
        if request['decision']=='ACCEPT':check(not set(result['reasons'])&self.BLOCKING,'ROW_HAS_BLOCKING_ISSUES')
        core=self.review_core(result['batch_id'],result['source_row'],'PENDING_REVIEW',result['reasons'],result['binding'])
        return self.journal.append(subject,request['operation_id'],request['expected_version'],dict(kind='ROW_'+request['decision'],
            batch_id=batch['batch_id'],row=request['row'],evaluation_sha256=core,evaluation_reference=request['evaluation_reference'],
            actor=actor(user),recorded_at=stamp(self.workspace),reason=request['reason'].strip(),
            evidence_reference=request['evidence_reference'].strip(),operation_id=request['operation_id'],request=request))
    def authority(self,packet,directory,report):
        """Same typed algorithm/signature/actor binding checks as the scoped authority view."""
        known=datetime.fromtimestamp(self.workspace.clock(),timezone.utc);actions=self.analysis.actions(packet,directory,[report]);records=S.rows(self.workspace,report['officer_uid']);results=[]
        for ref,action in actions.items():
            envelope=next((e for e in reversed(records) if e['payload']['action_reference']==ref and P.instant(e['payload']['recorded_at'])<=known),None)
            typed=None;reason=[]
            if envelope:
                p=envelope['payload']
                if p['workspace_sha256']!=P.fingerprint(packet) or p['source_public_sha256']!=packet['source_public_sha256']:reason.append('ASSESSMENT_SOURCE_WORKSPACE_CHANGED')
                elif P.instant(p['recorded_at'])<P.instant(report['analysis_recorded_at']):reason.append('ASSESSMENT_PRECEDES_UPLOADED_EVIDENCE')
                else:typed=A.assessment(p['assessment'])
            history,pins,missing=A.actor_history(self.workspace,packet,directory,[action],known,A.assessment_actors(typed) if typed else ())
            needed=set(action.actor_candidates)|(A.assessment_actors(typed) if typed else set())
            if typed and (needed.intersection(missing) or {u:envelope['payload']['actor_packets'].get(u) for u in needed}!={u:pins[u] for u in needed if u in pins}):
                typed=None;reason.append('ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE')
            if typed and any(s.state.actor_uid not in history.buckets or history.project(s.state.actor_uid,s.state.on)[0]!=s.state_id for s in typed.states):
                typed=None;reason.append('ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE')
            if action.reported_date and date.fromisoformat(action.reported_date)>known.date():typed=None;reason.append('FUTURE_ACTION_AUTHORITY_UNESTABLISHED_AT_KNOWLEDGE_TIME')
            result=A.ActionAuthority(history).review(action,typed)
            results.append(dict(action_reference=ref,status=result['status'],reasons=sorted(set(result['reasons'])|set(reason)),assessment_reference=P.fingerprint(envelope) if envelope else None,actor_packets=pins))
        # A promotion may contain additional action routes; all required routes must pass.
        status='INVALID' if any(r['status']=='INVALID' for r in results) else 'VALID' if results and all(r['status']=='VALID' for r in results) else 'CANNOT_VERIFY'
        check(S.rows(self.workspace,report['officer_uid'])==records,'ASSESSMENT_CHANGED_DURING_ACCEPTANCE')
        for result in results:
            for officer,pin in result['actor_packets'].items():check(P.fingerprint(self.workspace.get_packet(officer))==pin,'ACTOR_CHANGED_DURING_ACCEPTANCE')
        return dict(status=status,actions=results,assessment_inventory_sha256=digest(records))
    def evaluate_officer(self,officer):
        self.guard();reports=self.analysis.reports(officer)
        if not reports:return []
        packet=self.workspace.get_packet(officer)
        from app.access.full_source_profiles import profile
        with self.workspace.access.transaction() as c:directory=self.workspace.access._directory(c)
        source=profile(self.workspace,officer,directory['source_public_sha256'])
        service=[r for r in source['full_records'] if r['dataset']=='officer_service_information.csv']
        baseline=service[0]['fields'] if len(service)==1 else {};rank=RANKS.get(baseline.get('current_rank','').strip());base_rank=rank
        current_date=datetime.fromtimestamp(self.workspace.clock(),timezone.utc).astimezone(__import__('zoneinfo').ZoneInfo('Asia/Colombo')).date()
        results=[];by_date={};sequence_blocked=False
        for r in reports:by_date.setdefault(r['fields']['effective_date'].strip(),[]).append(r)
        for report in sorted(reports,key=lambda r:(r['fields']['effective_date'].strip(),r['raw_record_id'])):
            batch=self.intake.get(report['batch_id']);decision=self.approval(batch);f=report['fields'];issues=[]
            if decision is None or decision['kind']!='APPROVE':issues.append('IGP_PROCESSING_APPROVAL_REQUIRED')
            if sequence_blocked:issues.append('EARLIER_PROMOTION_REQUIRES_REVIEW')
            old,new=RANKS.get(f['from_rank'].strip()),RANKS.get(f['to_rank'].strip())
            if old is None or new is None or rank is None:issues.append('RANK_EVIDENCE_UNRESOLVED')
            elif old!=rank:issues.append('FROM_RANK_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE')
            elif ORDER.index(new)>=ORDER.index(old):issues.append('PROMOTION_MUST_INCREASE_RANK')
            same=by_date[f['effective_date'].strip()]
            if len(same)>1:issues.append('MULTIPLE_UPLOADED_PROMOTIONS_AT_SAME_EFFECTIVE_DATE')
            for row in packet.get('full_records',[]):
                if row['dataset']=='promotion_history.csv' and row['fields'].get('effective_date','').strip()==f['effective_date'].strip() and row['fields'].get('to_rank','').strip()!=f['to_rank'].strip():issues.append('CONFLICTING_ORIGINAL_PROMOTION_AT_EFFECTIVE_DATE')
            if baseline.get('service_status')!='Active':issues.append('SERVICE_STATUS_REQUIRES_REVIEW')
            authority=self.authority(packet,directory,report)
            if authority['status']!='VALID':issues.extend(v for a in authority['actions'] for v in a['reasons']);issues.append('AUTHORITY_'+authority['status'])
            check(P.instant(report['analysis_recorded_at'])<=datetime.fromtimestamp(self.workspace.clock(),timezone.utc),'ACCEPTANCE_CLOCK_DIFFERS')
            status='NOT_ACCEPTED' if authority['status']=='INVALID' else 'PENDING_REVIEW' if issues else 'ACCEPTED'
            binding=digest(dict(report=report,decision=decision,source_profile=P.fingerprint(source),packet=P.fingerprint(packet),baseline=baseline))
            status,review=self.reviewed(report['batch_id'],report['source_row'],status,issues,binding)
            if status=='ACCEPTED':rank=new
            else:sequence_blocked=True
            effective=date.fromisoformat(f['effective_date'].strip())
            results.append(dict(batch_id=report['batch_id'],source_row=report['source_row'],raw_record_id=report['raw_record_id'],officer_uid=officer,status=status,reasons=sorted(set(issues)),authority=authority,
                effective_on=effective.isoformat(),from_rank=f['from_rank'].strip(),to_rank=f['to_rank'].strip(),rank_code=new,
                effective_now=effective<=current_date,baseline_rank_code=base_rank,binding=binding,
                igp_decision_reference=digest(decision) if decision else None,publication=report['publication'],**review))
        check(self.analysis.reports(officer)==reports,'PROMOTION_REPORTS_CHANGED_DURING_ACCEPTANCE')
        check(P.fingerprint(profile(self.workspace,officer,directory['source_public_sha256']))==P.fingerprint(source) and self.workspace.get_packet(officer)==packet,'SOURCE_CHANGED_DURING_ACCEPTANCE')
        with self.workspace.access.transaction() as c:check(self.workspace.access._directory(c)==directory,'DIRECTORY_CHANGED_DURING_ACCEPTANCE')
        for result in results:
            decision=self.approval(self.intake.get(result['batch_id']))
            check((digest(decision) if decision else None)==result['igp_decision_reference'],'IGP_DECISION_CHANGED_DURING_ACCEPTANCE')
        return results
    def synchronize(self,limit=20):
        self.guard()
        # Repair acknowledgement loss between approval retention and queue creation.
        for batch in self.intake.batches(limit=1000):
            decision=self.approval(batch)
            if decision and decision['kind']=='APPROVE' and self.intake.phase(batch['batch_id'],'QUEUED') is None:self.queue(batch)
        active=self.analysis.journal.identifiers();officers=set()
        for ident in sorted(active):
            b=self.intake.get(ident)
            if self.approval(b):officers.update(r['officer_uid'] for r in b['rows'] if r['status']=='READY')
        # The configured intake quota bounds this list. Rotate to avoid starvation.
        ordered=sorted(officers);start=getattr(self,'cursor',0)%max(1,len(ordered));selected=(ordered[start:]+ordered[:start])[:limit];self.cursor=start+len(selected)
        for officer in selected:
            for result in self.evaluate_officer(officer):
                subject='ROW:'+result['batch_id']+':'+str(result['source_row']);previous=self.journal.head(subject)
                # effective_now is derived at read time; not an approval mutation.
                stable={k:v for k,v in result.items() if k!='effective_now'}
                if previous and previous['result']==stable:continue
                decision=self.approval(self.intake.get(result['batch_id']))
                if result['status']=='ACCEPTED' and (not previous or previous['result']['status']!='ACCEPTED'):self.live_reviewer(decision)
                self.journal.append(subject,'evaluation:'+subject+':'+str(previous['version']+1 if previous else 1)+':'+digest(stable),previous['version'] if previous else 0,dict(kind='PROMOTION_ACCEPTANCE',batch_id=result['batch_id'],actor=decision['actor'] if decision else {},recorded_at=stamp(self.workspace),reason='Evidence-derived promotion acceptance evaluation',result=stable))
        self.audit_outbox()
    def affected_officers(self):
        self.guard()
        with self.journal.transaction() as c:subjects=[r[0] for r in c.execute("SELECT DISTINCT subject FROM events WHERE subject LIKE 'ROW:%'")]
        return {self.journal.head(s)['result']['officer_uid'] for s in subjects}
    def current(self,officer):
        results=self.evaluate_officer(officer);current=[];pending=0;retained={}
        for result in results:
            head=self.journal.head('ROW:'+result['batch_id']+':'+str(result['source_row']));stable={k:v for k,v in result.items() if k!='effective_now'}
            retained[(result['batch_id'],result['source_row'])]=head is not None and head['result']==stable
            if not retained[(result['batch_id'],result['source_row'])]:pending+=1;continue
            if result['status']=='ACCEPTED' and result['effective_now']:current.append((result,head))
            elif result['status']!='ACCEPTED':pending+=1
        inventory=digest(S.rows(self.workspace,officer)) if results else None
        check(all(r['authority']['assessment_inventory_sha256']==inventory for r in results),'ASSESSMENT_CHANGED_DURING_PROJECTION')
        selected=max(current,key=lambda x:(x[0]['effective_on'],x[0]['raw_record_id'])) if current else None
        accepted=dict(**selected[0],acceptance_reference=digest(selected[1]),accepted_at=selected[1]['recorded_at']) if selected else None
        if accepted:
            for action in accepted['authority']['actions']:
                action['actor_evidence_digest']=digest(action.pop('actor_packets'))
        return {'policy':POLICY,'accepted_promotion':accepted,'pending_promotions':pending,
            'row_outcomes':[dict(batch_id=r['batch_id'],source_row=r['source_row'],
                status=r['status'],reasons=r['reasons'],from_rank=r['from_rank'],to_rank=r['to_rank'],
                effective_on=r['effective_on'],effective_now=r['effective_now'],
                decision_retained=retained[(r['batch_id'],r['source_row'])]) for r in results],
            'source_service_record_preserved':True}
    def audit_outbox(self):
        logs=getattr(self.workspace,'accountability',None)
        if logs is None:return
        from app.access.accountability import ACTIONS
        ACTIONS.add('PROMOTION_DECISION_RETAINED')
        for seq,value in self.journal.pending_audit():
            a=value['actor'];logseq=logs.append(dict(action='PROMOTION_DECISION_RETAINED',phase='ADMINISTRATION',method='WORKER',status=None,outcome='ALLOWED',actor=dict(user_id=a.get('user_id'),username=a.get('username'),role=a.get('role'),scope_type=a.get('scope_type'),scope_id=a.get('scope_id'),account_version=a.get('version'),authenticated=False,authentication_state='RETAINED_DECISION_OUTBOX'),request_id=None,operation_id=value.get('operation_id'),finding_id=None,requested_officer_uid=value.get('result',{}).get('officer_uid'),session_reference=None,peer_reference=None,reason=value['kind'],promotion_batch_id=value['batch_id'],promotion_decision_reference=digest(value),promotion_decision_version=value['version'],promotion_decision_recorded_at=value['recorded_at'],promotion_decision_status=value.get('result',{}).get('status'),promotion_decision_reason=value['reason']))
            self.journal.ack(seq,logseq)

def configured_approvals(workspace,analysis):
    if analysis is None:return None
    file=analysis.runtime.get('approval_config')
    return ApprovalEngine(workspace,analysis,file) if file else None
