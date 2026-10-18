"""Encrypted, append-only local request accountability; not independent anchoring."""
import base64
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from uuid import UUID, uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from app.access.api import COOKIE, _json_object
from app.access.policy import AccessError, account, encoded, require, username
from app.access.store import private

POLICY='PERSONNEL_ACCOUNTABILITY_V1'
PERSISTENT_READER_POLICY='GENERATED_RETAINED_LOG_READER_V1'
SCHEMA='''CREATE TABLE events(seq INTEGER PRIMARY KEY,previous TEXT NOT NULL,value BLOB NOT NULL,digest TEXT NOT NULL);
CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
PRAGMA user_version=1;'''
UUID_RE=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
ACTION_PATHS={'/api/auth/login':'LOGIN','/api/auth/logout':'LOGOUT','/api/auth/session':'SESSION_CHECK',
 '/api/research/authority':'AUTHORITY_QUERY','/api/research/contradictions':'CONTRADICTION_QUERY',
 '/api/research/browse':'OFFICER_SEARCH','/api/officers/search':'OFFICER_SEARCH','/api/research/history':'HISTORY_QUERY',
 '/api/research/requests':'REVIEW_REQUEST','/api/accountability/logs':'ACCESS_LOG_READ',
 '/api/accountability/legacy':'LEGACY_LOG_READ','/api/accountability/capabilities':'LOG_PERMISSION_CHECK',
 '/api/accountability/session-signal':'CLIENT_PAGE_EXIT',
 '/api/accountability/activity':'CLIENT_SECTION_DISPLAY','/api/accountability/anchoring':'ACCOUNTABILITY_ANCHOR_STATUS',
 '/api/research/unit-dashboard':'UNIT_DASHBOARD_READ','/api/research/available':'CONNECTED_VIEWS_READ','/accountability':'LOG_PAGE_VIEW'}
ACTIONS=set(ACTION_PATHS.values())|{'OFFICER_IDENTITY_READ','WORKSPACE_READ','RECENT_REQUESTS_READ',
 'REQUEST_STATUS_READ','CORRECTION_REQUEST','OTHER_REQUEST','ACCOUNT_RENEWAL','LOG_READER_GRANT','DATASET_CONNECTION','AUTHORITY_ASSESSMENT_RECORD','AUTHORITY_TRUST_SETUP','SESSION_EXPIRED','SESSION_INTERRUPTED','CLIENT_PAGE_EXIT','APPLICATION_ANCHOR_READ'}

ACTIONS.update({'RESEARCH_REVIEW_'+n for n in ('PAGE','SAVE','REQUEST','DECIDE','INSPECT','OPERATIONS','CAPABILITIES','POLICY')})

def canonical_uid(value):
    try:return value if type(value) is str and str(UUID(value))==value else None
    except Exception:return None

def action_for(path):
    if path=='/reviews':return 'RESEARCH_REVIEW_PAGE'
    if path.startswith('/api/research/reviews/'):
        name=path.split('/')[4].upper()
        return 'RESEARCH_REVIEW_'+name if name in ('SAVE','REQUEST','DECIDE','INSPECT','OPERATIONS','CAPABILITIES') else 'OTHER_REQUEST'
    if path in ACTION_PATHS:return ACTION_PATHS[path]
    if re.fullmatch(r'/api/research/intake/datasets/[A-Z_]{1,31}/batches/[0-9]{1,4}',path):return 'DATASET_IMPORT_BATCHES'
    if re.fullmatch(r'/api/research/intake/officers/'+UUID_RE,path):return 'DATASET_OFFICER_UPLOADS_READ'
    for pattern,action in [(r'/api/officers/'+UUID_RE,'OFFICER_IDENTITY_READ'),
      (r'/api/research/officers/'+UUID_RE+r'/requests','RECENT_REQUESTS_READ'),
      (r'/api/research/officers/'+UUID_RE+r'/application-anchoring','APPLICATION_ANCHOR_READ'),
      (r'/api/research/officers/'+UUID_RE+r'/integrity','OFFICER_INTEGRITY_READ'),
      (r'/api/research/officers/'+UUID_RE,'WORKSPACE_READ'),
      (r'/api/research/requests/'+UUID_RE,'REQUEST_STATUS_READ')]:
        if re.fullmatch(pattern,path):return action
    return 'OTHER_REQUEST'

def configured(file,*,access,workspace_key=None,workspace_root=None,create=False):
    file=private(file,repo=access.repo);c=json.loads(file.read_text())
    require(type(c) is dict and {'policy','state_directory','key_file','reader_grants'}<=set(c)<={'policy','state_directory','key_file','reader_grants','anchor_config'})
    require(c['policy']=='ACCOUNTABILITY_CONFIG_V1' and type(c['reader_grants']) is list and len(c['reader_grants'])<=20)
    store=AccountabilityStore(c['state_directory'],c['key_file'],access=access,create=create)
    if workspace_key is not None:require(store.key!=private(workspace_key,repo=access.repo).read_bytes(),'Independent log key required')
    if workspace_root is not None:
        other=private(workspace_root,directory=True,repo=access.repo)
        require(not store.root.is_relative_to(other) and not other.is_relative_to(store.root),'Separate workspace/log stores required')
    store.grant_files=tuple(c['reader_grants'])
    store.anchor_config=c.get('anchor_config')
    # Configuration cannot silently ignore an invalid configured grant.
    for p in store.grant_files:store.load_grant(p,check_time=False)
    return store

class AccountabilityStore:
    def __init__(self,root,key_file,*,access,create=False,clock=None):
        self.access=access;self.repo=access.repo;self.clock=clock or access.clock
        self.root=private(root,directory=True,repo=self.repo)
        require(not self.root.is_relative_to(access.root) and not access.root.is_relative_to(self.root))
        self.key_path=private(key_file,repo=self.repo)
        self.key=self.key_path.read_bytes()
        require(len(self.key)==32 and self.key!=access.key_path.read_bytes())
        self.aead=AESGCM(self.key);self.lock=threading.RLock();self.grant_files=()
        self.db=self.root/'accountability.sqlite3';self.checkpoint=self.root/'checkpoint.json';self.lockfile=self.root/'write.lock'
        if create:
            for p in (self.db,self.lockfile):
                with p.open('xb') as f:os.fchmod(f.fileno(),0o600)
            with sqlite3.connect(self.db) as c:c.executescript(SCHEMA)
            self._checkpoint(0,'0'*64,new=True)
        private(self.db,repo=self.repo);private(self.lockfile,repo=self.repo)
        with self.locked() as c:self.verify(c,recover=True)

    def digest(self,kind,value):return hmac.new(self.key,encoded([POLICY,kind,value]),hashlib.sha256).hexdigest()
    def _checkpoint(self,seq,head,new=False):
        value={'policy':POLICY,'sequence':seq,'head':head}
        data=encoded({**value,'mac':self.digest('CHECKPOINT',value)})
        temp=self.root/('checkpoint-'+secrets.token_hex(8)+'.tmp')
        try:
            with temp.open('xb') as f:
                os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
            if new:require(not self.checkpoint.exists())
            else:private(self.checkpoint,repo=self.repo)
            os.replace(temp,self.checkpoint)
            fd=os.open(self.root,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if temp.exists():temp.unlink()

    @contextmanager
    def locked(self):
        with self.lock:
            private(self.root,directory=True,repo=self.repo);private(self.db,repo=self.repo)
            require(private(self.key_path,repo=self.repo).read_bytes()==self.key,'Log key changed')
            for suffix in ('-journal','-wal','-shm'):
                p=Path(str(self.db)+suffix)
                if p.exists() or p.is_symlink():private(p,repo=self.repo)
            file=private(self.lockfile,repo=self.repo)
            with file.open('r+b') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                try:
                    with sqlite3.connect(self.db,timeout=5) as c:
                        c.execute('PRAGMA synchronous=FULL');yield c
                finally:fcntl.flock(lock,fcntl.LOCK_UN)

    def verify(self,c,recover=False):
        require(c.execute('PRAGMA user_version').fetchone()[0]==1)
        saved=json.loads(private(self.checkpoint,repo=self.repo).read_text())
        require(set(saved)=={'policy','sequence','head','mac'})
        pin={k:saved[k] for k in ('policy','sequence','head')}
        require(pin['policy']==POLICY and type(pin['sequence']) is int and pin['sequence']>=0)
        require(hmac.compare_digest(saved['mac'],self.digest('CHECKPOINT',pin)))
        previous='0'*64;rows=[];pinned=pin['sequence']==0 and pin['head']==previous
        for seq,prior,blob,head in c.execute('SELECT seq,previous,value,digest FROM events ORDER BY seq'):
            require(seq==len(rows)+1 and prior==previous and hmac.compare_digest(head,self.digest('EVENT',[seq,prior,blob.hex()])))
            value=json.loads(self.aead.decrypt(blob[:12],blob[12:],encoded([POLICY,seq,prior])))
            rows.append((seq,value));previous=head
            if seq==pin['sequence']:pinned=head==pin['head']
        require(pinned and len(rows)>=pin['sequence'],'Log rollback or missing event')
        if recover and len(rows)>pin['sequence']:self._checkpoint(len(rows),previous)
        return rows,previous

    def _append_locked(self,c,event):
        require(event['action'] in ACTIONS and event['phase'] in ('RECEIVED','COMPLETED','ADMINISTRATION'))
        value={**event,'recorded_at':datetime.fromtimestamp(self.clock(),timezone.utc).isoformat(),
               'event_id':str(uuid4()),'policy':POLICY}
        rows,previous=self.verify(c,recover=True);seq=len(rows)+1
        nonce=secrets.token_bytes(12)
        blob=nonce+self.aead.encrypt(nonce,encoded(value),encoded([POLICY,seq,previous]))
        head=self.digest('EVENT',[seq,previous,blob.hex()])
        c.execute('INSERT INTO events VALUES(?,?,?,?)',(seq,previous,blob,head));c.commit()
        self._checkpoint(seq,head)
        return seq

    def append(self,event):
        with self.locked() as c:return self._append_locked(c,event)

    def session_reference(self,token):
        return self.digest('SESSION_REFERENCE',token) if type(token) is str and 40<=len(token)<=64 else None

    def instance_reference(self):return self.digest('SERVER_INSTANCE',self.access.boot_key.hex())

    def login_metadata(self,token):
        with self.access.transaction() as c:
            account_,session=self.access._session(c,token)
            deadline=min(session['created']+1800,account_['expires_at']) if account_['expires_at'] is not None else session['created']+1800
            return dict(session_reference=self.session_reference(token),server_instance_reference=self.instance_reference(),
                session_started_at=datetime.fromtimestamp(session['created'],timezone.utc).isoformat(),
                session_deadline=datetime.fromtimestamp(deadline,timezone.utc).isoformat(),
                deadline_reason='FIXED_30_MINUTE_LIMIT' if deadline==session['created']+1800 else 'ACCOUNT_AUTHORIZATION_EXPIRY')

    def session_signal(self,token,csrf,value):
        if not (type(value) is dict and set(value)=={'event','page','persisted'} and value['event']=='PAGE_EXIT' and
                value['page'] in ('WORKSPACE','ACCESS_LOGS') and type(value['persisted']) is bool):
            raise AccessError(400,'INVALID_SESSION_SIGNAL')
        with self.access.transaction() as c:
            _,session=self.access._session(c,token,csrf)
            self.access._limit(c,'SESSION_SIGNAL',session['user'],30)
        return {'received':True,'logout_confirmed':False}

    def reconcile_sessions(self,*,restart=False,shutdown=False):
        """Independent expiry; atomic terminal-event dedupe against the encrypted ledger.

        No old login is invented. Prior events without a recorded deadline cannot
        be upgraded. A page-exit report never ends a server session.
        """
        now=self.clock();instance=self.instance_reference();count=0
        with self.locked() as c:
            rows,_=self.verify(c,recover=True);active={};ended=set();replacements={}
            for _,event in rows:
                ref=event.get('session_reference')
                if event.get('action')=='LOGIN' and event.get('phase')=='COMPLETED' and event.get('status')==200 and ref and event.get('session_deadline'):
                    active[ref]=event
                    prior=event.get('replaced_session_reference')
                    if prior:replacements[prior]=event
                if ref and event.get('phase')=='COMPLETED' and ((event.get('action')=='LOGOUT' and event.get('status')==200) or event.get('action') in ('SESSION_EXPIRED','SESSION_INTERRUPTED')):
                    ended.add(ref)
            for ref,login in active.items():
                if ref in ended:continue
                deadline=datetime.fromisoformat(login['session_deadline']).timestamp()
                if now>=deadline:
                    action='SESSION_EXPIRED';reason=login['deadline_reason'];effective=login['session_deadline']
                elif ref in replacements:
                    action='SESSION_INTERRUPTED';reason='REPLACED_BY_NEW_LOGIN';effective=replacements[ref]['session_started_at']
                elif (restart and login['server_instance_reference']!=instance) or (shutdown and login['server_instance_reference']==instance):
                    action='SESSION_INTERRUPTED';reason='SERVER_RESTART_OBSERVED' if restart else 'SERVER_SHUTDOWN_OBSERVED';effective=None
                else:continue
                self._append_locked(c,dict(action=action,phase='COMPLETED',method='SERVER',status=None,outcome='ALLOWED',
                    request_id=str(uuid4()),actor={**login['actor'],'authenticated':False,'authentication_state':action},
                    session_reference=ref,session_started_at=login['session_started_at'],session_deadline=login['session_deadline'],
                    session_effective_end_at=effective,reason=reason,logout_confirmed=False,
                    explanation='Authorization expired at the recorded deadline.' if action=='SESSION_EXPIRED' else
                        'Server interruption observed; browser closure and exact human logout time are unknown.'))
                count+=1
        return count

    def load_grant(self,file,check_time=True):
        value=json.loads(private(file,repo=self.repo).read_text())
        require(type(value) is dict and set(value)=={'key_id','payload','signature'})
        require(value['key_id'] in self.access.keys)
        p=value['payload']
        require(type(p) is dict and set(p)=={'policy','kind','user_id','account_version','issued_at','expires_at','review_reference'})
        require(p['policy'] in (POLICY,PERSISTENT_READER_POLICY) and p['kind']=='READ_ACCESS_LOGS' and canonical_uid(p['user_id']))
        require(type(p['account_version']) is int and p['account_version']>0)
        require(type(p['issued_at']) is int)
        if p['policy']==PERSISTENT_READER_POLICY:require(p['expires_at'] is None)
        else:require(type(p['expires_at']) is int and p['issued_at']<p['expires_at']<=p['issued_at']+86400)
        require(type(p['review_reference']) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',p['review_reference']))
        Ed25519PublicKey.from_public_bytes(self.access.keys[value['key_id']]).verify(
            base64.b64decode(value['signature'],validate=True),encoded(p))
        if check_time:require(p['issued_at']<=self.clock() and (p['expires_at'] is None or self.clock()<p['expires_at']))
        return p

    def reader(self,token,csrf=None):
        with self.access.transaction() as c:p,_=self.access._session(c,token,csrf)
        for file in self.grant_files:
            try:grant=self.load_grant(file)
            except Exception:continue
            if (grant['user_id'],grant['account_version'])==(p['user_id'],p['version']):return p
        raise AccessError(403,'LOG_ACCESS_DENIED')

    def actor(self,token=None,login=None):
        # Attribution only. This function never grants access or extends a session.
        try:
            with self.access.transaction() as c:
                session=None
                if token is not None and type(token) is str and 40<=len(token)<=64:
                    sid=self.access.session_id(token)
                    row=c.execute('SELECT value FROM sessions WHERE id=?',(sid,)).fetchone()
                    if row:session=self.access.open('SESSION',sid,1,row[0])
                if session:ident=session['user']
                elif login is not None:username(login);ident=self.access.index('USER',login)
                else:return None
                row=c.execute('SELECT version,value FROM users WHERE id=?',(ident,)).fetchone()
                if not row:return None
                value=self.access.open('USER',ident,row[0],row[1]);p=value['grant']['payload']
                authenticated=False
                state='NO_SESSION' if not session else 'UNVERIFIED'
                try:
                    account(value['grant'],self.access.keys,now=self.clock())
                    if not p['active']:state='ACCOUNT_INACTIVE'
                    elif session and session['version']!=row[0]:state='ACCOUNT_VERSION_CHANGED'
                    elif session and not (session['created']<=self.clock()<session['created']+1800 and
                            session['last']<=self.clock()):state='SESSION_EXPIRED'
                    elif session:state='ACTIVE'
                    authenticated=bool(session and p['active'] and session['version']==row[0] and
                       session['created']<=self.clock()<session['created']+1800 and
                       session['last']<=self.clock())
                except Exception:state='ACCOUNT_GRANT_INVALID_OR_EXPIRED'
                return {'user_id':p['user_id'],'username':p['username'],'role':p['role'],
                        'account_version':row[0],'scope_type':p['scope_type'],'scope_id':p['scope_id'],
                        'authenticated':authenticated,'authentication_state':state,
                        'session_account_version':session['version'] if session else None}
        except Exception:return None

    def read(self,token,csrf,filters,legacy=False):
        self.reader(token,csrf)
        try:
            require(type(filters) is dict and {'limit','before_sequence','action','outcome'}<=set(filters)<={'limit','before_sequence','action','outcome','account','request_id'})
            limit=filters['limit'];before=filters['before_sequence']
            require(type(limit) is int and 1<=limit<=100)
            require(before is None or type(before) is int and before>0)
            require(filters['action'] in (None,*ACTIONS) and filters['outcome'] in (None,'ALLOWED','DENIED','FAILED','ATTEMPT'))
            if filters.get('account') is not None:username(filters['account'])
            if filters.get('request_id') is not None:require(canonical_uid(filters['request_id']))
            if legacy:require(filters.get('account') is None and filters.get('request_id') is None)
            if legacy:require(filters['action'] is None and filters['outcome'] is None)
        except ValueError:raise AccessError(400,'INVALID_LOG_FILTERS') from None
        if legacy:
            with self.access.transaction() as c:
                self.access._verify_audit(c)
                actors={ident:self.access.open('USER',ident,version,blob)['grant']['payload']
                    for ident,version,blob in c.execute('SELECT id,version,value FROM users')}
                result=[]
                for seq,blob in c.execute('SELECT seq,value FROM audit ORDER BY seq DESC'):
                    if before is not None and seq>=before:continue
                    v=self.access.open('AUDIT',seq,1,blob);actor=actors.get(v['subject'])
                    result.append({'sequence':seq,'action':v['event'],
                        'recorded_at':datetime.fromtimestamp(v['observed_at'],timezone.utc).isoformat(),
                        'actor':{'username':actor['username'],'user_id':actor['user_id']} if actor else None,
                        'outcome':None,'reason':'LEGACY_DETAILS_NOT_CAPTURED','request_id':None,
                        'requested_officer_uid':None,'account_role_at_event':None})
                    if len(result)==limit:break
                response={'items':result,'next_before_sequence':result[-1]['sequence'] if len(result)==limit else None,
                    'integrity':'LOCAL_LEGACY_CHAIN_VERIFIED','independently_anchored':False}
            self.reader(token,csrf)
            return response
        with self.locked() as c:
            rows,head=self.verify(c,recover=True);items=[]
            for seq,v in reversed(rows):
                if before is not None and seq>=before:continue
                if filters.get('account') is not None and (v.get('actor') or {}).get('username')!=filters['account']:continue
                if filters.get('request_id') is not None and v.get('request_id')!=filters['request_id']:continue
                if filters['action'] is not None and filters['action']!=v['action']:continue
                if filters['outcome'] is not None and filters['outcome']!=v['outcome']:continue
                items.append({'sequence':seq,**v})
                if len(items)==limit:break
        self.reader(token,csrf) # Revocation during inspection stops disclosure.
        return {'items':items,'next_before_sequence':items[-1]['sequence'] if len(items)==limit else None,
                'head_sequence':len(rows),'head_digest':head,'integrity':'LOCAL_CHAIN_VERIFIED','independently_anchored':False}

def cookie(headers):
    values=[v.decode('latin1') for k,v in headers if k.lower()==b'cookie']
    if len(values)!=1:return None
    parts=[p.strip().split('=',1)[1] for p in values[0].split(';') if p.strip().startswith(COOKIE+'=')]
    return parts[0] if len(parts)==1 else None

class AccountabilityBoundary:
    def __init__(self,app,store):
        self.app=app;self.store=store;self.worker_failed=False;self.expiry_poll_seconds=5

    async def lifespan(self,scope,receive,send):
        stop=asyncio.Event();task=None;anchor_task=None
        async def monitor():
            while not stop.is_set():
                try:
                    await run_in_threadpool(self.store.reconcile_sessions)
                    self.worker_failed=False
                except Exception:self.worker_failed=True
                try:await asyncio.wait_for(stop.wait(),timeout=self.expiry_poll_seconds)
                except asyncio.TimeoutError:pass
        async def anchor_monitor():
            from app.access.accountability_anchor import tick
            while not stop.is_set():
                try:await run_in_threadpool(tick,self.store)
                except Exception:pass # Status endpoint retains pending/failure; local logging continues.
                try:await asyncio.wait_for(stop.wait(),timeout=2)
                except asyncio.TimeoutError:pass
        async def lifecycle_receive():
            event=await receive()
            if event['type']=='lifespan.startup':
                try:await run_in_threadpool(self.store.reconcile_sessions,restart=True)
                except Exception:raise RuntimeError('Accountability lifecycle unavailable') from None
            elif event['type']=='lifespan.shutdown':
                stop.set()
                if task is not None:await task
                if anchor_task is not None:await anchor_task
                await run_in_threadpool(self.store.reconcile_sessions,shutdown=True)
            return event
        async def lifecycle_send(event):
            nonlocal task,anchor_task
            if event['type']=='lifespan.startup.complete':
                task=asyncio.create_task(monitor())
                if getattr(self.store,'anchor_config',None):anchor_task=asyncio.create_task(anchor_monitor())
            await send(event)
        try:await self.app(scope,lifecycle_receive,lifecycle_send)
        finally:
            stop.set()
            if task is not None:await task
            if anchor_task is not None:await anchor_task

    async def __call__(self,scope,receive,send):
        if scope['type']=='lifespan':return await self.lifespan(scope,receive,send)
        if scope['type']!='http':return await self.app(scope,receive,send)
        path=scope.get('path','');tracked=path.startswith('/api/') or path in ('/accountability','/reviews')
        if not tracked:return await self.app(scope,receive,send)
        ident=str(uuid4());token=cookie(scope.get('headers',[]))
        actor=await run_in_threadpool(self.store.actor,token)
        peer=scope.get('client');peer_ref=self.store.digest('PEER',str(peer[0]) if peer else 'unknown')
        base={'request_id':ident,'action':action_for(path),'method':scope['method'] if scope['method'] in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS') else 'OTHER',
              'actor':actor,'peer_reference':peer_ref,'requested_officer_uid':None,'finding_id':None,'operation_id':None,
              'status':None,'outcome':'ATTEMPT','reason':None,'session_reference':self.store.session_reference(token)}
        for part in path.split('/'):
            if canonical_uid(part):
                if base['action'] in ('REQUEST_STATUS_READ','RESEARCH_REVIEW_OPERATIONS'):base['operation_id']=part
                else:base['requested_officer_uid']=part
        async def unavailable():
            await JSONResponse({'error':'ACCOUNTABILITY_UNAVAILABLE','request_id':ident,
              'operation_outcome_unknown':scope['method']=='POST'},status_code=503,
              headers={'cache-control':'no-store','x-request-id':ident})(scope,receive,send)
        try:
            await run_in_threadpool(self.store.reconcile_sessions)
            if self.worker_failed:raise RuntimeError('Lifecycle worker unavailable')
            await run_in_threadpool(self.store.append,{**base,'phase':'RECEIVED'})
        except Exception:return await unavailable()
        captured=bytearray();response=[];size=0;overflow=False
        async def recv():
            event=await receive()
            if event['type']=='http.request' and len(captured)<65536:
                data=event.get('body',b'');captured.extend(data[:65536-len(captured)])
            return event
        async def buffered(event):
            nonlocal size,overflow
            if event['type']=='http.response.body':size+=len(event.get('body',b''))
            if size>32*1024*1024:overflow=True;return
            response.append(event)
        try:await self.app(scope,recv,buffered)
        except Exception:
            response=[];await JSONResponse({'error':'RESEARCH_SERVICE_UNAVAILABLE'},status_code=503)(scope,recv,buffered)
        parsed=None
        try:
            parsed=json.loads(captured,object_pairs_hook=_json_object)
            if type(parsed) is not dict:parsed=None
        except Exception:pass
        captured.clear()
        if parsed:
            if base['action']=='RESEARCH_REVIEW_DECIDE' and parsed.get('decision') in ('APPROVE','REJECT','NEEDS_MORE_EVIDENCE'):
                base['reason']='RESEARCH_DECISION_'+parsed['decision']
            if base['action']=='LOGIN':
                base['authentication_factors_submitted']=['PASSWORD']+(['TOTP'] if 'totp_code' in parsed else [])
                login=parsed.get('username');base['actor']=await run_in_threadpool(self.store.actor,None,login)
                if type(login) is str and len(login)<=200:base['attempted_login_reference']=self.store.digest('LOGIN',login)
            for key in ('officer_uid','finding_id','operation_id'):
                value=canonical_uid(parsed.get(key))
                if value:base['requested_officer_uid' if key=='officer_uid' else key]=value
            if base['action']=='OFFICER_SEARCH' and base['actor'] and base['actor'].get('authenticated'):
                query=parsed.get('query');kind=parsed.get('kind')
                if kind in ('NAME','NIC') and type(query) is str and len(query)<=200 and not any(ord(v)<32 for v in query):
                    base['search']={'kind':kind,'query':query}
            if base['action']=='CLIENT_PAGE_EXIT' and parsed.get('event')=='PAGE_EXIT' and parsed.get('page') in ('WORKSPACE','ACCESS_LOGS') and type(parsed.get('persisted')) is bool:
                base['client_page_event']={'event':'PAGE_EXIT','page':parsed['page'],'persisted':parsed['persisted'],'logout_confirmed':False}
            if base['action']=='REVIEW_REQUEST' and parsed.get('kind')=='CORRECTION':base['action']='CORRECTION_REQUEST'
            if base['action'] in ('AUTHORITY_QUERY','CONTRADICTION_QUERY','HISTORY_QUERY') and base['actor'] and base['actor'].get('authenticated'):
                base['workflow_query']={}
                for field in ('effective_on','known_at','action_on','status','dimension','relationship'):
                    value=parsed.get(field)
                    if field in ('effective_on','known_at','action_on') and value not in (None,''):
                        try:datetime.fromisoformat(value.replace('Z','+00:00'))
                        except Exception:continue
                    if value is None or type(value) is str and len(value)<=80 and (value=='' or re.fullmatch('[A-Za-z0-9_:+. -]+',value)):base['workflow_query'][field]=value
        if parsed and base['actor'] and base['actor'].get('authenticated'):
            permitted_fields={
                'OFFICER_SEARCH':('kind','query','availability','level','scope_id','limit','offset'),
                'HISTORY_QUERY':('effective_on','known_at'),
                'AUTHORITY_QUERY':('action_on','known_at','status','limit','offset'),
                'CONTRADICTION_QUERY':('effective_on','known_at','dimension','status','relationship','limit','offset'),
                'ACCESS_LOG_READ':('limit','before_sequence','action','outcome','account','request_id'),
                'LEGACY_LOG_READ':('limit','before_sequence'),
                'CLIENT_SECTION_DISPLAY':('section','event_id'),
                **{n:('kind','decision','reason','finding_id','operation_id','expected_version') for n in ('RESEARCH_REVIEW_SAVE','RESEARCH_REVIEW_REQUEST','RESEARCH_REVIEW_DECIDE','REVIEW_REQUEST','CORRECTION_REQUEST')},
            }.get(base['action'],())
            detail={}
            for field in permitted_fields:
                value=parsed.get(field)
                if field in ('effective_on','known_at','action_on') and value not in (None,''):
                    try:datetime.fromisoformat(value.replace('Z','+00:00'))
                    except Exception:continue
                if value is None or type(value) is int and 0<=value<=10000 or type(value) is str and len(value)<=(4000 if field=='reason' else 200) and not any(ord(x)<32 and x not in '\n\t' for x in value):detail[field]=value
            if detail:base['request_details']=detail
            if base['action']=='OFFICER_SEARCH':base['request_details']['entry_point']='DIRECTORY_BROWSER' if path=='/api/research/browse' else 'IDENTITY_SEARCH'
            if base['action']=='CLIENT_SECTION_DISPLAY':base['observation_basis']='AUTHENTICATED_CLIENT_REPORT_NOT_PROOF_OF_HUMAN_READING'
        parsed=None
        start=next((e for e in response if e['type']=='http.response.start'),None)
        status=start['status'] if start and not overflow else 503
        base.update(status=status,outcome='ALLOWED' if 200<=status<400 else 'DENIED' if status<500 else 'FAILED')
        if start and base['action']=='LOGIN' and status==200:
            for k,v in start.get('headers',[]):
                if k.lower()==b'set-cookie' and v.startswith((COOKIE+'=').encode()):
                    new_token=v.decode('latin1').split(';',1)[0].split('=',1)[1]
                    base['actor']=await run_in_threadpool(self.store.actor,new_token)
                    try:base.update(await run_in_threadpool(self.store.login_metadata,new_token))
                    except Exception:return await unavailable()
                    if self.store.session_reference(token):base['replaced_session_reference']=self.store.session_reference(token)
        if status>=400:
            try:
                body=b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body')
                error=json.loads(body).get('error') if len(body)<=65536 else None
                if type(error) is str and re.fullmatch('[A-Z_]{3,80}',error):base['reason']=error
            except Exception:pass
        elif base['action'] in ('OFFICER_SEARCH','CONNECTED_VIEWS_READ'):
            try:
                body=b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body')
                value=json.loads(body) if len(body)<=512*1024 else None
                if type(value) is dict and type(value.get('items')) is list and len(value['items'])<=100:
                    base['returned_officer_uids']=[v['officer_uid'] for v in value['items']
                        if type(v) is dict and canonical_uid(v.get('officer_uid'))]
            except Exception:pass
        if base['action']=='CLIENT_PAGE_EXIT' and status!=200:base.pop('client_page_event',None)
        if base['action'] in ('AUTHORITY_QUERY','CONTRADICTION_QUERY','HISTORY_QUERY') and status==200 and 'workflow_query' in base:
            try:
                payload=b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body')
                value=json.loads(payload)
                for key in ('known_at','query_digest','comparison_digest'):
                    item=value.get(key)
                    if type(item) is str and len(item)<=80 and re.fullmatch('[A-Za-z0-9_:+. -]+',item):base['workflow_query'][key]=item
            except Exception:pass
        if status==200 and base['actor'] and base['actor'].get('authenticated'):
            try:
                answer=json.loads(b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body'))
                identity=answer.get('identity')
                if type(identity) is dict:
                    base['officer_identity']={k:identity[k] for k in ('officer_uid','names','nic') if k in identity}
                if base['action']=='OFFICER_SEARCH' and type(answer.get('items')) is list:
                    base['result_count']=len(answer['items'])
                    base['matching_total']=answer.get('total')
                    base['returned_officer_uids']=[v['officer_uid'] for v in answer['items'] if canonical_uid(v.get('officer_uid'))][:100]
                    if path=='/api/research/browse':base['result_order']='NAME_NIC_UID_ASCENDING'
            except Exception:pass
        if base['action']=='LOGOUT' and status==200:
            base.update(logout_confirmed=True,session_end_reason='MANUAL_LOGOUT',
                session_effective_end_at=datetime.fromtimestamp(self.store.clock(),timezone.utc).isoformat())
        if overflow:base['reason']='RESPONSE_SIZE_LIMIT'
        try:await run_in_threadpool(self.store.append,{**base,'phase':'COMPLETED'})
        except Exception:return await unavailable()
        if overflow:return await unavailable()
        for event in response:
            if event['type']=='http.response.start':
                event={**event,'headers':[(k,v) for k,v in event.get('headers',[]) if k.lower()!=b'x-request-id']+[(b'x-request-id',ident.encode())]}
            await send(event)
