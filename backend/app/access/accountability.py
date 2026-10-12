"""Encrypted, append-only local request accountability; not independent anchoring."""
import base64
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
SCHEMA='''CREATE TABLE events(seq INTEGER PRIMARY KEY,previous TEXT NOT NULL,value BLOB NOT NULL,digest TEXT NOT NULL);
CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
PRAGMA user_version=1;'''
UUID_RE=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
ACTION_PATHS={'/api/auth/login':'LOGIN','/api/auth/logout':'LOGOUT','/api/auth/session':'SESSION_CHECK',
 '/api/officers/search':'OFFICER_SEARCH','/api/research/history':'HISTORY_QUERY',
 '/api/research/requests':'REVIEW_REQUEST','/api/accountability/logs':'ACCESS_LOG_READ',
 '/api/accountability/legacy':'LEGACY_LOG_READ','/api/accountability/capabilities':'LOG_PERMISSION_CHECK',
 '/accountability':'LOG_PAGE_VIEW'}
ACTIONS=set(ACTION_PATHS.values())|{'OFFICER_IDENTITY_READ','WORKSPACE_READ','RECENT_REQUESTS_READ',
 'REQUEST_STATUS_READ','CORRECTION_REQUEST','OTHER_REQUEST','ACCOUNT_RENEWAL','LOG_READER_GRANT'}

def canonical_uid(value):
    try:return value if type(value) is str and str(UUID(value))==value else None
    except Exception:return None

def action_for(path):
    if path in ACTION_PATHS:return ACTION_PATHS[path]
    for pattern,action in [(r'/api/officers/'+UUID_RE,'OFFICER_IDENTITY_READ'),
      (r'/api/research/officers/'+UUID_RE+r'/requests','RECENT_REQUESTS_READ'),
      (r'/api/research/officers/'+UUID_RE,'WORKSPACE_READ'),
      (r'/api/research/requests/'+UUID_RE,'REQUEST_STATUS_READ')]:
        if re.fullmatch(pattern,path):return action
    return 'OTHER_REQUEST'

def configured(file,*,access,workspace_key=None,workspace_root=None,create=False):
    file=private(file,repo=access.repo);c=json.loads(file.read_text())
    require(type(c) is dict and set(c)=={'policy','state_directory','key_file','reader_grants'})
    require(c['policy']=='ACCOUNTABILITY_CONFIG_V1' and type(c['reader_grants']) is list and len(c['reader_grants'])<=20)
    store=AccountabilityStore(c['state_directory'],c['key_file'],access=access,create=create)
    if workspace_key is not None:require(store.key!=private(workspace_key,repo=access.repo).read_bytes(),'Independent log key required')
    if workspace_root is not None:
        other=private(workspace_root,directory=True,repo=access.repo)
        require(not store.root.is_relative_to(other) and not other.is_relative_to(store.root),'Separate workspace/log stores required')
    store.grant_files=tuple(c['reader_grants'])
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

    def append(self,event):
        require(event['action'] in ACTIONS and event['phase'] in ('RECEIVED','COMPLETED','ADMINISTRATION'))
        value={**event,'recorded_at':datetime.fromtimestamp(self.clock(),timezone.utc).isoformat(),
               'event_id':str(uuid4()),'policy':POLICY}
        with self.locked() as c:
            rows,previous=self.verify(c,recover=True);seq=len(rows)+1
            nonce=secrets.token_bytes(12)
            blob=nonce+self.aead.encrypt(nonce,encoded(value),encoded([POLICY,seq,previous]))
            head=self.digest('EVENT',[seq,previous,blob.hex()])
            c.execute('INSERT INTO events VALUES(?,?,?,?)',(seq,previous,blob,head));c.commit()
            self._checkpoint(seq,head)
        return seq

    def load_grant(self,file,check_time=True):
        value=json.loads(private(file,repo=self.repo).read_text())
        require(type(value) is dict and set(value)=={'key_id','payload','signature'})
        require(value['key_id'] in self.access.keys)
        p=value['payload']
        require(type(p) is dict and set(p)=={'policy','kind','user_id','account_version','issued_at','expires_at','review_reference'})
        require(p['policy']==POLICY and p['kind']=='READ_ACCESS_LOGS' and canonical_uid(p['user_id']))
        require(type(p['account_version']) is int and p['account_version']>0)
        require(type(p['issued_at']) is int and type(p['expires_at']) is int and
                p['issued_at']<p['expires_at']<=p['issued_at']+86400)
        require(type(p['review_reference']) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',p['review_reference']))
        Ed25519PublicKey.from_public_bytes(self.access.keys[value['key_id']]).verify(
            base64.b64decode(value['signature'],validate=True),encoded(p))
        if check_time:require(p['issued_at']<=self.clock()<p['expires_at'])
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
                            session['last']<=self.clock()<session['last']+600):state='SESSION_EXPIRED'
                    elif session:state='ACTIVE'
                    authenticated=bool(session and p['active'] and session['version']==row[0] and
                       session['created']<=self.clock()<session['created']+1800 and
                       session['last']<=self.clock()<session['last']+600)
                except Exception:state='ACCOUNT_GRANT_INVALID_OR_EXPIRED'
                return {'user_id':p['user_id'],'username':p['username'],'role':p['role'],
                        'account_version':row[0],'scope_type':p['scope_type'],'scope_id':p['scope_id'],
                        'authenticated':authenticated,'authentication_state':state,
                        'session_account_version':session['version'] if session else None}
        except Exception:return None

    def read(self,token,csrf,filters,legacy=False):
        self.reader(token,csrf)
        try:
            require(type(filters) is dict and set(filters)=={'limit','before_sequence','action','outcome'})
            limit=filters['limit'];before=filters['before_sequence']
            require(type(limit) is int and 1<=limit<=100)
            require(before is None or type(before) is int and before>0)
            require(filters['action'] in (None,*ACTIONS) and filters['outcome'] in (None,'ALLOWED','DENIED','FAILED','ATTEMPT'))
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
    def __init__(self,app,store):self.app=app;self.store=store
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        path=scope.get('path','');tracked=path.startswith('/api/') or path=='/accountability'
        if not tracked:return await self.app(scope,receive,send)
        ident=str(uuid4());token=cookie(scope.get('headers',[]))
        actor=await run_in_threadpool(self.store.actor,token)
        peer=scope.get('client');peer_ref=self.store.digest('PEER',str(peer[0]) if peer else 'unknown')
        base={'request_id':ident,'action':action_for(path),'method':scope['method'] if scope['method'] in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS') else 'OTHER',
              'actor':actor,'peer_reference':peer_ref,'requested_officer_uid':None,'finding_id':None,'operation_id':None,
              'status':None,'outcome':'ATTEMPT','reason':None}
        for part in path.split('/'):
            if canonical_uid(part):
                if base['action']=='REQUEST_STATUS_READ':base['operation_id']=part
                else:base['requested_officer_uid']=part
        async def unavailable():
            await JSONResponse({'error':'ACCOUNTABILITY_UNAVAILABLE','request_id':ident,
              'operation_outcome_unknown':scope['method']=='POST'},status_code=503,
              headers={'cache-control':'no-store','x-request-id':ident})(scope,receive,send)
        try:await run_in_threadpool(self.store.append,{**base,'phase':'RECEIVED'})
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
            if base['action']=='LOGIN':
                login=parsed.get('username');base['actor']=await run_in_threadpool(self.store.actor,None,login)
                if type(login) is str and len(login)<=200:base['attempted_login_reference']=self.store.digest('LOGIN',login)
            for key in ('officer_uid','finding_id','operation_id'):
                value=canonical_uid(parsed.get(key))
                if value:base['requested_officer_uid' if key=='officer_uid' else key]=value
            if base['action']=='REVIEW_REQUEST' and parsed.get('kind')=='CORRECTION':base['action']='CORRECTION_REQUEST'
        parsed=None
        start=next((e for e in response if e['type']=='http.response.start'),None)
        status=start['status'] if start and not overflow else 503
        base.update(status=status,outcome='ALLOWED' if 200<=status<400 else 'DENIED' if status<500 else 'FAILED')
        if start and base['action']=='LOGIN' and status==200:
            for k,v in start.get('headers',[]):
                if k.lower()==b'set-cookie' and v.startswith((COOKIE+'=').encode()):
                    new_token=v.decode('latin1').split(';',1)[0].split('=',1)[1]
                    base['actor']=await run_in_threadpool(self.store.actor,new_token)
        if status>=400:
            try:
                body=b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body')
                error=json.loads(body).get('error') if len(body)<=65536 else None
                if type(error) is str and re.fullmatch('[A-Z_]{3,80}',error):base['reason']=error
            except Exception:pass
        elif base['action']=='OFFICER_SEARCH':
            try:
                body=b''.join(e.get('body',b'') for e in response if e['type']=='http.response.body')
                value=json.loads(body) if len(body)<=65536 else None
                if type(value) is dict and type(value.get('items')) is list and len(value['items'])<=100:
                    base['returned_officer_uids']=[v['officer_uid'] for v in value['items']
                        if type(v) is dict and canonical_uid(v.get('officer_uid'))]
            except Exception:pass
        if overflow:base['reason']='RESPONSE_SIZE_LIMIT'
        try:await run_in_threadpool(self.store.append,{**base,'phase':'COMPLETED'})
        except Exception:return await unavailable()
        if overflow:return await unavailable()
        for event in response:
            if event['type']=='http.response.start':
                event={**event,'headers':[(k,v) for k,v in event.get('headers',[]) if k.lower()!=b'x-request-id']+[(b'x-request-id',ident.encode())]}
            await send(event)
