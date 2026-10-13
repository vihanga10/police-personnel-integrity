"""Generated research approvals; never police authorization or source edits."""
import base64
from copy import deepcopy
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.access.policy import AccessError,require,uid,encoded,permitted,account,ROLES
from app.access import research_policy as P

POLICY='GENERATED_APPLICATION_REVIEW_V1'
REQUEST=['IGP','HQ_ADMIN','SDIG','DIG','SSP','SP']
REVIEW=['IGP','SDIG','DIG','SSP','SP']

def initialize(store):
    with store.transaction() as c:
        c.execute('CREATE TABLE IF NOT EXISTS application_review_policies(version INTEGER PRIMARY KEY,value BLOB NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS application_review_entries(seq INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,value BLOB NOT NULL)')
        for table in ('application_review_policies','application_review_entries'):
            for action in ('UPDATE','DELETE'):
                c.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_{action} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable research review'); END")

def policies(store,c):
    rows=[];previous=None
    for version,blob in c.execute('SELECT version,value FROM application_review_policies ORDER BY version'):
        e=store.open('APPLICATION_REVIEW_POLICY',version,blob);p=e['payload']
        require(set(e)=={'key_id','payload','signature'} and e['key_id'] in store.review_keys)
        require(set(p)=={'policy','version','supersedes','issued_at','reason','accounts','request_roles','review_roles','inspect_roles','no_self_approval'})
        require(p['policy']==POLICY and type(p['version']) is int and p['version']==version==len(rows)+1 and p['supersedes']==previous and p['no_self_approval'] is True)
        require(type(p['issued_at']) is int and p['issued_at']<=store.clock() and (not rows or p['issued_at']>=rows[-1]['payload']['issued_at']));P.text(p['reason'])
        for name in ('request_roles','review_roles','inspect_roles'):require(type(p[name]) is list and len(p[name])==len(set(p[name])) and set(p[name])<=set(ROLES))
        require(type(p['accounts']) is list and 1<=len(p['accounts'])<=100)
        seen=set()
        for a in p['accounts']:
            require(set(a)=={'user_id','role','scope_type','scope_id'});uid(a['user_id'])
            require(a['user_id'] not in seen and a['role'] in ROLES and a['scope_type'] in ROLES[a['role']]);seen.add(a['user_id'])
            if a['scope_type']=='ALL':require(a['scope_id'] is None)
            else:
                from app.access.policy import label
                label(a['scope_id'])
        Ed25519PublicKey.from_public_bytes(store.review_keys[e['key_id']]).verify(base64.b64decode(e['signature'],validate=True),encoded(p))
        rows.append(e);previous=P.fingerprint(e)
    return rows

def install_policy(store,envelope):
    initialize(store)
    with store.transaction() as c:
        old=policies(store,c)
        if old and old[-1]==envelope:return
        v=envelope['payload']['version'];require(v==len(old)+1)
        c.execute('INSERT INTO application_review_policies VALUES(?,?)',(v,store.seal('APPLICATION_REVIEW_POLICY',v,envelope)))
        policies(store,c);store.event(c,dict(kind='APPLICATION_REVIEW_POLICY',version=v,reference=P.fingerprint(envelope)))

def entries(store,c):
    rows=[];events=[e for e in store._events(c) if e.get('kind')=='APPLICATION_REVIEW_ENTRY']
    refs={P.fingerprint(p) for p in policies(store,c)}
    for seq,ident,blob in c.execute('SELECT seq,id,value FROM application_review_entries ORDER BY seq'):
        e=store.open('APPLICATION_REVIEW_ENTRY',ident,blob)
        require(seq==len(rows)+1 and ident==store.index('APPLICATION_REVIEW_OPERATION',e['input']['operation_id']))
        require(e['policy_reference'] in refs and len(events)>=seq and events[seq-1]['reference']==P.fingerprint(e))
        rows.append(e)
    require(len(events)==len(rows),'Missing review entry');return rows

def state(rows):
    findings={};requests={}
    for e in rows:
        ref=P.fingerprint(e)
        if e['kind']=='SAVE':
            require(e['finding_id'] not in findings);findings[e['finding_id']]=dict(head=ref,versions=[e])
        elif e['kind']=='REQUEST':requests[ref]=dict(reference=ref,entry=e,status='PENDING',reviews=[])
        elif e['kind']=='DECIDE':
            r=requests[e['input']['request_reference']];require(r['status']=='PENDING')
            r['status']=e['input']['decision'];r['reviews'].append(e)
            if r['status']=='APPROVE' and r['entry']['input']['request_kind']=='CORRECTION':
                f=findings[e['finding_id']];require(f['head']==e['supersedes']);f['head']=ref;f['versions'].append(e)
        else:raise ValueError('Review entry domain differs')
    return findings,requests

class ReviewWorkflow:
    def __init__(self,service):self.service=service;self.store=service.store
    def permission(self,token,csrf=None,action='inspect'):
        with self.store.access.transaction() as a:user,_=self.store.access._session(a,token,csrf)
        if not getattr(self.store,'review_keys',{}):raise AccessError(503,'REVIEW_NOT_CONFIGURED')
        with self.store.transaction() as c:ps=policies(self.store,c)
        if not ps:raise AccessError(503,'REVIEW_NOT_CONFIGURED')
        p=ps[-1];member=next((m for m in p['payload']['accounts'] if m['user_id']==user['user_id']),None)
        if not member or any(member[k]!=user[k] for k in ('role','scope_type','scope_id')) or user['role'] not in p['payload'][action+'_roles']:raise AccessError(403,'REVIEW_PERMISSION_DENIED')
        return user,p
    def source(self,token,csrf,officer):
        u,g,p,i=self.service.authorized(token,officer,csrf=csrf,charge=False)
        if p.get('record_origin')!='GENERATED_RESEARCH_RECORDS' or p.get('kind')!='PRESENTATION':raise AccessError(403,'GENERATED_RECORDED_HISTORY_REQUIRED')
        return u,p,i
    def capabilities(self,token):
        u,p=self.permission(token)
        return dict(can_request=u['role'] in p['payload']['request_roles'],can_review=u['role'] in p['payload']['review_roles'],policy_version=p['payload']['version'])
    @staticmethod
    def result(e):return dict(operation_id=e['input']['operation_id'],reference=P.fingerprint(e),finding_id=e['finding_id'],kind=e['kind'],status=e['input'].get('decision','PENDING' if e['kind']=='REQUEST' else 'SAVED'),chain_submitted=False,police_authority_issued=False,independent_witness_verified=False)
    def mutate(self,token,csrf,kind,body):
        fields={'SAVE':{'officer_uid','operation_id','finding_id','effective_on','known_at','reason'},'REQUEST':{'officer_uid','operation_id','finding_id','target_head','request_kind','effective_on','known_at','reason','prior_request'},'DECIDE':{'officer_uid','operation_id','request_reference','decision','reason'}}
        try:
            require(kind in fields and type(body) is dict and set(body)==fields[kind]);uid(body['operation_id']);uid(body['officer_uid']);P.text(body['reason'])
            if 'finding_id' in body:uid(body['finding_id'])
            for name in ('request_reference','target_head'):
                if name in body:P.sha(body[name])
            if kind=='REQUEST':
                require(body['request_kind'] in ('REVIEW','CORRECTION'))
                if body['prior_request'] is not None:P.sha(body['prior_request'])
                if body['request_kind']=='REVIEW':require(body['effective_on'] is None and body['known_at'] is None)
            if kind=='DECIDE':require(body['decision'] in ('APPROVE','REJECT','NEEDS_MORE_EVIDENCE'))
        except Exception:raise AccessError(400,'INVALID_RESEARCH_REVIEW') from None
        action='review' if kind=='DECIDE' else 'request';user,policy=self.permission(token,csrf,action);_,packet,_=self.source(token,csrf,body['officer_uid'])
        answer=None
        # Compute only on retained evidence; final transaction rechecks its pin.
        if kind=='SAVE' or kind=='REQUEST' and body['request_kind']=='CORRECTION':answer=self.service.history(token,csrf,body['officer_uid'],body['effective_on'],body['known_at'])
        with self.store.access.transaction() as a:
            with self.store.transaction() as c:
                def check():
                    current,_=self.store.access._session(a,token,csrf);directory=self.store.access._directory(a)
                    o=next((v for v in directory['officers'] if v['officer_uid']==body['officer_uid']),None)
                    ident=self.store.index('OFFICER',body['officer_uid']);row=c.execute('SELECT value FROM presentations WHERE id=?',(ident,)).fetchone()
                    latest=P.packet(self.store.open('PACKET',ident,row[0]),self.store.keys,self.store.clock()) if row else None
                    self.disclosure(c,user,body['officer_uid'],packet['source_public_sha256'])
                    if current!=user or not o or not permitted(user,o) or latest!=packet or directory['source_public_sha256']!=packet['source_public_sha256'] or policies(self.store,c)[-1]!=policy:raise AccessError(409,'REVIEW_INPUTS_CHANGED')
                check();rows=entries(self.store,c)
                old=next((e for e in rows if e['input']['operation_id']==body['operation_id']),None)
                if old:
                    if old['input']!=body or old['by']['user_id']!=user['user_id'] or old['kind']!=kind:raise AccessError(409,'OPERATION_CONFLICT')
                    return self.result(old)
                fs,rs=state(rows);extra={};fid=body.get('finding_id')
                if kind=='SAVE':
                    if fid in fs:raise AccessError(409,'FINDING_ID_CONFLICT')
                    extra['comparison']=answer
                elif kind=='REQUEST':
                    f=fs.get(fid)
                    if not f or f['versions'][0]['input']['officer_uid']!=body['officer_uid']:raise AccessError(404,'NOT_FOUND')
                    if f['head']!=body['target_head'] or f['versions'][-1]['source_sha256']!=P.fingerprint(packet):raise AccessError(409,'FINDING_CHANGED')
                    if answer and answer['comparison_digest']==f['versions'][-1]['comparison']['comparison_digest']:raise AccessError(409,'UNCHANGED_CORRECTION')
                    if body['prior_request']:
                        prior=rs.get(body['prior_request'])
                        if not prior or prior['status']!='NEEDS_MORE_EVIDENCE' or prior['entry']['by']['user_id']!=user['user_id'] or prior['entry']['finding_id']!=fid or any(r['entry']['input']['prior_request']==body['prior_request'] for r in rs.values()):raise AccessError(409,'RESUBMISSION_CONFLICT')
                    extra['proposed_comparison']=answer
                else:
                    r=rs.get(body['request_reference'])
                    if not r or r['entry']['input']['officer_uid']!=body['officer_uid']:raise AccessError(404,'NOT_FOUND')
                    req=r['entry'];fid=req['finding_id'];f=fs[fid]
                    if req['by']['user_id']==user['user_id']:raise AccessError(403,'SELF_REVIEW_FORBIDDEN')
                    if r['status']!='PENDING':raise AccessError(409,'ALREADY_DECIDED')
                    if f['head']!=req['input']['target_head'] or req['source_sha256']!=P.fingerprint(packet):raise AccessError(409,'FINDING_CHANGED')
                    row=a.execute('SELECT id,version,value FROM users WHERE owner=?',(self.store.access.index('OWNER',req['by']['user_id']),)).fetchone()
                    if not row:raise AccessError(409,'REQUESTER_REVOKED')
                    requester=account(self.store.access.open('USER',row[0],row[1],row[2])['grant'],self.store.access.keys,now=self.store.clock())
                    directory=self.store.access._directory(a);o=next(v for v in directory['officers'] if v['officer_uid']==body['officer_uid'])
                    member=next((m for m in policy['payload']['accounts'] if m['user_id']==requester['user_id']),None)
                    if not requester['active'] or requester['version']!=req['by']['version'] or not permitted(requester,o) or not member or any(member[k]!=requester[k] for k in ('role','scope_type','scope_id')) or requester['role'] not in policy['payload']['request_roles']:raise AccessError(409,'REQUESTER_PERMISSION_CHANGED')
                    self.disclosure(c,requester,body['officer_uid'],packet['source_public_sha256'])
                    extra=dict(supersedes=f['head'],comparison=req['proposed_comparison'] if body['decision']=='APPROVE' and req['input']['request_kind']=='CORRECTION' else None)
                e=dict(kind=kind,input=deepcopy(body),finding_id=fid,by={k:user[k] for k in ('user_id','username','role','scope_type','scope_id','version')},recorded_at=datetime.fromtimestamp(self.store.clock(),timezone.utc).isoformat(),source_sha256=P.fingerprint(packet),policy_reference=P.fingerprint(policy),**extra)
                if len(rows)>=20000 or len(encoded(e))>8*1024*1024:raise AccessError(422,'REVIEW_STORAGE_LIMIT')
                ident=self.store.index('APPLICATION_REVIEW_OPERATION',body['operation_id'])
                c.execute('INSERT INTO application_review_entries VALUES(?,?,?)',(len(rows)+1,ident,self.store.seal('APPLICATION_REVIEW_ENTRY',ident,e)))
                self.store.event(c,dict(kind='APPLICATION_REVIEW_ENTRY',reference=P.fingerprint(e),operation_id=body['operation_id']))
                check();return self.result(e)
    def disclosure(self,c,user,officer,public):
        ident=self.store.index('GRANT',user['user_id'],officer);row=c.execute('SELECT value FROM disclosures WHERE id=?',(ident,)).fetchone()
        if not row:raise AccessError(403,'DETAILS_WITHHELD')
        g=P.grant(self.store.open('GRANT',ident,row[0]),self.store.keys,self.store.clock())
        from app.security.record_protection import AssignmentProtection,RecordClassification,DisclosureCategory,ProtectionLevel,required_protection
        d=required_protection(assignment=AssignmentProtection(g['assignment']),record_classification=RecordClassification(g['classification']),category=DisclosureCategory.PERSONNEL_DETAILS)
        if g['account_version']!=user['version'] or g['source_public_sha256']!=public or d.level is ProtectionLevel.WITHHOLD or d.level is ProtectionLevel.RESTRICTED and not g['restricted_clearance']:raise AccessError(403,'DETAILS_WITHHELD')
    def inspect(self,token,csrf,body):
        try:
            require(set(body)=={'officer_uid','status','offset'} and body['status'] in ('ALL','PENDING','APPROVE','REJECT','NEEDS_MORE_EVIDENCE') and type(body['offset']) is int and 0<=body['offset']<=20000)
            if body['officer_uid'] is not None:uid(body['officer_uid'])
        except Exception:raise AccessError(400,'INVALID_INSPECTION') from None
        user,p=self.permission(token,csrf)
        if body['officer_uid']:self.source(token,csrf,body['officer_uid'])
        with self.store.transaction() as c:rows=entries(self.store,c)
        fs,rs=state(rows);identities={};packets={}
        for officer in {e['input']['officer_uid'] for e in rows if body['officer_uid'] is None or e['input']['officer_uid']==body['officer_uid']}:
            try:_,packet,i=self.source(token,csrf,officer);identities[officer]=i;packets[officer]=packet
            except AccessError as error:
                if error.status==401:raise
        filtered=[r for r in reversed(list(rs.values())) if r['entry']['input']['officer_uid'] in identities and (body['status']=='ALL' or r['status']==body['status'])]
        items=[]
        for r in filtered[body['offset']:body['offset']+50]:
            req=r['entry'];o=req['input']['officer_uid'];stale=fs[req['finding_id']]['head']!=req['input']['target_head'] or req['source_sha256']!=P.fingerprint(packets[o])
            items.append(dict(**deepcopy(r),identity=identities[o],stale=stale,can_decide=not stale and r['status']=='PENDING' and user['role'] in p['payload']['review_roles'] and user['user_id']!=req['by']['user_id']))
        for o,packet in packets.items():
            if self.source(token,csrf,o)[1]!=packet:raise AccessError(409,'REVIEW_INPUTS_CHANGED')
        if self.permission(token,csrf)!=(user,p):raise AccessError(409,'REVIEW_INPUTS_CHANGED')
        with self.store.transaction() as c:
            if entries(self.store,c)!=rows:raise AccessError(409,'LEDGER_CHANGED_RELOAD')
        return dict(items=items,total=len(filtered),offset=body['offset'],findings=[dict(finding_id=k,**v) for k,v in fs.items() if v['versions'][0]['input']['officer_uid']==body['officer_uid']],operations=[self.result(e) for e in reversed(rows) if e['by']['user_id']==user['user_id'] and e['input']['officer_uid'] in identities][:20])
    def recover(self,token,operation):
        try:uid(operation)
        except Exception:raise AccessError(404,'NOT_FOUND') from None
        u,p=self.permission(token)
        with self.store.transaction() as c:rows=entries(self.store,c)
        e=next((v for v in rows if v['input']['operation_id']==operation),None)
        if not e:raise AccessError(404,'NOT_FOUND')
        self.source(token,None,e['input']['officer_uid'])
        if self.permission(token)!=(u,p):raise AccessError(409,'REVIEW_INPUTS_CHANGED')
        result=self.result(e)
        if e['kind']=='REQUEST':result['status']=state(rows)[1][P.fingerprint(e)]['status']
        return result
