"""Stopped-app unit-scope/TOTP migration for generated records; encrypted recovery.
Existing source profiles, histories, findings and past logs remain unchanged.
Existing until-revoked lifetime policies are preserved when rerun; TOTP seeds persist.
"""
import argparse,base64,hashlib,json,os,secrets,sqlite3,sys,time,fcntl
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import quote
sys.dont_write_bytecode=True
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
import _unit_setup_support as S
from app.access import policy as A,research_policy as P,full_source_profiles as F,totp,review_workflow as W,accountability as L
from app.access.store import private,password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

UNIT_ACCOUNTS={'research.sdig':'CID','research.sdig.ccib':'CCIB','research.sdig.criminal':'CRIMINAL_DIVISION'}
EXPECTED={'CID':150,'CCIB':149,'CRIMINAL_DIVISION':705}

class SQL:
    def __init__(self,c,prefix):self.c,self.prefix=c,prefix
    def execute(self,sql,args=()):
        for table in ('application_review_policies','events'):
            sql=sql.replace('FROM '+table,'FROM '+self.prefix+'.'+table)
        return self.c.execute(sql,args)

def plan(x,c,expected=EXPECTED):
    now=int(time.time());persistent=any(u['policy']==A.PERSISTENT_ACCOUNT_POLICY for u in x.manifest['accounts'])
    A.require(not persistent or all(u['policy']==A.PERSISTENT_ACCOUNT_POLICY for u in x.manifest['accounts']),'Mixed account lifetime policies')
    expiry=None if persistent else now+86398
    x.a._verify_audit(c);x.w._events(SQL(c,'ui'));x.l.verify(SQL(c,'logs'),recover=False)
    directory=x.a._directory(c)
    A.require(directory['policy']==A.RETAINED_DIRECTORY_POLICY,'Retained generated membership required')
    row=c.execute('SELECT generation,value FROM ui.source_profile_sets ORDER BY generation DESC LIMIT 1').fetchone()
    A.require(row,'Connected full source profiles required')
    meta=F.signed(x.w.open('SOURCE_SET',row[0],row[1]),x.w.keys,'SOURCE_SET',now)
    A.require(meta['generation']==row[0] and meta['source_public_sha256']==directory['source_public_sha256'],'Profile source differs')
    units={};seen=set()
    for ident,blob in c.execute('SELECT id,value FROM ui.source_profiles WHERE generation=?',(row[0],)):
        A.require(ident in meta['profiles'] and ident not in seen,'Unexpected source profile');seen.add(ident)
        envelope=x.w.open('SOURCE_PROFILE',[row[0],ident],blob)
        A.require(P.fingerprint(envelope)==meta['profiles'][ident],'Source digest differs')
        p=F.validate_profile(envelope,x.w.keys,now)
        A.require(all(p[k]==meta[k] for k in ('generation','source_public_sha256','source_context_sha256')) and
                  ident==x.w.index('SOURCE_PROFILE',p['officer_uid']),'Source context differs')
        service=[r for r in p['full_records'] if r['dataset']=='officer_service_information.csv']
        A.require(len(service)==1,'Unresolved unit source')
        u=service[0]['fields'].get('current_unit_type')
        units[p['officer_uid']]={'CID':'CID','CCIB':'CCIB','Criminal Division':'CRIMINAL_DIVISION'}.get(u)
    A.require(seen==set(meta['profiles']) and set(units)=={o['officer_uid'] for o in directory['officers']},'Complete connected directory required')
    counts={unit:sum(v==unit for v in units.values()) for unit in EXPECTED}
    if expected is not None:A.require(counts==expected,'Connected unit counts differ from reviewed 150/149/705; inspect first')
    fresh_directory={**directory,'generation':directory['generation']+1,'issued_at':now,
        'review_reference':'GENERATED_UNIT_MEMBERSHIP_V1',
        'officers':[{**o,'membership':{**o['membership'],'UNIT':units[o['officer_uid']]}} for o in directory['officers']]}
    directory_env=S.sign(x.ask,x.access_id,fresh_directory)
    from app.access.directory import validate_directory
    validate_directory(directory_env,x.a.keys,now=now)
    members={o['officer_uid']:o for o in fresh_directory['officers']}
    declared={p['username']:p for p in x.manifest['accounts']}
    oldusers={};newusers={};updates=[];passwords=json.loads(private(x.root/'credentials.json',repo=x.repo).read_text())
    A.require(isinstance(passwords,dict),'Credential inventory differs')
    for ident,owner,version,blob in c.execute('SELECT id,owner,version,value FROM users'):
        value=x.a.open('USER',ident,version,blob);p=A.account(value['grant'],x.a.keys,now=value['grant']['payload']['issued_at'])
        A.require(p['username'] in declared and p['version']==version and ident==x.a.index('USER',p['username']) and owner==x.a.index('OWNER',p['user_id']) and
            all(p[k]==declared[p['username']][k] for k in ('user_id','role','scope_type','scope_id','active')),'Existing account policy changed')
        A.require(p['username'] not in oldusers and p['username'] in passwords,'Duplicate or missing account')
        oldusers[p['username']]=p
        fresh={**p,'version':version+1,'issued_at':now-1,'expires_at':expiry}
        if p['username'] in UNIT_ACCOUNTS:
            A.require(p['role']=='SDIG' and p['active'],'Unit account must remain active SDIG')
            fresh.update(scope_type='UNIT',scope_id=UNIT_ACCOUNTS[p['username']],review_reference='GENERATED_UNIT_SCOPE_V1')
        A.account(S.sign(x.ask,x.access_id,fresh),x.a.keys,now=now);newusers[p['username']]=fresh
        updates.append((ident,version,blob,fresh,{**value,'grant':S.sign(x.ask,x.access_id,fresh)}))
    A.require(set(oldusers)==set(declared) and 'research.sdig' in oldusers,'Account manifest differs')
    for login,unit in UNIT_ACCOUNTS.items():
        if login in newusers:continue
        fresh=dict(policy=A.PERSISTENT_ACCOUNT_POLICY if persistent else A.POLICY,kind='ACCOUNT',issued_at=now-1,expires_at=expiry,user_id=str(uuid4()),username=login,
                   role='SDIG',scope_type='UNIT',scope_id=unit,version=1,active=True,review_reference='GENERATED_UNIT_SCOPE_V1')
        password=secrets.token_urlsafe(24);passwords[login]=password;newusers[login]=fresh
        ident=x.a.index('USER',login)
        updates.append((ident,None,None,fresh,dict(grant=S.sign(x.ask,x.access_id,fresh),password=password_hash(password))))
    A.require(len(newusers)==12 and sum(p['active'] for p in newusers.values())==11,'Expected twelve accounts with one inactive')
    byid={p['user_id']:p for p in newusers.values()};oldbyid={p['user_id']:p for p in oldusers.values()}
    grants={};templates={}
    for ident,issued,blob in c.execute('SELECT id,issued,value FROM ui.disclosures'):
        env=x.w.open('GRANT',ident,blob);p=P.grant(env,x.w.keys,env['payload']['issued_at'])
        A.require(p['policy'] in (P.RETAINED_POLICY,P.PERSISTENT_DISCLOSURE_POLICY) and p['source_public_sha256']==meta['source_public_sha256'] and
                  ident==x.w.index('GRANT',p['user_id'],p['officer_uid']) and issued==p['issued_at'],'Disclosure source differs')
        user=byid.get(p['user_id']);A.require(user and p['officer_uid'] in members,'Disclosure owner differs')
        if oldbyid.get(p['user_id'],{}).get('role')=='HQ_ADMIN':templates[p['officer_uid']]=p
        if not user['active'] or not A.permitted(user,members[p['officer_uid']]):continue
        fresh={**p,'policy':P.PERSISTENT_DISCLOSURE_POLICY if persistent else P.RETAINED_POLICY,'issued_at':now,'expires_at':expiry,'account_version':user['version']}
        if not persistent:fresh.update(request_reviews=False,reviewer_uid=None)
        grants[ident]=S.sign(x.wsk,x.workspace_id,fresh)
    for login,unit in UNIT_ACCOUNTS.items():
        user=newusers[login]
        for officer,member in members.items():
            if not A.permitted(user,member):continue
            A.require(officer in templates,'Existing HQ detail assessment required for every unit officer')
            p=templates[officer]
            fresh={**p,'policy':P.PERSISTENT_DISCLOSURE_POLICY if persistent else P.RETAINED_POLICY,'user_id':user['user_id'],'account_version':user['version'],'issued_at':now,'expires_at':expiry,
                   'request_reviews':False,'reviewer_uid':None}
            # Explicit generated unit clearance: retain assessed protection labels.
            from app.access.full_source_profiles import grant_allows
            A.require(grant_allows(fresh,user,meta['source_public_sha256']),'Existing assessment withholds unit details')
            ident=x.w.index('GRANT',user['user_id'],officer);grants[ident]=S.sign(x.wsk,x.workspace_id,fresh)
    for env in grants.values():P.grant(env,x.w.keys,now)
    readerfiles=[]
    for file in x.l.grant_files:
        p=x.l.load_grant(file,check_time=False);user=byid.get(p['user_id']);A.require(user and user['active'],'Log reader owner differs')
        readerfiles.append((file,S.sign(x.ask,x.access_id,{**p,'policy':L.PERSISTENT_READER_POLICY if persistent else p['policy'],'account_version':user['version'],'issued_at':now-1,'expires_at':expiry})))
    wc=json.loads(private(x.root/'workspace-config.json',repo=x.repo).read_text())
    x.w.review_keys={k:base64.b64decode(v,validate=True) for k,v in wc['review_workflow_keys'].items()}
    seed=private(x.root/'keys/research-review-policy.key',repo=x.repo).read_bytes()
    A.require(seed==private(x.root/'key-backup/research-review-policy.key',repo=x.repo).read_bytes(),'Review key backup differs')
    key=Ed25519PrivateKey.from_private_bytes(seed)
    keyid=next((k for k,v in x.w.review_keys.items() if v==key.public_key().public_bytes_raw()),None)
    A.require(keyid,'Existing reviewer trust required')
    policies=W.policies(x.w,SQL(c,'ui'));A.require(policies,'Existing review policy required')
    p=policies[-1]['payload'];review={**p,'version':p['version']+1,'supersedes':P.fingerprint(policies[-1]),'issued_at':now,
        'reason':'Generated unit-scoped SDIG accounts; retained independent-review rules.',
        'accounts':[{k:u[k] for k in ('user_id','role','scope_type','scope_id')} for u in newusers.values() if u['active']]}
    policy=S.sign(key,keyid,review)
    enabled=totp.required(x.a,c);factors=[];enrollment=[]
    for ident,_,_,u,_ in updates:
        row=c.execute('SELECT value FROM totp_factors WHERE id=?',(ident,)).fetchone() if enabled else None
        if row:
            factor=x.a.open('TOTP_FACTOR',ident,1,row[0]);A.require(factor['user_id']==u['user_id'],'TOTP owner differs')
        else:factor=dict(policy='APPLICATION_TOTP_V1',user_id=u['user_id'],seed=base64.b32encode(secrets.token_bytes(20)).decode(),last_counter=-1)
        factors.append((ident,factor))
        if u['active']:
            label='Police Personnel Integrity:'+u['username']
            enrollment.append(dict(username=u['username'],secret=factor['seed'],issuer='Police Personnel Integrity',
                algorithm='SHA1',digits=6,period=30,otpauth_uri='otpauth://totp/'+quote(label,safe='')+'?secret='+factor['seed']+'&issuer=Police%20Personnel%20Integrity&algorithm=SHA1&digits=6&period=30'))
    manifest={**x.manifest,'scope_basis':'SIGNED_GENERATED_UNIT_AND_EXISTING_GEOGRAPHIC_SCOPES','accounts':list(newusers.values())}
    access_path=Path(wc['access_config']);access_config=json.loads(private(access_path,repo=x.repo).read_text())
    files=[(access_path,{**access_config,'totp_required':True}),(x.root/'accounts.json',manifest),(x.root/'credentials.json',passwords),
           (x.root/'totp-enrollment-private.json',dict(policy='APPLICATION_TOTP_ENROLLMENT_V1',accounts=enrollment))]+readerfiles
    filejobs=[dict(path=str(path),old_sha=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,new=value) for path,value in files]
    return dict(directory=directory_env,updates=updates,grants=grants,policy=policy,factors=factors,files=filejobs,
        summary=dict(accounts=12,active_accounts=11,inactive_accounts=1,unit_counts=counts,
             unit_accounts=UNIT_ACCOUNTS,totp_required=True,authorization_expires_at_utc=datetime.fromtimestamp(expiry,timezone.utc).isoformat() if expiry is not None else None,
             sessions_minutes=30,original_passwords_preserved=True,police_authority_issued=False,source_reimported=False,chain_submitted=False))

def finalize(x,directory,job):
    c=S.connect(x,True)
    try:
        A.require(all(c.execute('SELECT version FROM users WHERE id=?',(i,)).fetchone()==(v,) for i,v in job['versions']),'Committed account state differs')
        rows,head=x.l.verify(SQL(c,'logs'),recover=False)
        A.require(sum(e.get('operation_id')==directory.name for _,e in rows)==1,'Committed operation missing')
    finally:c.close()
    for item in job['files']:
        path=Path(item['path']);new=A.encoded(item['new'])
        if path.exists():
            private(path,repo=x.repo);digest=hashlib.sha256(path.read_bytes()).hexdigest()
            A.require(digest in (item['old_sha'],hashlib.sha256(new).hexdigest()),'Private output changed; inspect recovery')
            if digest==hashlib.sha256(new).hexdigest():continue
        else:A.require(item['old_sha'] is None,'Private output missing')
        tmp=path.parent/('unit-setup-'+secrets.token_hex(8)+'.tmp');S.write_new(tmp,new);os.replace(tmp,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    x.l._checkpoint(len(rows),head);job['phase']='COMPLETED';S.job_write(x,directory,job)
    return dict(status='UNIT_SDIG_TOTP_SETUP_PASSED',**job['summary'],recovery_attempt=str(directory),sign_in_again=True)

def execute(x,expected=EXPECTED):
    bank=x.root/'unit-sdig-totp-attempts'
    if bank.exists():
        private(bank,directory=True,repo=x.repo)
        for d in bank.iterdir():
            old=S.job_read(x,d)
            if old['phase'] not in ('COMPLETED','ROLLED_BACK'):
                x.recovery_attempt=d;raise ValueError('RECOVER_PREVIOUS_ATTEMPT_FIRST')
    else:bank.mkdir(mode=0o700)
    c=S.connect(x,False);d=None;committed=False
    try:
        p=plan(x,c,expected);A.require(all(hashlib.sha256(Path(f).read_bytes()).hexdigest()==h for f,h in x.pins.items()),'Private configuration changed')
        d=bank/str(uuid4());d.mkdir(mode=0o700);x.recovery_attempt=d
        job=dict(policy='UNIT_SDIG_TOTP_SETUP_V1',phase='PREPARED',versions=[[i,u['version']] for i,_,_,u,_ in p['updates']],
                 old_versions=[[i,v] for i,v,_,_,_ in p['updates']],files=p['files'],summary=p['summary'])
        S.job_write(x,d,job)
        for name,path in [('access.sqlite3',x.a.path),('workspace.sqlite3',x.w.path),('accountability.sqlite3',x.l.db)]:
            target=d/name;S.write_new(target,b'');src=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True);dst=sqlite3.connect(target)
            try:src.backup(dst)
            finally:dst.close();src.close()
        for ident,version,old,u,value in p['updates']:
            blob=x.a.seal('USER',ident,u['version'],value)
            if version is None:c.execute('INSERT INTO users VALUES(?,?,?,?)',(ident,x.a.index('OWNER',u['user_id']),u['version'],blob))
            else:
                changed=c.execute('UPDATE users SET version=?,value=? WHERE id=? AND version=? AND value=?',(u['version'],blob,ident,version,old))
                A.require(changed.rowcount==1,'Concurrent account change')
            x.a._audit(c,'ACCOUNT_VERSION',ident)
        env=p['directory'];generation=env['payload']['generation']
        c.execute('UPDATE directory SET version=?,value=? WHERE id=1',(generation,x.a.seal('DIRECTORY',1,generation,env)))
        x.a._audit(c,'DIRECTORY_GENERATION',x.a.index('DIRECTORY',generation))
        for ident,env in p['grants'].items():c.execute('INSERT INTO ui.disclosures VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET issued=excluded.issued,value=excluded.value',(ident,env['payload']['issued_at'],x.w.seal('GRANT',ident,env)))
        version=p['policy']['payload']['version']
        c.execute('INSERT INTO ui.application_review_policies VALUES(?,?)',(version,x.w.seal('APPLICATION_REVIEW_POLICY',version,p['policy'])))
        W.policies(x.w,SQL(c,'ui'))
        for stmt in totp.SCHEMA.split(';'):
            if stmt.strip():c.execute(stmt)
        c.execute('INSERT OR REPLACE INTO totp_control VALUES(1,?)',(x.a.seal('TOTP_CONTROL',1,1,dict(policy='APPLICATION_TOTP_V1',required=True)),))
        for ident,factor in p['factors']:c.execute('INSERT OR REPLACE INTO totp_factors VALUES(?,?)',(ident,x.a.seal('TOTP_FACTOR',ident,1,factor)))
        c.execute('DELETE FROM sessions')
        previous=c.execute('SELECT digest FROM ui.events ORDER BY seq DESC LIMIT 1').fetchone();previous=previous[0] if previous else '0'*64
        seq=c.execute('SELECT COUNT(*) FROM ui.events').fetchone()[0]+1
        event=dict(kind='APPLICATION_REVIEW_POLICY',version=version,reference=P.fingerprint(p['policy']),operation_id=d.name)
        blob=x.w.seal('EVENT',seq,event);c.execute('INSERT INTO ui.events VALUES(?,?,?,?)',(seq,previous,blob,x.w.index(seq,previous,blob.hex())))
        rows,head=x.l.verify(SQL(c,'logs'),recover=False);seq=len(rows)+1
        event=dict(policy='PERSONNEL_ACCOUNTABILITY_V1',event_id=str(uuid4()),recorded_at=datetime.now(timezone.utc).isoformat(),
              action='ACCOUNT_RENEWAL',phase='ADMINISTRATION',method='OPERATOR',request_id=str(uuid4()),operation_id=d.name,
              actor={'principal_kind':'SIGNING_KEY','key_id':x.access_id},outcome='ALLOWED',reason='GENERATED_UNIT_SCOPE_AND_TOTP_SETUP')
        nonce=secrets.token_bytes(12);blob=nonce+x.l.aead.encrypt(nonce,A.encoded(event),A.encoded(['PERSONNEL_ACCOUNTABILITY_V1',seq,head]))
        c.execute('INSERT INTO logs.events VALUES(?,?,?,?)',(seq,head,blob,x.l.digest('EVENT',[seq,head,blob.hex()])))
        c.commit();committed=True;job['phase']='DATABASES_COMMITTED';S.job_write(x,d,job)
    except BaseException:
        if not committed:
            c.rollback()
            if d is not None:
                check=S.connect(x,True)
                try:old=all(check.execute('SELECT version FROM users WHERE id=?',(i,)).fetchone()==((v,) if v is not None else None) for i,v in job['old_versions'])
                finally:check.close()
                if old:job['phase']='ROLLED_BACK';S.job_write(x,d,job)
        raise
    finally:c.close()
    return finalize(x,d,job)

def recover(x,d):
    private(d,directory=True,repo=x.repo);A.require(d.parent==x.root/'unit-sdig-totp-attempts','Exact attempt required')
    job=S.job_read(x,d);A.require(job['policy']=='UNIT_SDIG_TOTP_SETUP_V1','Recovery domain differs')
    c=S.connect(x,True)
    try:
        if all(c.execute('SELECT version FROM users WHERE id=?',(i,)).fetchone()==((v,) if v is not None else None) for i,v in job['old_versions']):
            job['phase']='ROLLED_BACK';S.job_write(x,d,job);return dict(status='ROLLED_BACK_SAFE_TO_EXECUTE')
    finally:c.close()
    return finalize(x,d,job)

def main():
    parser=argparse.ArgumentParser(description=__doc__);m=parser.add_mutually_exclusive_group(required=True)
    m.add_argument('--preview',action='store_true');m.add_argument('--execute',action='store_true');m.add_argument('--recover',type=Path)
    parser.add_argument('--repository',type=Path,default=Path.home()/'Developer/police-personnel-integrity')
    parser.add_argument('--app-root',type=Path,default=Path.home()/'ResearchKeys/police-personnel-integrity/research-app-v1')
    args=parser.parse_args();os.umask(0o077)
    try:
        x=S.load(args.repository.expanduser().resolve(),args.app_root.expanduser().absolute())
        if args.preview:
            c=S.connect(x,True)
            try:p=plan(x,c)
            finally:c.close()
            result=dict(status='UNIT_SDIG_TOTP_PREVIEW_PASSED',**p['summary'],private_state_changed=False)
        else:
            path=x.root/'unit-sdig-totp.lock'
            if path.exists():private(path,repo=x.repo)
            fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                result=recover(x,args.recover.expanduser().absolute()) if args.recover else execute(x)
            finally:os.close(fd)
        print(json.dumps(result,indent=2));return 0
    except Exception as e:
        print(json.dumps(dict(status='STOPPED',error_type=type(e).__name__,reason=(str(e) if str(e) in {'Connected unit counts differ from reviewed 150/149/705; inspect first','Connected full source profiles required','Existing HQ detail assessment required for every unit officer','Existing assessment withholds unit details','Complete connected directory required','RECOVER_PREVIOUS_ATTEMPT_FIRST','STOP_APPLICATION_FIRST'} else 'PRIVATE_SETUP_REQUIRES_INSPECTION'),
             recovery_attempt=str(getattr(locals().get('x'),'recovery_attempt','')) or None,chain_submitted=False),indent=2));return 2

if __name__=='__main__':raise SystemExit(main())
