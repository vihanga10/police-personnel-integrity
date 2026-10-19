"""Migrate signed login/detail/log permissions to until-revoked research access.

Stopped application only. Original source data, TOTP factors, password records,
review policy, officer scopes and chain journals are preserved.
"""
import argparse,fcntl,hashlib,json,os,secrets,sqlite3,sys
from pathlib import Path
from datetime import datetime,timezone
from uuid import uuid4
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
import _unit_setup_support as S
import setup_unit_sdig_totp as U
from app.access import policy as A,research_policy as P,accountability as L
from app.access.store import private

POLICY='SIGNED_UNTIL_REVOKED_ACCESS_MIGRATION_V1'

def plan(x,c):
    now=int(x.a.clock());x.a._verify_audit(c);x.w._events(U.SQL(c,'ui'));x.l.verify(U.SQL(c,'logs'),recover=False)
    directory=x.a._directory(c);members={o['officer_uid']:o for o in directory['officers']}
    declared={u['username']:u for u in x.manifest['accounts']};oldusers={};updates=[];freshusers={};already=True;issued_values=[]
    for ident,owner,version,blob in c.execute('SELECT id,owner,version,value FROM users'):
        value=x.a.open('USER',ident,version,blob);p=A.account(value['grant'],x.a.keys,now=value['grant']['payload']['issued_at'])
        A.require(p['username'] in declared and all(p[k]==declared[p['username']][k] for k in ('user_id','username','role','scope_type','scope_id','active','version')),'Existing account manifest differs')
        A.require(ident==x.a.index('USER',p['username']) and owner==x.a.index('OWNER',p['user_id']) and version==p['version'],'Account binding differs')
        A.require(p['issued_at']<=now,'Future account issue time');issued_values.append(p['issued_at'])
        oldusers[p['user_id']]=p;already=already and p['policy']==A.PERSISTENT_ACCOUNT_POLICY
        fresh={**p,'policy':A.PERSISTENT_ACCOUNT_POLICY,'issued_at':now,'expires_at':None,'version':version+1}
        env=S.sign(x.ask,x.access_id,fresh);A.account(env,x.a.keys,now=now)
        freshusers[p['user_id']]=fresh;updates.append((ident,version,blob,fresh,{**value,'grant':env}))
    A.require(len(updates)==len(declared) and len(updates) in (10,12),'Account inventory differs')
    grants=[]
    for ident,issued,blob in c.execute('SELECT id,issued,value FROM ui.disclosures'):
        env=x.w.open('GRANT',ident,blob);p=P.grant(env,x.w.keys,env['payload']['issued_at']);u=oldusers.get(p['user_id'])
        A.require(u is not None and ident==x.w.index('GRANT',p['user_id'],p['officer_uid']) and issued==p['issued_at'],'Disclosure binding differs')
        A.require(p['officer_uid'] in members and p['source_public_sha256']==directory['source_public_sha256'],'Disclosure source differs')
        if not u['active'] or not A.permitted(u,members[p['officer_uid']]):continue
        A.require(p['account_version']==u['version'] and p['issued_at']<=now,'Current disclosure version required; inspect first')
        issued_values.append(p['issued_at']);already=already and p['policy']==P.PERSISTENT_DISCLOSURE_POLICY
        fresh={**p,'policy':P.PERSISTENT_DISCLOSURE_POLICY,'issued_at':now,'expires_at':None,'account_version':freshusers[u['user_id']]['version']}
        env=S.sign(x.wsk,x.workspace_id,fresh);P.grant(env,x.w.keys,now);grants.append((ident,env))
    readerfiles=[]
    for file in x.l.grant_files:
        p=x.l.load_grant(file,check_time=False);u=oldusers.get(p['user_id'])
        A.require(u is not None and u['active'] and p['account_version']==u['version'] and p['issued_at']<=now,'Log reader binding differs')
        issued_values.append(p['issued_at']);already=already and p['policy']==L.PERSISTENT_READER_POLICY
        fresh={**p,'policy':L.PERSISTENT_READER_POLICY,'issued_at':now,'expires_at':None,'account_version':freshusers[u['user_id']]['version']}
        readerfiles.append((file,S.sign(x.ask,x.access_id,fresh)))
    summary=dict(accounts=len(updates),active_accounts=sum(u['active'] for u in oldusers.values()),inactive_accounts=sum(not u['active'] for u in oldusers.values()),daily_access_expiry_removed=True,access_valid_until='EXPLICIT_REVOCATION_OR_POLICY_CHANGE',session_minutes=30,totp_preserved=True,passwords_preserved=True,roles_and_scopes_preserved=True,personnel_records_changed=False,chain_transactions_submitted=0)
    if already:return dict(already=True,summary=summary)
    A.require(max(issued_values)<now,'WAIT_FOR_NEXT_SECOND_BEFORE_MIGRATION')
    manifest={**x.manifest,'accounts':[freshusers[declared[name]['user_id']] for name in declared]}
    files=[(x.root/'accounts.json',manifest),*readerfiles]
    jobs=[dict(path=str(f),old_sha=hashlib.sha256(private(f,repo=x.repo).read_bytes()).hexdigest(),new=v) for f,v in files]
    return dict(already=False,summary=summary,updates=updates,grants=grants,files=jobs)

def finish(x,d,job):
    result=U.finalize(x,d,job)
    return {**result,'status':'SIGNED_UNTIL_REVOKED_ACCESS_ENABLED','sign_in_again':True}

def execute(x):
    bank=x.root/'persistent-access-attempts'
    if not bank.exists():bank.mkdir(mode=0o700)
    private(bank,directory=True,repo=x.repo)
    for other in (x.root/'unit-sdig-totp-attempts',bank):
        if other.exists():
            for directory in other.iterdir():
                old=S.job_read(x,directory)
                if old['phase'] not in ('COMPLETED','ROLLED_BACK'):x.recovery_attempt=directory;raise ValueError('RECOVER_PREVIOUS_ATTEMPT_FIRST')
    c=S.connect(x,False);d=None;committed=False
    try:
        p=plan(x,c)
        if p['already']:c.rollback();return dict(status='SIGNED_UNTIL_REVOKED_ACCESS_ALREADY_CONFIGURED',**p['summary'],private_state_changed=False)
        A.require(all(hashlib.sha256(private(f,repo=x.repo).read_bytes()).hexdigest()==pin for f,pin in x.pins.items()),'Private configuration changed')
        d=bank/str(uuid4());d.mkdir(mode=0o700);x.recovery_attempt=d
        job=dict(policy=POLICY,phase='PREPARED',versions=[[i,u['version']] for i,_,_,u,_ in p['updates']],old_versions=[[i,v] for i,v,_,_,_ in p['updates']],files=p['files'],summary=p['summary']);S.job_write(x,d,job)
        for name,file in [('access.sqlite3',x.a.path),('workspace.sqlite3',x.w.path),('accountability.sqlite3',x.l.db)]:
            target=d/name;S.write_new(target,b'');src=sqlite3.connect(file.as_uri()+'?mode=ro',uri=True);dst=sqlite3.connect(target)
            try:src.backup(dst)
            finally:src.close();dst.close()
        for ident,version,old,u,value in p['updates']:
            changed=c.execute('UPDATE users SET version=?,value=? WHERE id=? AND version=? AND value=?',(u['version'],x.a.seal('USER',ident,u['version'],value),ident,version,old));A.require(changed.rowcount==1,'Account changed concurrently');x.a._audit(c,'ACCOUNT_VERSION',ident)
        for ident,env in p['grants']:c.execute('UPDATE ui.disclosures SET issued=?,value=? WHERE id=?',(env['payload']['issued_at'],x.w.seal('GRANT',ident,env),ident))
        c.execute('DELETE FROM sessions')
        previous=c.execute('SELECT digest FROM ui.events ORDER BY seq DESC LIMIT 1').fetchone();previous=previous[0] if previous else '0'*64;seq=c.execute('SELECT COUNT(*) FROM ui.events').fetchone()[0]+1
        value=dict(kind='ACCESS_LIFETIME_POLICY',reference=POLICY,operation_id=d.name);blob=x.w.seal('EVENT',seq,value);c.execute('INSERT INTO ui.events VALUES(?,?,?,?)',(seq,previous,blob,x.w.index(seq,previous,blob.hex())))
        rows,head=x.l.verify(U.SQL(c,'logs'),recover=False);seq=len(rows)+1
        event=dict(policy=L.POLICY,event_id=str(uuid4()),recorded_at=datetime.now(timezone.utc).isoformat(),action='ACCOUNT_RENEWAL',phase='ADMINISTRATION',method='OPERATOR',request_id=str(uuid4()),operation_id=d.name,actor={'principal_kind':'SIGNING_KEY','key_id':x.access_id},outcome='ALLOWED',reason='SIGNED_UNTIL_REVOKED_ACCESS_MIGRATION')
        nonce=secrets.token_bytes(12);blob=nonce+x.l.aead.encrypt(nonce,A.encoded(event),A.encoded([L.POLICY,seq,head]));c.execute('INSERT INTO logs.events VALUES(?,?,?,?)',(seq,head,blob,x.l.digest('EVENT',[seq,head,blob.hex()])))
        c.commit();committed=True;job['phase']='DATABASES_COMMITTED';S.job_write(x,d,job)
    except BaseException:
        if not committed:
            c.rollback()
            if d is not None:
                check=S.connect(x,True)
                try:old=all(check.execute('SELECT version FROM users WHERE id=?',(i,)).fetchone()==(v,) for i,v in job['old_versions'])
                finally:check.close()
                if old:job['phase']='ROLLED_BACK';S.job_write(x,d,job)
        raise
    finally:c.close()
    return finish(x,d,job)

def recover(x,d):
    private(d,directory=True,repo=x.repo);A.require(d.parent==x.root/'persistent-access-attempts','Exact migration attempt required');job=S.job_read(x,d);A.require(job['policy']==POLICY,'Recovery domain differs')
    c=S.connect(x,True)
    try:old=all(c.execute('SELECT version FROM users WHERE id=?',(i,)).fetchone()==(v,) for i,v in job['old_versions'])
    finally:c.close()
    if old:job['phase']='ROLLED_BACK';S.job_write(x,d,job);return dict(status='ROLLED_BACK_SAFE_TO_EXECUTE')
    return finish(x,d,job)

def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--preview',action='store_true');g.add_argument('--execute',action='store_true');g.add_argument('--recover',type=Path)
    p.add_argument('--repository',type=Path,default=Path.home()/'Developer/police-personnel-integrity');p.add_argument('--app-root',type=Path,default=Path.home()/'ResearchKeys/police-personnel-integrity/research-app-v1');a=p.parse_args();os.umask(0o077)
    x=S.load(a.repository.resolve(),a.app_root.absolute())
    fd=os.open(x.root/'unit-sdig-totp.lock',os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.preview:
            c=S.connect(x,True)
            try:job=plan(x,c)
            finally:c.close()
            result=dict(status='UNTIL_REVOKED_ACCESS_PREVIEW_PASSED',**job['summary'],private_state_changed=False)
        else:result=recover(x,a.recover.absolute()) if a.recover else execute(x)
    finally:os.close(fd)
    print(json.dumps(result,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='STOPPED',error_type=type(e).__name__,reason=str(e) if str(e) in ('RECOVER_PREVIOUS_ATTEMPT_FIRST','STOP_APPLICATION_FIRST','WAIT_FOR_NEXT_SECOND_BEFORE_MIGRATION') else 'PRESERVE_PRIVATE_STATE_AND_INSPECT',chain_transactions_submitted=0)));raise SystemExit(1)
