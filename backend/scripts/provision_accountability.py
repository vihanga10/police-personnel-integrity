"""Operator provisioning/renewal for generated-record Stage 1 accounts and logs."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.accountability import AccountabilityStore,configured as log_store,POLICY
from app.access.api import configured_store
from app.access.policy import account,encoded,require
from app.access.store import private

BASE='068502879ec5a8ccd14b9ce6c40f7954b5fa3b4c'

def repository(repo):
    repo=repo.expanduser().absolute()
    require(not any(p.is_symlink() for p in (repo,*repo.parents)))
    def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],text=True,stderr=subprocess.DEVNULL).strip()
    require(git('branch','--show-current')=='feat/identity-resolution' and not git('status','--porcelain'))
    require(subprocess.run(['git','-C',str(repo),'merge-base','--is-ancestor',BASE,'HEAD'],capture_output=True).returncode==0)
    return repo

def write(path,value,new=True):
    data=encoded(value) if type(value) is dict else value
    if new:
        with path.open('xb') as f:
            os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
    else:
        private(path)
        temp=path.with_name(path.name+'.'+uuid4().hex+'.tmp')
        try:
            write(temp,data);os.replace(temp,path)
            fd=os.open(path.parent,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if temp.exists():temp.unlink()

def inputs(repo,root):
    private(root,directory=True,repo=repo)
    manifest=json.loads(private(root/'accounts.json',repo=repo).read_text())
    require(manifest['record_origin']=='GENERATED_RESEARCH_RECORDS' and len(manifest['accounts'])==10)
    cfg=json.loads(private(root/'workspace-config.json',repo=repo).read_text())
    access,_=configured_store(cfg['access_config'])
    require(access.repo==repo.resolve())
    signer=Ed25519PrivateKey.from_private_bytes(private(root/'keys/research-access-signer.key',repo=repo).read_bytes())
    require(signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==access.keys['research-operator-access'])
    return access,signer,cfg,manifest

def envelope(key,payload):
    return {'key_id':'research-operator-access','payload':payload,
            'signature':base64.b64encode(key.sign(encoded(payload))).decode()}

def stored(access,login):
    with access.transaction() as c:
        identity=access.index('USER',login)
        row=c.execute('SELECT version,value FROM users WHERE id=?',(identity,)).fetchone()
        require(row is not None)
        return access.open('USER',identity,row[0],row[1])['grant']['payload']

def reader(access,signer,login):
    p=stored(access,login)
    require(p['role'] in ('HQ_ADMIN','IGP') and p['active'],'Explicit national log reader required')
    now=int(time.time())
    account(envelope(signer,p),access.keys,now=now)
    return envelope(signer,{'policy':POLICY,'kind':'READ_ACCESS_LOGS','user_id':p['user_id'],
        'account_version':p['version'],'issued_at':now-1,'expires_at':min(p['expires_at'],now+86398),
        'review_reference':'GENERATED_RESEARCH_ACCOUNTABILITY_REVIEW'})

def administration(logs,action,outcome,subject=None,reason=None,request_id=None):
    logs.append({'request_id':request_id or str(uuid4()),'action':action,'phase':'ADMINISTRATION','method':'OPERATOR',
      'actor':{'principal_kind':'SIGNING_KEY','key_id':'research-operator-access'},
      'requested_officer_uid':None,'finding_id':None,'operation_id':None,'subject_user_id':subject,
      'peer_reference':None,'status':None,'outcome':outcome,'reason':reason})

def provision(repo,root,login='research.hq'):
    access,signer,cfg,_=inputs(repo,root)
    require('accountability_config' not in cfg)
    paths=[root/'accountability-state',root/'keys/accountability.key',root/'key-backup/accountability.key',
           root/'accountability-config.json',root/'log-reader-grant.json']
    require(all(not p.exists() and not p.is_symlink() for p in paths),'Existing log setup must not be overwritten')
    private(root/'keys',directory=True,repo=repo);private(root/'key-backup',directory=True,repo=repo)
    grant=reader(access,signer,login)
    key=os.urandom(32)
    require(key not in (access.key_path.read_bytes(),private(cfg['key_file'],repo=repo).read_bytes()))
    paths[0].mkdir(mode=0o700);write(paths[1],key);write(paths[2],key)
    write(paths[4],grant)
    config={'policy':'ACCOUNTABILITY_CONFIG_V1','state_directory':str(paths[0]),
            'key_file':str(paths[1]),'reader_grants':[str(paths[4])]}
    write(paths[3],config)
    logs=log_store(paths[3],access=access,workspace_key=cfg['key_file'],workspace_root=cfg['state_directory'],create=True)
    administration(logs,'LOG_READER_GRANT','ALLOWED',grant['payload']['user_id'],'EXPLICIT_SIGNED_LOG_INSPECTION')
    # Existing configuration bytes change only after successful store/grant setup.
    write(root/'workspace-config.json',{**cfg,'accountability_config':str(paths[3])},new=False)
    return {'status':'ACCOUNTABILITY_CONFIGURED','reader_login':login,'legacy_access_events_preserved':True,
            'logs_encrypted':True,'local_integrity_checkpoint':True,'independently_anchored':False,
            'personnel_connected':False,'original_data_or_chain_modified':False}

def renew(repo,root,login,accounts=False):
    access,signer,cfg,manifest=inputs(repo,root)
    require('accountability_config' in cfg)
    logs=log_store(cfg['accountability_config'],access=access,workspace_key=cfg['key_file'],workspace_root=cfg['state_directory'])
    if accounts:
        issued=int(time.time())-1
        for row in manifest['accounts']:
            p=stored(access,row['username']);require(p['user_id']==row['user_id'])
            ident=str(uuid4())
            administration(logs,'ACCOUNT_RENEWAL','ATTEMPT',p['user_id'],'SIGNED_ACCOUNT_RENEWAL',ident)
            access.put_account(envelope(signer,{**p,'issued_at':issued,'expires_at':issued+86400,'version':p['version']+1}))
            administration(logs,'ACCOUNT_RENEWAL','ALLOWED',p['user_id'],'SIGNED_ACCOUNT_RENEWAL',ident)
    grant=reader(access,signer,login)
    ident=str(uuid4())
    administration(logs,'LOG_READER_GRANT','ATTEMPT',grant['payload']['user_id'],'SIGNED_LOG_READER_RENEWAL',ident)
    # Never substitute an arbitrary file from a configuration into an overwrite.
    require(logs.grant_files==(str(root/'log-reader-grant.json'),))
    write(root/'log-reader-grant.json',grant,new=False)
    administration(logs,'LOG_READER_GRANT','ALLOWED',grant['payload']['user_id'],'SIGNED_LOG_READER_RENEWAL',ident)
    return {'status':'ACCOUNTS_AND_LOG_READER_RENEWED' if accounts else 'LOG_READER_RENEWED',
      'new_sign_in_required':True,'connected_disclosures_require_new_account_versions':accounts,
      'original_data_or_chain_modified':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('check','provision','renew-reader','renew-accounts'))
    p.add_argument('--repository',type=Path,required=True);p.add_argument('--state-root',type=Path)
    p.add_argument('--reader-login',default='research.hq')
    args=p.parse_args();stage='SOURCE_CHECK'
    try:
        repo=repository(args.repository)
        if args.action=='check':
            require(args.state_root is None);print('Source check PASSED. No private state changed.');return
        require(args.state_root is not None)
        os.umask(0o077);root=args.state_root.expanduser().absolute();stage='PRIVATE_ACCOUNTABILITY_SETUP'
        result=provision(repo,root,args.reader_login) if args.action=='provision' else renew(repo,root,args.reader_login,args.action=='renew-accounts')
        print(json.dumps(result,indent=2))
        print('Private keys, passwords and database contents were not printed. Restart the server and sign in again.')
    except Exception:
        print(json.dumps({'status':'STOPPED','stage':stage,'original_data_or_chain_modified':False,
                         'partial_private_setup_may_exist':stage!='SOURCE_CHECK'}))
        raise SystemExit(2)

if __name__=='__main__':main()
