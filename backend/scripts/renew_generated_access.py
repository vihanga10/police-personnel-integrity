"""Explicit one-day renewal of the same generated simulation accounts and HQ log reader.

No account/scope/password changes, no new disclosure or police action authority.
The subsequent history import renews existing source disclosure settings.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access import generated_connection as G, research_connection as C
from app.access import research_connection_runtime as R
from app.access.policy import account,require

def renew(repo,app_root):
    repo=Path(repo).resolve();app_root=Path(app_root).absolute();C.revision(repo)
    from provision_generated_connection import stopped_app
    stopped_app(repo,app_root)
    from app.access.research_app import configured
    store,_=configured(app_root/'workspace-config.json');access=store.access;logs=store.accountability
    require(logs is not None)
    manifest=R.read_json(app_root/'accounts.json',repo)
    require(manifest['record_origin']=='GENERATED_RESEARCH_RECORDS' and len(manifest['accounts'])==10)
    signer=R.signer(app_root/'keys/research-access-signer.key',repo)
    require(access.keys[G.ACCESS_ID]==G.public(signer))
    now=int(time.time());readers=[];versions={};users=[]
    # Validate every existing log reader before any update; only those identities
    # already granted log inspection can receive its one-day renewal.
    for file in logs.grant_files:
        value=logs.load_grant(file,check_time=False);require(value['issued_at']<=now)
        readers.append((Path(file),value))
    with access.transaction() as database:
        for declared in manifest['accounts']:
            ident=access.index('USER',declared['username'])
            row=database.execute('SELECT version,value FROM users WHERE id=?',(ident,)).fetchone();require(row is not None)
            old=access.open('USER',ident,row[0],row[1]);envelope=old['grant'];p=envelope['payload']
            require(type(p['issued_at']) is int and p['issued_at']<=now)
            p=account(envelope,access.keys,now=p['issued_at'])
            require(p['version']==row[0] and all(p[k]==declared[k] for k in
                ('user_id','username','role','scope_type','scope_id','active')),'Original simulation account changed')
            fresh={**p,'version':p['version']+1,'issued_at':now-1,'expires_at':now+86398}
            account(G.signed(signer,G.ACCESS_ID,fresh),access.keys,now=now)
            users.append((ident,old,fresh));versions[p['user_id']]=fresh['version']
        require(len(versions)==10)
        for _,p in readers:require(p['user_id'] in versions and p['account_version']<versions[p['user_id']])
        for ident,old,fresh in users:
            value={**old,'grant':G.signed(signer,G.ACCESS_ID,fresh)}
            database.execute('UPDATE users SET version=?,value=? WHERE id=?',
                (fresh['version'],access.seal('USER',ident,fresh['version'],value),ident))
            access._audit(database,'ACCOUNT_VERSION',ident)
    for file,p in readers:
        G.write(file,G.signed(signer,G.ACCESS_ID,{**p,'account_version':versions[p['user_id']],
            'issued_at':now-1,'expires_at':now+86398}),replace=True)
    from uuid import uuid4
    logs.append(dict(request_id=str(uuid4()),action='ACCOUNT_RENEWAL',phase='ADMINISTRATION',method='OPERATOR',
        actor=dict(principal_kind='SIGNING_KEY',key_id=G.ACCESS_ID),requested_officer_uid=None,finding_id=None,
        operation_id=None,subject_user_id=None,peer_reference=None,status=None,outcome='ALLOWED',reason='SAME_TEN_GENERATED_ACCOUNTS_ONE_DAY_RENEWAL'))
    return dict(status='SAME_GENERATED_ACCESS_RENEWED',accounts=10,active_accounts=sum(p['active'] for _,_,p in users),
        passwords_changed=False,roles_or_scopes_changed=False,stored_logs_deleted=False,police_action_authority_issued=False,
        sign_in_again=True,detail_disclosures_renewed=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repository',type=Path,required=True)
    parser.add_argument('--app-root',type=Path,required=True);args=parser.parse_args();os.umask(0o077)
    try:print(json.dumps(renew(args.repository.expanduser(),args.app_root.expanduser()),indent=2));return 0
    except Exception as error:
        print(json.dumps(dict(status='STOPPED',error_type=type(error).__name__,private_state_may_have_changed=True)));return 2
if __name__=='__main__':raise SystemExit(main())
