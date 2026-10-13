"""Stopped-app, separately signed research reviewer policy administration."""
import argparse,json,sys,time
from pathlib import Path
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));sys.path.insert(0,str(Path(__file__).resolve().parent))
from app.access import generated_connection as G,research_connection as C,research_connection_runtime as R,review_workflow as W
from app.access.policy import require
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
KEY='generated-application-review-policy'

def prepare(repo,app,draft=None):
    C.revision(repo)
    from provision_generated_connection import stopped_app
    stopped_app(repo,app)
    require(R.read_json(app/'accounts.json',repo)['record_origin']=='GENERATED_RESEARCH_RECORDS')
    cfg=R.read_json(app/'workspace-config.json',repo);require('accountability_config' in cfg)
    keyfile=app/'keys/research-review-policy.key';backup=app/'key-backup/research-review-policy.key'
    if keyfile.exists() or backup.exists():require(R.private(keyfile,repo=repo).read_bytes()==R.private(backup,repo=repo).read_bytes())
    else:
        seed=Ed25519PrivateKey.generate().private_bytes_raw();G.write(keyfile,seed);G.write(backup,seed)
    key=R.signer(keyfile,repo);pins=G.pins({KEY:G.public(key)})
    access_cfg=R.read_json(cfg['access_config'],repo);log_cfg=R.read_json(cfg['accountability_config'],repo)
    seed=R.private(keyfile,repo=repo).read_bytes()
    for path in (access_cfg['key_file'],cfg['key_file'],log_cfg['key_file'],app/'keys/research-access-signer.key',app/'keys/research-presentation-signer.key'):
        require(seed!=R.private(path,repo=repo).read_bytes(),'Separate reviewer policy signing seed required')
    if 'review_workflow_keys' in cfg:require(cfg['review_workflow_keys']==pins,'Existing trust differs')
    else:G.write(app/'workspace-config.json',{**cfg,'review_workflow_keys':pins},replace=True)
    from app.access.research_app import configured
    store,_=configured(app/'workspace-config.json')
    accounts=G.current_accounts(app,repo,R.signer(app/'keys/research-access-signer.key',repo))
    members=[{k:u[k] for k in ('user_id','role','scope_type','scope_id')} for u in accounts if u['active']]
    roles=dict(request_roles=W.REQUEST,review_roles=W.REVIEW,inspect_roles=W.REQUEST);reason='User-approved generated research reviewer policy. No self approval.'
    if draft:
        d=R.read_json(draft,repo);require(set(d)==set(roles)|{'reason'});roles={k:d[k] for k in roles};reason=d['reason']
    with store.transaction() as c:old=W.policies(store,c)
    if old and not draft:
        require(old[-1]['payload']['accounts']==members and all(old[-1]['payload'][k]==v for k,v in roles.items()),'Preserve current policy; use explicit policy-update')
        return dict(status='PRIORITY3_ALREADY_CONFIGURED',policy_version=old[-1]['payload']['version'])
    payload=dict(policy=W.POLICY,version=len(old)+1,supersedes=W.P.fingerprint(old[-1]) if old else None,issued_at=int(time.time()),reason=reason,accounts=members,no_self_approval=True,**roles)
    event=dict(action='RESEARCH_REVIEW_POLICY',phase='ADMINISTRATION',method='OPERATOR',request_id=str(uuid4()),actor={'key_id':KEY},reason=reason,policy_version=payload['version'])
    store.accountability.append({**event,'outcome':'ATTEMPT'})
    try:W.install_policy(store,G.signed(key,KEY,payload))
    except Exception:
        store.accountability.append({**event,'outcome':'FAILED','reason':'POLICY_OPERATION_UNCERTAIN'});raise
    store.accountability.append({**event,'outcome':'ALLOWED'})
    return dict(status='PRIORITY3_RESEARCH_POLICY_CONFIGURED',policy_version=payload['version'],no_self_approval=True,existing_datasets_or_histories_changed=False,police_authority_issued=False,chain_submitted=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','policy-update']);p.add_argument('--repository',type=Path,required=True);p.add_argument('--app-root',type=Path,required=True);p.add_argument('--policy-draft',type=Path);a=p.parse_args()
    require((a.action=='policy-update')==(a.policy_draft is not None));print(json.dumps(prepare(a.repository.resolve(),a.app_root.absolute(),a.policy_draft),indent=2))
