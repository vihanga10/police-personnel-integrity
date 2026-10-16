"""Enable independent IGP intake approval; preserve existing published batches."""
import argparse,json,os,socket,subprocess,sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.policy import account
from app.access.store import private
from app.intake.promotion_pipeline.analysis import configured_analysis
from app.intake.promotion_pipeline.approvals import ApprovalEngine,POLICY,batch_binding
from app.intake.promotion_pipeline.configuration import source_pins
from app.intake.promotion_pipeline.core import canonical,check
from manage_promotion_analysis import write

def initialize(workspace,origin):
    url=urlsplit(origin);check(url.hostname=='127.0.0.1','LOCAL_WORKSPACE_REQUIRED')
    with socket.socket() as connection:
        connection.settimeout(2);check(connection.connect_ex(('127.0.0.1',url.port or 443))!=0,'STOP_HTTPS_SERVER_FIRST')
    check(not subprocess.check_output(['git','-C',str(workspace.repo),'status','--porcelain'],text=True).strip(),'COMMIT_REVIEWED_SOURCE_FIRST')
    analysis=configured_analysis(workspace);check(analysis is not None,'EXISTING_PROMOTION_ANALYSIS_REQUIRED')
    analysis.guard();runtime=analysis.runtime;check(runtime['source_pins']==source_pins(workspace.repo),'REVIEWED_SOURCE_PINS_REQUIRED')
    root=private(runtime['state_root'],directory=True,repo=workspace.repo);file=root/'approval-config.json';decisions=root/'approval-v1'
    if file.exists():
        config=json.loads(private(file,repo=workspace.repo).read_bytes())
        check(config['policy']==POLICY and config['decision_root']==str(decisions),'EXISTING_APPROVAL_CONFIG_DIFFERS')
    else:
        users=[]
        with workspace.access.transaction() as c:
            for ident,version,blob in c.execute('SELECT id,version,value FROM users'):
                value=workspace.access.open('USER',ident,version,blob);envelope=value.get('account',value.get('grant'))
                if not envelope:continue
                try:user=account(envelope,workspace.access.keys,now=workspace.access.clock())
                except ValueError:continue
                if user['active'] and user['role']=='IGP' and user['scope_type']=='ALL':users.append(user)
        check(len(users)==1,'ONE_CURRENT_IGP_REVIEWER_REQUIRED_RENEW_EXPIRED_ACCOUNT_FIRST')
        check(users[0]['user_id'] not in runtime['importer_ids'],'INDEPENDENT_IGP_REQUIRED')
        config={'policy':POLICY,'decision_root':str(decisions),'reviewer_ids':[u['user_id'] for u in users],
            'legacy_queued':{b['batch_id']:batch_binding(b) for b in analysis.intake.batches(limit=1000) if analysis.intake.phase(b['batch_id'],'QUEUED') is not None}}
        if not decisions.exists():decisions.mkdir(mode=0o700)
        write(file,canonical(config))
    ApprovalEngine(workspace,analysis,file,create=True)
    if 'approval_config' in runtime:check(runtime['approval_config']==str(file),'ANOTHER_APPROVAL_CONFIG_PRESENT')
    else:
        write(root/('runtime-before-igp-approval-'+str(uuid4())+'.json'),analysis.runtime_raw)
        runtime['approval_config']=str(file);temporary=root/('approval-runtime-'+str(uuid4())+'.tmp');write(temporary,canonical(runtime));os.replace(temporary,analysis.runtime_file)
        fd=os.open(root,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    return {'status':'INDEPENDENT_IGP_PROMOTION_APPROVAL_ENABLED','reviewer_accounts':len(config['reviewer_ids']),
        'existing_processing_batches_preserved':len(config['legacy_queued']),'new_uploads_require_igp_approval':True,
        'rank_acceptance_requires_valid_assessed_authority':True,'existing_batches_automatically_accepted':False,
        'original_records_changed':False,'chain_transactions_submitted':0,'restart_required':True}

def main():
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['initialize','status']);p.add_argument('--workspace-config',type=Path,default=Path.home()/'ResearchKeys/police-personnel-integrity/research-app-v1/workspace-config.json');args=p.parse_args();workspace,origin=configured(args.workspace_config)
    if args.command=='initialize':result=initialize(workspace,origin)
    else:
        a=configured_analysis(workspace);file=a.runtime.get('approval_config') if a else None;engine=ApprovalEngine(workspace,a,file) if file else None
        if engine:engine.guard()
        result={'status':'IGP_PROMOTION_APPROVAL_STATUS','configured':engine is not None,'chain_transactions_submitted':0}
    print(json.dumps(result,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'status':'STOPPED','error_type':type(e).__name__,'reason':getattr(e,'code','RETAIN_APPROVAL_STATE_AND_INSPECT'),'chain_transactions_submitted':0}));raise SystemExit(1)
