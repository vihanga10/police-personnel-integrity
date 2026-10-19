"""Enable read-only promotion analysis after reviewed source installation."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.store import private
from app.intake.promotion_pipeline.analysis import POLICY,PromotionAnalysis
from app.intake.promotion_pipeline.core import canonical,check
from app.intake.promotion_pipeline.configuration import source_pins

def write(file,data):
    with file.open('xb') as out:
        os.fchmod(out.fileno(),0o600);out.write(data);out.flush();os.fsync(out.fileno())
    fd=os.open(file.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def initialize(workspace,origin):
    url=urlsplit(origin)
    check(url.hostname=='127.0.0.1','LOCAL_WORKSPACE_REQUIRED')
    with socket.socket() as connection:
        connection.settimeout(2);check(connection.connect_ex(('127.0.0.1',url.port or 443))!=0,'STOP_HTTPS_SERVER_FIRST')
    check(subprocess.check_output(['git','-C',str(workspace.repo),'status','--porcelain'],text=True).strip()=='','COMMIT_REVIEWED_SOURCE_FIRST')
    file=private(workspace.promotion_intake_config,repo=workspace.repo)
    raw=file.read_bytes();runtime=json.loads(raw)
    check(runtime['source_pins']==source_pins(workspace.repo),'REVIEWED_SOURCE_PINS_REQUIRED')
    root=private(runtime['state_root'],directory=True,repo=workspace.repo)
    analysis_root=root/'analysis-v1';config_file=root/'analysis-config.json'
    expected={'policy':POLICY,'intake_config':str(file),'analysis_root':str(analysis_root)}
    if not analysis_root.exists():analysis_root.mkdir(mode=0o700)
    private(analysis_root,directory=True,repo=workspace.repo)
    if config_file.exists():check(private(config_file,repo=workspace.repo).read_bytes()==canonical(expected),'ANALYSIS_CONFIG_ALREADY_DIFFERS')
    else:write(config_file,canonical(expected))
    if 'analysis_config' in runtime:check(runtime['analysis_config']==str(config_file),'ANOTHER_ANALYSIS_CONFIG_PRESENT')
    else:
        write(root/('runtime-before-analysis-'+str(uuid4())+'.json'),raw)
        runtime['analysis_config']=str(config_file)
        temporary=file.with_name('runtime-analysis-'+str(uuid4())+'.tmp')
        write(temporary,canonical(runtime));os.replace(temporary,file)
        fd=os.open(file.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    analysis=PromotionAnalysis(workspace,config_file,create=True)
    created=analysis.activate_visible()
    return {'status':'PUBLISHED_PROMOTION_ANALYSIS_ENABLED','activated_batches_now':len(created),
        'total_activated_batches':len(analysis.journal.identifiers()),'original_signed_packets_changed':False,
        'original_personnel_rows_changed':False,'accepted_rank_automatically_changed':False,
        'chain_transactions_submitted':0,'restart_required':True,
        'knowledge_semantics':'ACTUAL_ANALYSIS_AVAILABILITY_NO_BACKDATING'}

def main():
    os.umask(0o077);parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['initialize','status'])
    parser.add_argument('--workspace-config',type=Path,default=Path.home()/'ResearchKeys/police-personnel-integrity/research-app-v1/workspace-config.json')
    args=parser.parse_args();workspace,origin=configured(args.workspace_config)
    check(getattr(workspace,'promotion_intake_config',None),'PROMOTION_INTAKE_NOT_CONFIGURED')
    if args.command=='initialize':result=initialize(workspace,origin)
    else:
        from app.intake.promotion_pipeline.analysis import configured_analysis
        analysis=configured_analysis(workspace)
        if analysis:analysis.guard()
        result={'status':'PUBLISHED_PROMOTION_ANALYSIS_STATUS','configured':analysis is not None,
            'activated_batches':len(analysis.journal.identifiers()) if analysis else 0,'chain_transactions_submitted':0}
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'STOPPED','error_type':type(error).__name__,
            'reason':getattr(error,'code','KEEP_EXISTING_ANALYSIS_STATE_AND_INSPECT'),'chain_transactions_submitted':0}))
        raise SystemExit(1)
