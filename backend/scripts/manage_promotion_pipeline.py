"""Prepare an isolated promotion intake. Commands never reset the original data.

initialize: private keys/passwords and duplicate index only.
storage: explicit additive PostgreSQL/Mongo setup.
configure: verify dedicated destination receipts and prepare runtime settings.
enable: stop-server-only, backed-up workspace configuration update.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.policy import account
from app.access.store import private
from app.access import full_source_profiles as F
from app.intake.promotion_pipeline.core import check,digest,canonical
from app.intake.promotion_pipeline.store import IntakeStore
from app.intake.promotion_pipeline.baseline import index_original
from app.intake.promotion_pipeline.chain_worker import write_private
from app.intake.promotion_pipeline.configuration import source_pins
from app.intake.promotion_pipeline import provision_storage as D

def read(file,repo):return json.loads(private(file,repo=repo).read_bytes())
def sha(file,repo):return hashlib.sha256(private(file,repo=repo).read_bytes()).hexdigest()
def ensure_stopped(origin):
    url=urlsplit(origin)
    check(url.hostname=='127.0.0.1','LOCAL_WORKSPACE_REQUIRED')
    with socket.socket() as s:
        s.settimeout(2);check(s.connect_ex(('127.0.0.1',url.port or 443))!=0,'STOP_APPLICATION_BEFORE_SETUP')
def new_secret(file,size=32):
    if file.exists():return private(file).read_bytes()
    with file.open('xb') as f:
        os.fchmod(f.fileno(),0o600);f.write(secrets.token_bytes(size));f.flush();os.fsync(f.fileno())
    return private(file).read_bytes()
def initialize(args,workspace,origin):
    ensure_stopped(origin)
    check(getattr(workspace,'accountability',None) is not None,'PROMOTION_ACCOUNTABILITY_REQUIRED')
    root=args.state_root
    if not root.exists():root.mkdir(mode=0o700)
    private(root,directory=True,repo=args.repository)
    backup=args.backup_root
    if not backup.exists():backup.mkdir(mode=0o700)
    private(backup,directory=True,repo=args.repository)
    check(not root.is_relative_to(backup) and not backup.is_relative_to(root),'SEPARATE_BACKUP_ROOT_REQUIRED')
    key=new_secret(root/'intake.key')
    import hmac
    check(key!=workspace.access.key_path.read_bytes() and key!=workspace.accountability.key and hmac.digest(key,b'RESEARCH_UI_INDEX_V1','sha256')!=workspace.index_key,'SEPARATE_INTAKE_KEY_REQUIRED')
    copy=backup/'intake.key'
    if not copy.exists():
        with copy.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(key);f.flush();os.fsync(f.fileno())
    check(private(copy).read_bytes()==key,'BACKUP_KEY_DIFFERS')
    recovery=new_secret(root/'chain-recovery.key')
    copy=backup/'chain-recovery.key'
    if not copy.exists():
        with copy.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(recovery);f.flush();os.fsync(f.fileno())
    check(private(copy).read_bytes()==recovery and recovery!=key,'CHAIN_BACKUP_DIFFERS')
    for name in ['chain-jobs','mongo-setup']:
        p=root/name
        if not p.exists():p.mkdir(mode=0o700)
        private(p,directory=True,repo=args.repository)
    for name in ['postgres','mongo']:
        file=root/(name+'-writer.json')
        if not file.exists():write_private(file,{'username':D.USER,'password':secrets.token_urlsafe(36)})
        c=read(file,args.repository);check(set(c)=={'username','password'} and c['username']==D.USER and len(c['password'])>=32,'WRITER_CREDENTIALS_DIFFER')
    users=[]
    with workspace.access.transaction() as c:
        for ident,version,blob in c.execute('SELECT id,version,value FROM users'):
            value=workspace.access.open('USER',ident,version,blob)
            if value['grant']['payload'].get('username')!=args.importer:continue
            u=account(value['grant'],workspace.access.keys,now=workspace.clock())
            if u['username']==args.importer and u['active'] and u['role']=='HQ_ADMIN' and u['scope_type']=='ALL':users.append(u)
    check(len(users)==1,'EXPLICIT_ACTIVE_HQ_IMPORTER_REQUIRED')
    intake=IntakeStore(root,root/'intake.key',backup/'intake.key',repo=args.repository,create=True)
    print('Checking the original signed promotion index…',flush=True)
    baseline=index_original(workspace,intake)
    value={'policy':'PROMOTION_PRIVATE_SETUP_V1','importer_ids':[users[0]['user_id']],
        'baseline_source_set_sha256':baseline['source_set_sha256'],'state_root':str(root),'backup_root':str(backup)}
    write_private(root/'setup.json',value)
    return {'status':'PROMOTION_PRIVATE_STATE_PREPARED','original_promotions_indexed':baseline['promotions'],'worker_enabled':False,'chain_submitted':False}

def storage(args,workspace,origin):
    ensure_stopped(origin);root=args.state_root;plan=read(root/'setup.json',args.repository)
    check(plan['baseline_source_set_sha256']==digest(F.active_set(workspace)),'BASELINE_CHANGED')
    pg=read(root/'postgres-writer.json',args.repository);mg=read(root/'mongo-writer.json',args.repository)
    import psycopg
    from app.storage.mongo_connection import load_credentials,client
    root_password,_=load_credentials(args.mongo_bootstrap)
    # PostgreSQL administrative authentication uses the same local username
    # already used by psql; passwords never appear on a command line or URI.
    with psycopg.connect(host='127.0.0.1',port=5432,dbname='police_identity',user=args.postgres_admin,connect_timeout=5) as connection:
        with connection.cursor() as c:
            c.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='promotion_intake'),EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)",(D.USER,));schema,role=c.fetchone()
        check(schema==role,'SQL_SETUP_PARTIAL_REQUIRES_INSPECTION')
        started=root/'POSTGRES_SETUP_ATTEMPT.json'
        if schema:check(started.exists(),'SQL_DESTINATION_NOT_CREATED_BY_THIS_SETUP')
        write_private(started,{'policy':'PROMOTION_POSTGRES_SETUP_V1','user':D.USER,'database':'police_identity','schema':'promotion_intake','credential_sha256':sha(root/'postgres-writer.json',args.repository)})
        D.postgres(connection,pg['password'],existing=schema)
    with psycopg.connect(host='127.0.0.1',port=5432,dbname='police_identity',user=D.USER,password=pg['password'],connect_timeout=5) as writer:
        with writer.cursor() as c:c.execute('SELECT record_id FROM promotion_intake.evidence LIMIT 0')
    from pymongo import MongoClient
    def authenticate(password):
        with MongoClient('127.0.0.1',27018,username=D.USER,password=password,authSource=D.DATABASE,serverSelectionTimeoutMS=5000,connectTimeoutMS=5000,socketTimeoutMS=10000,retryWrites=False) as writer:
            list(writer[D.DATABASE][D.COLLECTION].find({},limit=1))
    with client(root_password,bootstrap=True) as bootstrap:
        D.mongo(bootstrap[D.DATABASE],mg['password'],root/'mongo-setup',authenticate=authenticate)
    result={'policy':'PROMOTION_STORAGE_SETUP_V1','status':'PASSED','postgres_credential_sha256':sha(root/'postgres-writer.json',args.repository),'mongo_credential_sha256':sha(root/'mongo-writer.json',args.repository),'schema':'promotion_intake','mongo_database':D.DATABASE,'collection':D.COLLECTION}
    write_private(root/'STORAGE_READY.json',result)
    return {'status':'PROMOTION_STORAGE_VERIFIED','original_records_changed':False,'worker_enabled':False,'chain_submitted':False}

def configure(args,workspace,origin):
    ensure_stopped(origin);root=args.state_root;plan=read(root/'setup.json',args.repository)
    check(plan['baseline_source_set_sha256']==digest(F.active_set(workspace)),'BASELINE_CHANGED')
    storage_receipt=read(root/'STORAGE_READY.json',args.repository)
    check(storage_receipt['status']=='PASSED' and storage_receipt['postgres_credential_sha256']==sha(root/'postgres-writer.json',args.repository) and storage_receipt['mongo_credential_sha256']==sha(root/'mongo-writer.json',args.repository),'STORAGE_SETUP_REQUIRED')
    gateway=read(args.fabric_gateway,args.repository)
    check(gateway['policy']=='PROMOTIONS_AUTHENTICATED_GATEWAY_V2' and gateway['destination']['chaincode']=='promotions-anchor-v1','DEDICATED_PROMOTIONS_GATEWAY_REQUIRED')
    gateway_receipt=read(args.fabric_gateway.parent/'PASSED.json',args.repository)
    check(gateway_receipt['status']=='PROMOTIONS_FABRIC_GATEWAY_VERIFIED' and gateway_receipt['configuration_sha256']==sha(args.fabric_gateway,args.repository),'VERIFIED_PROMOTIONS_GATEWAY_REQUIRED')
    deployment=read(root/'deployment/PASSED.json',args.repository)
    check(deployment['policy']=='SEPOLIA_PROMOTIONS_CONTRACT_DEPLOYMENT_V1' and deployment['status']=='PASSED' and deployment['finalized'] is True and deployment['two_rpc_readback'] is True,'FINALIZED_PROMOTIONS_DEPLOYMENT_REQUIRED')
    wallet=read(args.wallet_root/'wallet-info.json',args.repository)
    check(wallet['address'].lower()==deployment['writer'].lower(),'PROMOTIONS_WRITER_DIFFERS')
    # Dedicated writer prevents nonce races with original-evidence or findings
    # publishers. A second directory containing the old key is not sufficient.
    old=args.existing_wallet/'wallet-info.json'
    if old.exists():check(read(old,args.repository)['address'].lower()!=wallet['address'].lower(),'DEDICATED_PROMOTIONS_WALLET_REQUIRED')
    check(sha(args.network_file,args.repository)==deployment['config_sha256'],'PROMOTIONS_NETWORK_PIN_DIFFERS')
    check(read(args.network_file,args.repository)['policy']=='PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1','PROMOTIONS_NETWORK_POLICY_REQUIRED')
    destination={'chain_id':11155111,'contract':deployment['contract_address'].lower(),'runtime_sha256':deployment['artifact']['runtime_sha256'],'writer':deployment['writer'].lower(),'namespace':'promotions-anchor-v1','finality':'FINALIZED'}
    chains={'fabric_config':str(args.fabric_gateway),'fabric_sha256':sha(args.fabric_gateway,args.repository),'network_config':str(args.network_file),'network_sha256':sha(args.network_file,args.repository),'destination':destination,'wallet_root':str(args.wallet_root),'wallet_backup':str(args.wallet_backup),'recovery_key':str(root/'chain-recovery.key')}
    config={'policy':'PROMOTION_PIPELINE_RUNTIME_V1','state_root':str(root),'key_file':str(root/'intake.key'),'backup_key_file':str(args.backup_root/'intake.key'),'importer_ids':plan['importer_ids'],'baseline_source_set_sha256':plan['baseline_source_set_sha256'],'postgres_credentials':str(root/'postgres-writer.json'),'mongo_credentials':str(root/'mongo-writer.json'),'chains':chains,'source_pins':source_pins(args.repository)}
    write_private(root/'runtime.json',config)
    return {'status':'PROMOTION_RUNTIME_CONFIG_PREPARED','file':str(root/'runtime.json'),'worker_enabled':False,'chain_submitted':False}

def enable(args,workspace,origin):
    ensure_stopped(origin);file=args.workspace_config;raw=private(file,repo=args.repository).read_bytes();config=json.loads(raw)
    target=str(args.state_root/'runtime.json')
    if config.get('promotion_intake_config')==target:return {'status':'PROMOTION_PIPELINE_ALREADY_ENABLED','restart_required':True}
    check('promotion_intake_config' not in config,'OTHER_PROMOTION_RUNTIME_ALREADY_CONFIGURED')
    from app.intake.promotion_pipeline.runtime import Runtime
    from app.access.research_service import ResearchService
    runtime=Runtime(workspace,ResearchService(workspace),args.state_root/'runtime.json')
    try:
        with runtime.engine.connect() as c:
            from sqlalchemy import text
            c.execute(text('SELECT record_id FROM promotion_intake.evidence LIMIT 0'))
        runtime.mongo[D.DATABASE].command('ping')
    finally:runtime.engine.dispose();runtime.mongo.close()
    backup=args.state_root/'workspace-config-before-enable.json'
    if backup.exists():check(private(backup).read_bytes()==raw,'WORKSPACE_BACKUP_DIFFERS')
    else:
        with backup.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    check(private(file).read_bytes()==raw,'WORKSPACE_CONFIG_CHANGED')
    config['promotion_intake_config']=target
    tmp=file.parent/('promotion-config-'+secrets.token_hex(8)+'.tmp')
    try:
        write_private(tmp,config);check(private(file).read_bytes()==raw,'WORKSPACE_CONFIG_CHANGED');os.replace(tmp,file)
        fd=os.open(file.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if tmp.exists():tmp.unlink()
    return {'status':'PROMOTION_PIPELINE_ENABLED','restart_required':True,'original_records_changed':False,'chain_submitted':False}

def disable(args,workspace,origin):
    ensure_stopped(origin);file=private(args.workspace_config,repo=args.repository);raw=file.read_bytes();config=json.loads(raw)
    if 'promotion_intake_config' not in config:return {'status':'PROMOTION_PIPELINE_ALREADY_DISABLED'}
    check(config['promotion_intake_config']==str(args.state_root/'runtime.json'),'OTHER_PROMOTION_RUNTIME_CONFIGURED')
    backup=args.state_root/('workspace-before-disable-'+hashlib.sha256(raw).hexdigest()[:16]+'.json')
    if backup.exists():check(private(backup).read_bytes()==raw,'WORKSPACE_BACKUP_DIFFERS')
    else:
        with backup.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    del config['promotion_intake_config'];temp=file.parent/('promotion-disable-'+secrets.token_hex(8)+'.tmp')
    try:
        write_private(temp,config);check(private(file).read_bytes()==raw,'WORKSPACE_CONFIG_CHANGED');os.replace(temp,file)
        fd=os.open(file.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()
    return {'status':'PROMOTION_PIPELINE_DISABLED','all_retained_uploads_and_chain_journals_preserved':True,'restart_required':True,'chain_submitted':False}

def refresh_pins(args,workspace,origin):
    """Re-pin reviewed, committed source after an upgrade; only source_pins changes."""
    ensure_stopped(origin)
    import subprocess
    check(not subprocess.check_output(['git','-C',str(args.repository),'status','--porcelain'],text=True).strip(),'COMMIT_SOURCE_BEFORE_PINNING')
    revision=subprocess.check_output(['git','-C',str(args.repository),'rev-parse','HEAD'],text=True).strip()
    file=args.state_root/'runtime.json';raw=private(file,repo=args.repository).read_bytes();config=json.loads(raw)
    check(config['policy']=='PROMOTION_PIPELINE_RUNTIME_V1','PROMOTION_RUNTIME_REQUIRED')
    pins=source_pins(args.repository)
    if config['source_pins']==pins:return {'status':'SOURCE_PINS_ALREADY_CURRENT','revision':revision}
    backup=args.state_root/('runtime-before-repin-'+revision[:12]+'.json')
    if backup.exists():check(private(backup).read_bytes()==raw,'RUNTIME_BACKUP_DIFFERS')
    else:
        with backup.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    temp=file.parent/('runtime-repin-'+secrets.token_hex(8)+'.tmp')
    try:
        write_private(temp,{**config,'source_pins':pins});check(private(file).read_bytes()==raw,'RUNTIME_CONFIG_CHANGED');os.replace(temp,file)
    finally:
        if temp.exists():temp.unlink()
    return {'status':'SOURCE_PINS_REFRESHED','revision':revision,'files_pinned':len(pins),'backup':str(backup),'restart_required':True,'chain_submitted':False}

def wallet(args,workspace,origin):
    ensure_stopped(origin)
    import subprocess
    program="const W=require(process.argv[1]);W.initialize(process.argv[2],process.argv[3]).then(x=>console.log(JSON.stringify(x))).catch(()=>{console.error('WALLET_SETUP_STOPPED');process.exitCode=1;});"
    result=subprocess.run(['node','-e',program,str(args.repository/'blockchain/public/sepolia-wallet.js'),str(args.wallet_root),str(args.wallet_backup)],capture_output=True,timeout=120)
    check(result.returncode==0,'PROMOTIONS_WALLET_SETUP_STOPPED')
    value=json.loads(result.stdout);check(value['status']=='PASSED' and value['chain_id']==11155111,'PROMOTIONS_WALLET_SETUP_DIFFERS')
    return {'status':'DEDICATED_PROMOTIONS_WALLET_PREPARED','address':value['address'],'chain_submitted':False,'next':'Fund this new address with Sepolia test ETH before deployment.'}

def network(args,workspace,origin):
    ensure_stopped(origin)
    from urllib.parse import urlsplit
    private(args.state_root,directory=True,repo=args.repository)
    target=args.network_file
    check(target.parent==args.state_root,'PROMOTIONS_NETWORK_LOCATION_DIFFERS')
    if args.existing_network.exists():
        value=read(args.existing_network,args.repository)
        check(value['policy'] in ('FINDINGS_LIVE_SEPOLIA_NETWORK_V1','PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1'),'EXISTING_NETWORK_POLICY_DIFFERS')
        value={**value,'policy':'PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1'}
    else:
        value={'policy':'PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1','rpc_urls':[getpass.getpass('QuickNode Sepolia HTTPS URL (hidden): '),getpass.getpass('Alchemy Sepolia HTTPS URL (hidden): ')],'max_fee_gwei':'5','priority_fee_gwei':'1','max_total_fee_eth':'0.025','confirmations':12}
    check(set(value)=={'policy','rpc_urls','max_fee_gwei','priority_fee_gwei','max_total_fee_eth','confirmations'},'NETWORK_FIELDS_DIFFER')
    hosts=[]
    for url in value['rpc_urls']:
        parsed=urlsplit(url)
        check(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and parsed.port in (None,443) and parsed.path not in ('','/'),'TOKENIZED_HTTPS_RPC_REQUIRED')
        hosts.append(parsed.hostname)
    check(len(hosts)==2 and sum(h.endswith('.quiknode.pro') for h in hosts)==1 and hosts.count('eth-sepolia.g.alchemy.com')==1,'INDEPENDENT_EXISTING_RPC_PROVIDERS_REQUIRED')
    write_private(target,value)
    return {'status':'PRIVATE_PROMOTIONS_NETWORK_PREPARED','sha256':sha(target,args.repository),'chain_submitted':False}

def public_operation(args,workspace,origin):
    ensure_stopped(origin)
    import subprocess
    mode={'public-preview':'--preview','public-deploy':'--execute','public-reconcile':'--reconcile'}[args.command]
    command=['node',str(args.repository/'blockchain/public/promotions/deploy-live.js'),'--network-file',str(args.network_file),'--network-sha256',sha(args.network_file,args.repository),'--wallet-root',str(args.wallet_root),'--backup-wallet-root',str(args.wallet_backup),'--journal-root',str(args.state_root/'deployment'),mode]
    result=subprocess.run(command,cwd=args.repository,capture_output=True,timeout=600)
    check(result.returncode==0,'PROMOTIONS_DEPLOYMENT_STOPPED_PRESERVE_JOURNAL')
    value=json.loads(result.stdout)
    check(value.get('scope')=='DEDICATED_EMPTY_PROMOTIONS_CONTRACT','DEPLOYMENT_SCOPE_DIFFERS')
    return value

def verify_batch(args,workspace,origin):
    ensure_stopped(origin)
    check(args.batch_id is not None,'BATCH_REFERENCE_REQUIRED')
    from app.intake.promotion_pipeline.runtime import Runtime
    from app.access.research_service import ResearchService
    from app.intake.promotion_pipeline.delivery import reconcile
    from app.intake.promotion_pipeline.core import publication
    runtime=Runtime(workspace,ResearchService(workspace),args.state_root/'runtime.json')
    try:
        with runtime.store.worker_lock():
            batch=runtime.store.get(args.batch_id)
            prepared=runtime.store.phase(args.batch_id,'DOCUMENTS_PREPARED')
            check(prepared is not None,'NO_ORIGINAL_DELIVERY_TO_VERIFY')
            def boundary():
                runtime.check_pins();runtime.service.source_state()
                reconcile(runtime.store,batch,prepared['documents'],runtime.sql,runtime.documents)
            boundary();payload,_=publication(runtime.store.key,batch)
            mode='RECONCILE'
            if args.command=='retry-retained':
                check(args.chain in ('fabric','public'),'EXPLICIT_RETRY_CHAIN_REQUIRED')
                runtime.authorize(batch)
                mode='RETRY_'+args.chain.upper()
                original_boundary=boundary
                def boundary():runtime.authorize(batch);original_boundary()
            result=runtime.chains(batch,payload,boundary,mode=mode)
            return {'status':result['status'],'batch_id':args.batch_id,'fresh_chain_reads':True,'transactions_submitted':0 if mode=='RECONCILE' else None,'operator_exact_retry_requested':args.command=='retry-retained','replacement_transaction_created':False,'scope':'THIS_PROMOTION_BATCH_ONLY','publication_id':payload['publication_id'],'merkle_root':payload['merkle_root'],'public_contract':runtime.config['chains']['destination']['contract'],'fabric_transaction_id':result.get('fabric',{}).get('transaction_id'),'public_transaction_id':(result.get('public') or {}).get('transaction_id')}
    finally:runtime.engine.dispose();runtime.mongo.close()

def demo_csv(args,workspace,origin):
    """An explicitly controlled generated report; never an original PF record."""
    import csv,io
    from datetime import datetime,timezone
    from uuid import uuid4
    from app.identity.service_values import RANKS
    from app.intake.promotion_pipeline.core import COLUMNS,parse,validate_rows
    root=args.state_root;plan=read(root/'setup.json',args.repository)
    check(plan['baseline_source_set_sha256']==digest(F.active_set(workspace)),'BASELINE_CHANGED')
    target=root/'controlled-promotion-demo.csv'
    if target.exists():
        parse(private(target,repo=args.repository).read_bytes())
        return {'status':'EXISTING_CONTROLLED_DEMO_PRESERVED','file':str(target),'chain_submitted':False}
    order=('SDIG','DIG','SSP','SP','ASP','CIP','IP','SI','PS_C1','PS_C2','PC_C1','PC_C2','PC_C3','PC_C4')
    labels={code:label for label,code in RANKS.items()};now=datetime.fromtimestamp(workspace.clock(),timezone.utc)
    with workspace.access.transaction() as c:directory=workspace.access._directory(c)
    selected=None
    for officer in directory['officers'][:100]:
        profile=F.profile(workspace,officer['officer_uid'],directory['source_public_sha256'])
        service=[r['fields'] for r in profile['full_records'] if r['dataset']=='officer_service_information.csv']
        if len(service)!=1:continue
        fields=service[0];code=RANKS.get(fields.get('current_rank',''))
        if fields.get('service_status')!='Active' or code not in order or order.index(code)==0:continue
        row=dict.fromkeys(COLUMNS,'');row.update(promotion_id='CONTROLLED-UPLOAD-'+str(uuid4()),officer_nic_no=officer['nic'],
            from_rank=fields['current_rank'],to_rank=labels[order[order.index(code)-1]],is_same_unit='TRUE',
            from_unit_name=fields.get('current_unit_name',''),to_unit_name=fields.get('current_unit_name',''),
            effective_date=now.date().isoformat(),promotion_order_date=now.date().isoformat(),
            promotion_order_no='CONTROLLED_RESEARCH_UPLOAD_DEMO',promotion_reason='Controlled generated report to test the upload pipeline; authority not assessed.')
        result=validate_rows([row],lambda nic:[officer['officer_uid']] if nic==officer['nic'] else [],lambda *a:'ABSENT',now=now)
        if result[0]['status']=='READY':selected=row;break
    check(selected is not None,'NO_SUITABLE_CONNECTED_DEMO_OFFICER_FOUND')
    stream=io.StringIO(newline='');writer=csv.writer(stream);writer.writerow(COLUMNS);writer.writerow([selected[k] for k in COLUMNS]);data=stream.getvalue().encode()
    with target.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
    return {'status':'CONTROLLED_GENERATED_PROMOTION_DEMO_PREPARED','file':str(target),'rows':1,'source_reference':'CONTROLLED_PROMOTION_UPLOAD_DEMONSTRATION_V1','authority_assessed':False,'chain_submitted':False}

def main():
    home=Path.home();base=home/'ResearchKeys/police-personnel-integrity'
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['initialize','storage','wallet','network','public-preview','public-deploy','public-reconcile','configure','enable','disable','verify-batch','retry-retained','demo-csv','refresh-pins'])
    p.add_argument('--repository',type=Path,default=home/'Developer/police-personnel-integrity');p.add_argument('--workspace-config',type=Path,default=base/'research-app-v1/workspace-config.json')
    p.add_argument('--state-root',type=Path,default=base/'application-promotions-v1');p.add_argument('--backup-root',type=Path,default=base/'application-promotions-v1-backup');p.add_argument('--importer',default='research.hq')
    p.add_argument('--mongo-bootstrap',type=Path,default=base/'mongo-v1');p.add_argument('--postgres-admin',default=getpass.getuser())
    p.add_argument('--fabric-gateway',type=Path,default=base/'application-promotions-v1/fabric-gateway-setup/promotions-gateway.json');p.add_argument('--network-file',type=Path,default=base/'application-promotions-v1/promotions-network.json')
    p.add_argument('--batch-id');p.add_argument('--chain',choices=['fabric','public'])
    p.add_argument('--existing-network',type=Path,default=base/'application-findings-v1/findings-network.json')
    p.add_argument('--wallet-root',type=Path,default=base/'promotions-sepolia-v1');p.add_argument('--wallet-backup',type=Path,default=base/'promotions-sepolia-v1-backup');p.add_argument('--existing-wallet',type=Path,default=base/'sepolia-v1')
    a=p.parse_args();os.umask(0o077)
    for name,value in vars(a).items():
        if isinstance(value,Path):check(value.is_absolute() and '..' not in value.parts,'ABSOLUTE_SETUP_PATH_REQUIRED')
    workspace,origin=configured(a.workspace_config)
    check(workspace.repo==a.repository,'WORKSPACE_REPOSITORY_DIFFERS')
    result=(public_operation if a.command.startswith('public-') else verify_batch if a.command in ('verify-batch','retry-retained') else demo_csv if a.command=='demo-csv' else refresh_pins if a.command=='refresh-pins' else globals()[a.command])(a,workspace,origin);print(json.dumps(result,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'STOPPED','error_type':type(error).__name__,'reason':getattr(error,'code','SETUP_INCOMPLETE_RETAIN_PRIVATE_STATE'),'automatic_redeployment':False,'transaction_outcome':'CHECK_RETAINED_JOURNALS_BEFORE_RETRY'}));raise SystemExit(1)
