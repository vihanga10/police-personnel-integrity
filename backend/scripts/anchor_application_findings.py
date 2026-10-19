"""Fresh-source-gated application findings preparation and live chain coordination.

Operator only. Stop the web app first. A source check failure kills the worker;
retained original transaction plans must be reconciled, never replaced.
"""
import argparse,base64,json,os,subprocess,sys,time,queue,threading
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));sys.path.insert(0,str(Path(__file__).resolve().parent))
from app.access import generated_connection as G,research_connection as C,research_connection_runtime as R,application_findings_commitments as A
from app.access.policy import require,encoded,uid
from app.identity.algorithm_permit import AlgorithmPermit
from app.access.application_anchor_guard import SourcePins
from app.access import application_anchor_observations as O

def keys(root,repo):
    R.private(root,directory=True,repo=repo)
    one=R.private(root/'keys.json',repo=repo);two=R.private(root/'backup/keys.json',repo=repo)
    require(one.read_bytes()==two.read_bytes() and not os.path.samefile(one,two),'Commitment recovery differs')
    value=R.read_json(one,repo);require(set(value)=={'policy','encryption','content','publication','recovery'} and value['policy']=='APPLICATION_FINDINGS_ANCHOR_KEYS_V1')
    result={k:base64.b64decode(value[k],validate=True) for k in ('encryption','content','publication','recovery')}
    require(all(len(v)==32 for v in result.values()) and len(set(result.values()))==4)
    return result

def initialize(root,repo,app):
    require(R.read_json(app/'accounts.json',repo)['record_origin']=='GENERATED_RESEARCH_RECORDS')
    R.private(root.parent,directory=True,repo=repo);require(not root.exists() and not root.is_symlink(),'New root required; preserve existing state')
    root.mkdir(mode=0o700)
    for name in ('backup','jobs'):(root/name).mkdir(mode=0o700)
    value={'policy':'APPLICATION_FINDINGS_ANCHOR_KEYS_V1',**{k:base64.b64encode(os.urandom(32)).decode() for k in ('encryption','content','publication','recovery')}}
    G.write(root/'keys.json',value);G.write(root/'backup/keys.json',value);G.write(root/'recovery.key',base64.b64decode(value['recovery']))
    return dict(status='APPLICATION_FINDINGS_KEYS_PREPARED',chain_submitted=False)

def save_job(root,job,k):
    ident=job['public']['publication_id'];directory=root/'jobs'/ident;directory.mkdir(mode=0o700)
    nonce=os.urandom(12);cipher=AESGCM(k['encryption']).encrypt(nonce,encoded(job),encoded(['APPLICATION_FINDINGS_JOB_V1',ident]))
    G.write(directory/'job.encrypted.json',dict(nonce=base64.b64encode(nonce).decode(),ciphertext=base64.b64encode(cipher).decode()))
    G.write(directory/'public.json',job['public']);return ident

def load_job(root,ident,k,repo):
    A.P.sha(ident);e=R.read_json(root/'jobs'/ident/'job.encrypted.json',repo);require(set(e)=={'nonce','ciphertext'})
    return json.loads(AESGCM(k['encryption']).decrypt(base64.b64decode(e['nonce'],validate=True),base64.b64decode(e['ciphertext'],validate=True),encoded(['APPLICATION_FINDINGS_JOB_V1',ident])))

def source_context(a):
    from provision_generated_connection import stopped_app
    from app.access.research_app import configured
    from app.identity.algorithm_snapshot import load_verified_snapshot
    stopped_app(a.repository,a.app_root);revision=C.revision(a.repository)
    plan=G.validate_plan(a.repository,a.connection_root,a.app_root)
    args=SimpleNamespace(**{k:Path(v) for k,v in {**plan['source'],'audit_gate_attempt':str(a.audit_gate_attempt)}.items()})
    pins=SourcePins(vars(args).values())
    snapshot=load_verified_snapshot(args,a.repository,revision);pins.check();permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    store,_=configured(a.app_root/'workspace-config.json');require(store.accountability is not None)
    return store,snapshot,permit,revision,pins

def run_worker(command,check,*,timeout=600):
    """Drain both pipes, bound messages/time, terminate only our owned process."""
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    messages=queue.Queue(maxsize=256)
    def stdout():
        try:
            while True:
                line=process.stdout.readline(65537)
                if not line:break
                if len(line)>65536:messages.put(('error',None));break
                messages.put(('line',line))
        finally:messages.put(('end',None))
    def stderr():
        # SDK diagnostics may contain credentials: drain without printing or storing.
        while process.stderr.read(4096):pass
    threading.Thread(target=stdout,daemon=True).start();threading.Thread(target=stderr,daemon=True).start()
    deadline=time.monotonic()+timeout;result=None;last=0
    try:
        while True:
            require(time.monotonic()<deadline,'Owned worker deadline exceeded')
            try:kind,line=messages.get(timeout=min(1,max(.01,deadline-time.monotonic())))
            except queue.Empty:check();continue
            if kind=='end':break
            require(kind=='line');value=json.loads(line)
            if value.get('request')=='SOURCE_CHECK':
                require(set(value)=={'request','id','phase'} and type(value['id']) is int and value['id']==last+1<=200 and type(value['phase']) is str and len(value['phase'])<=100)
                last=value['id'];check();process.stdin.write(json.dumps(dict(id=last,ok=True))+'\n');process.stdin.flush()
            else:
                require(set(value)=={'result'} and result is None and last>0,'Chain operation uncertain; reconcile original plans');result=value['result']
        require(process.wait(timeout=10)==0 and result is not None);check();return result
    finally:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout,process.stderr):stream.close()

def verify_scope(store,snapshot,job,k):
    selection=A.select(store,job['selection']['officer_uid']);require(selection==job['selection'],'Finding prefix changed; prepare a new complete prefix')
    require(selection['source_public_sha256']==A.P.fingerprint(snapshot['public']),'Original source publication differs')
    require(A.generate(selection,k['content'],k['publication'],salt=bytes.fromhex(job['salt']))==job['public'],'Retained commitments differ')

def operate(a):
    if a.action in ('initialize','status'):return _operate(a)
    R.private(a.state_root,directory=True,repo=a.repository)
    lock=a.state_root/'.operator-lock';lock.mkdir(mode=0o700)
    try:return _operate(a)
    finally:lock.rmdir()

def _operate(a):
    if a.action=='initialize':return initialize(a.state_root,a.repository,a.app_root)
    k=keys(a.state_root,a.repository)
    if a.action=='status':
        jobs=[]
        for directory in sorted((a.state_root/'jobs').iterdir()):
            if directory.is_dir() and not directory.is_symlink():
                job=load_job(a.state_root,directory.name,k,a.repository);jobs.append(dict(publication_id=directory.name,application_entry_count=len(job['selection']['entries']),has_chain_observation=any(directory.glob('observation-*.json'))))
        return dict(status='LOCAL_FINDINGS_JOB_INVENTORY',jobs=jobs,fresh_chain_verification=False)
    require(a.audit_gate_attempt and a.connection_root,'Fresh original audit and connection root required')
    store,snapshot,permit,revision,pins=source_context(a)
    event=dict(action='OTHER_REQUEST',phase='ADMINISTRATION',method='OPERATOR',request_id=str(uuid4()),actor={'identity_basis':'LOCAL_RESEARCH_OPERATOR','uid':os.getuid()},reason='APPLICATION_FINDINGS_'+a.action.upper())
    store.accountability.append({**event,'outcome':'ATTEMPT'})
    if a.action=='prepare':
        uid(a.officer);selection=A.select(store,a.officer);require(selection['source_public_sha256']==A.P.fingerprint(snapshot['public']))
        forbidden={*snapshot['crypto'].encryption_keys.values(),*snapshot['crypto'].lookup_keys.values(),*snapshot['backup'].encryption_keys.values(),*snapshot['backup'].lookup_keys.values()}
        from app.identity.generate_protected_commitments import load_keys
        plan=G.validate_plan(a.repository,a.connection_root,a.app_root)
        original=load_keys(Path(plan['source']['commitment_key_file']),Path(plan['source']['backup_commitment_key_file']),a.repository)
        forbidden.update((original.content,original.publication))
        cfg=R.read_json(a.app_root/'workspace-config.json',a.repository);access=R.read_json(cfg['access_config'],a.repository);logs=R.read_json(cfg['accountability_config'],a.repository)
        forbidden.update(R.private(f,repo=a.repository).read_bytes() for f in (cfg['key_file'],access['key_file'],logs['key_file']))
        require(not set(k.values())&forbidden,'Separate commitment/recovery keys required')
        salt=os.urandom(32);public=A.generate(selection,k['content'],k['publication'],salt=salt)
        job=dict(policy='APPLICATION_FINDINGS_PREPARED_JOB_V1',selection=selection,public=public,salt=salt.hex(),code_revision=revision,prepared_at=time.time())
        pins.check();permit.check(snapshot);verify_scope(store,snapshot,job,k);ident=save_job(a.state_root,job,k)
        store.accountability.append({**event,'outcome':'ALLOWED'})
        return dict(status='FINDINGS_PREFIX_PREPARED_NOT_SUBMITTED',publication_id=ident,entry_count=len(selection['entries']),chain_submitted=False)
    require(a.publication and a.fabric_config and a.fabric_sha256 and a.network_config and a.network_sha256 and a.deployment_passed and a.wallet_root and a.backup_wallet_root,'Exact verified chain configuration paths/pins required')
    job=load_job(a.state_root,a.publication,k,a.repository);verify_scope(store,snapshot,job,k)
    require(job['policy']=='APPLICATION_FINDINGS_PREPARED_JOB_V1' and job['public']['publication_id']==a.publication)
    if a.action=='execute':require(job['code_revision']==revision,'Execute requires original prepared revision')
    deployment=R.read_json(a.deployment_passed,a.repository)
    require(deployment['policy']=='SEPOLIA_FINDINGS_CONTRACT_DEPLOYMENT_V1' and deployment['status']=='PASSED' and deployment['finalized'] is True and deployment['two_rpc_readback'] is True,'Dedicated finalized findings deployment required')
    directory=a.state_root/'jobs'/a.publication
    worker=dict(policy='APPLICATION_FINDINGS_CHAIN_JOB_V1',mode=a.action.upper(),fabric_config=str(a.fabric_config),fabric_sha256=a.fabric_sha256,
        network_config=str(a.network_config),network_sha256=a.network_sha256,destination=dict(chain_id=11155111,contract=deployment['contract_address'].lower(),runtime_sha256=deployment['artifact']['runtime_sha256'],writer=deployment['writer'].lower(),namespace='findings-anchor-v1',finality='FINALIZED'),
        wallet_root=str(a.wallet_root),wallet_backup=str(a.backup_wallet_root),recovery_key=str(a.state_root/'recovery.key'),directory=str(directory),payload=A.fabric_payload(job['public']))
    worker_file=directory/'worker-'+a.action+'.json'
    if worker_file.exists():require(R.read_json(worker_file,a.repository)==worker,'Original worker configuration differs')
    else:G.write(worker_file,worker)
    operation_pins=SourcePins([a.state_root/'keys.json',a.state_root/'backup/keys.json',a.state_root/'recovery.key',worker_file,a.deployment_passed,a.fabric_config,a.network_config,a.state_root/'jobs'/a.publication/'job.encrypted.json'])
    def check():
        pins.check();operation_pins.check();permit.check(snapshot);require(C.revision(a.repository)==revision);verify_scope(store,snapshot,job,k)
    try:
        result=run_worker(['node',str(a.repository/'blockchain/public/findings/application-anchor-worker.js'),str(worker_file)],check)
        O.validate(result,job['public'],worker['destination']);O.record(store,job['selection'],job['public'],result,worker['destination'])
        observation=directory/('observation-'+str(uuid4())+'.json');G.write(observation,result)
        store.accountability.append({**event,'outcome':'ALLOWED'})
        return dict(status=result['status'],publication_id=a.publication,scope='APPLICATION_FINDINGS_PREFIX_ONLY',original_data_changed=False,independent_witness_deployment_verified=False)
    except Exception:
        store.accountability.append({**event,'outcome':'FAILED'});raise

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['initialize','prepare','execute','reconcile','status'])
    for name in ('repository','state-root','app-root'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('connection-root','audit-gate-attempt','fabric-config','network-config','deployment-passed','wallet-root','backup-wallet-root'):p.add_argument('--'+name,type=Path)
    for name in ('officer','publication','fabric-sha256','network-sha256'):p.add_argument('--'+name)
    a=p.parse_args();os.umask(0o077)
    try:print(json.dumps(operate(a),indent=2))
    except Exception as error:print(json.dumps(dict(status='STOPPED',error_type=type(error).__name__,recovery='INSPECT_OR_RECONCILE_ORIGINAL_PLANS',both_chains_anchored=False)));raise SystemExit(1)
