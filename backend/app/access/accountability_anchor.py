"""Automatic private Fabric commitments for exact encrypted accountability prefixes.

Raw events never leave the application. Retained plans are reconciled after uncertain
submission; a fresh transaction is never created to replace an attempted one.
"""
import base64,fcntl,hashlib,hmac,json,os,subprocess,time
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.policy import encoded,require
from app.access.store import private
POLICY='ACCOUNTABILITY_AUTOMATIC_FABRIC_V1'
FIELDS={'policy','state_directory','key_file','gateway_config','gateway_sha256','source_pins','interval_seconds','batch_events'}
def fingerprint(v):return hashlib.sha256(encoded(v)).hexdigest()
def configuration(logs):
    file=private(logs.anchor_config,repo=logs.repo);cfg=json.loads(file.read_bytes())
    require(set(cfg)==FIELDS and cfg['policy']==POLICY,'Accountability anchor configuration differs')
    require(cfg['interval_seconds']==60 and cfg['batch_events']==100,'Approved batching policy differs')
    root=private(cfg['state_directory'],directory=True,repo=logs.repo)
    require(not root.is_relative_to(logs.root) and not logs.root.is_relative_to(root),'Separate anchor state required')
    key=private(cfg['key_file'],repo=logs.repo).read_bytes();require(len(key)==32 and key!=logs.key and key!=logs.access.key_path.read_bytes(),'Independent anchor key required')
    require(type(cfg['source_pins']) is dict and cfg['source_pins'],'Source pins required')
    for name,pin in cfg['source_pins'].items():
        require(type(name) is str and (name.startswith('blockchain/fabric/client/') or name.startswith('blockchain/fabric/accountability-chaincode/') or name in ('blockchain/fabric/integration/package.json','blockchain/fabric/integration/package-lock.json') or name in ('backend/app/access/accountability_anchor.py','backend/app/access/accountability.py','backend/app/access/accountability_activity.py')) and '..' not in Path(name).parts)
        source=logs.repo/name;require(not source.is_symlink() and hashlib.sha256(source.read_bytes()).hexdigest()==pin,'Anchor source changed')
    raw=private(cfg['gateway_config'],repo=logs.repo).read_bytes()
    require(hashlib.sha256(raw).hexdigest()==cfg['gateway_sha256'],'Pinned gateway changed')
    gateway=json.loads(raw);require(gateway['destination']['chaincode']=='accountability-anchor-v1')
    return cfg,root,key

def save(file,value,key):
    nonce=os.urandom(12);data=nonce+AESGCM(key).encrypt(nonce,encoded(value),file.name.encode())
    tmp=file.with_name('.'+file.name+'.pending')
    # A retained incomplete write stops this worker rather than overwriting unknown state.
    with tmp.open('xb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,file)
    fd=os.open(file.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read(file,key,repo,*,aad_name=None):
    raw=private(file,repo=repo).read_bytes();require(len(raw)<=2*1024*1024)
    return json.loads(AESGCM(key).decrypt(raw[:12],raw[12:],(aad_name or file.name).encode()))

@contextmanager
def lock(root):
    path=root/'worker.lock'
    if not path.exists():
        try:
            with path.open('xb') as f:os.fchmod(f.fileno(),0o600)
        except FileExistsError:pass
    private(path)
    with path.open('r+b') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(f,fcntl.LOCK_UN)

def ledger_snapshot(logs):
    with logs.locked() as c:
        rows,_=logs.verify(c,recover=True)
        raw=c.execute('SELECT seq,previous,value,digest FROM events ORDER BY seq').fetchall()
    return rows,raw

def make_batch(logs,key,start,end,*,snapshot=None):
    rows,all_raw=snapshot if snapshot is not None else ledger_snapshot(logs)
    require(1<=start<=end<=len(rows))
    raw=all_raw[start-1:end]
    material=[(seq,prior,blob.hex(),digest) for seq,prior,blob,digest in raw]
    content={'policy':POLICY,'start':start,'end':end,'prior':raw[0][1],'head':raw[-1][3],'events':material}
    commit=lambda label,v:hmac.new(key,encoded([POLICY,label,v]),hashlib.sha256).hexdigest()
    handle=commit('BATCH',content)
    payload={'policy':'ACCOUNTABILITY_FABRIC_ANCHOR_V1','namespace':'accountability-anchor-v1',
      'publication_id':handle,'public_sha256':commit('CONTENT',content),
      'merkle_root':commit('COMPLETE_RANGE',material),'publication_commitment':commit('BINDING',content)}
    # merkle_root is a retained contract field: use the actual domain-separated Merkle tree.
    from app.identity.protected_commitment import merkle_root
    payload['merkle_root']=merkle_root([{'kind':'ACCOUNTABILITY_EVENT','handle':commit('SEQUENCE',v[0]),'commitment':commit('EVENT',v)} for v in material])
    payload['publication_commitment']=commit('PUBLICATION',payload)
    return {'policy':POLICY,'start':start,'end':end,'head':raw[-1][3],'payload':payload}

def journal(logs,root,key):
    jobs=[];end=0
    paths=sorted(root.glob('batch-*.encrypted'))
    snapshot=ledger_snapshot(logs)
    for path in paths:
        job=read(path,key,logs.repo);require(path.name==f"batch-{job['start']:020d}.encrypted",'Batch filename binding differs');require(job['start']==end+1,'Anchor journal gap or rollback')
        expected=make_batch(logs,key,job['start'],job['end'],snapshot=snapshot);require(all(job[k]==v for k,v in expected.items()),'Anchored log prefix changed')
        require(job['phase'] in ('PENDING','VERIFIED'))
        if job['phase']=='VERIFIED':
            receipt=job['receipt'];require(receipt['status']=='FINAL' and receipt['payload']==job['payload'] and
                receipt['verification']['organizations']==['Org1MSP','Org2MSP'] and receipt['verification']['validation_code']=='VALID')
            end=job['end']
        else:require(not any(j['phase']=='PENDING' for _,j in jobs),'Multiple pending batches')
        jobs.append((path,job))
    return jobs,end

def status(logs):
    if not getattr(logs,'anchor_config',None):return {'status':'NOT_CONFIGURED','private_chain_verified':False,'public_chain_anchored':False}
    try:
        cfg,root,key=configuration(logs)
        jobs,end=journal(logs,root,key)
        with logs.locked() as c:rows,_=logs.verify(c)
        interrupted_write=any(root.glob('.batch-*.encrypted.pending'))
        pending=next((j for _,j in jobs if j['phase']=='PENDING'),None)
        latest=next((j for _,j in reversed(jobs) if j['phase']=='VERIFIED'),None)
        return {'status':'INTERRUPTED_WRITE_PENDING_RECOVERY' if interrupted_write else ('FAILED_PENDING_RECOVERY' if pending and pending.get('last_error') else 'PENDING') if pending else 'NEW_EVENTS_PENDING' if len(rows)>end else 'VERIFIED_THROUGH_SEQUENCE' if end else 'WAITING_FOR_EVENTS',
          'anchored_through_sequence':end,'latest_local_sequence':len(rows),'unanchored_events':len(rows)-end,
          'private_chain_verified':bool(end),'public_chain_anchored':False,
          'last_verified_at':latest.get('verified_at') if latest else None,
          'transaction_id':latest['receipt']['transaction_id'] if latest else None,
          'organizations':['Org1MSP','Org2MSP'] if latest else [],'observation':'RETAINED_VERIFIED_RECEIPT_NOT_A_FRESH_CHAIN_READ',
          'batch_seconds':60,'batch_events':100}
    except Exception:return {'status':'VERIFICATION_FAILED','private_chain_verified':False,'public_chain_anchored':False}

def run_worker(logs,cfg,root,key,job,*,retry_retained=False,read_only=False):
    directory=root/('transaction-'+job['payload']['publication_id'])
    if not directory.exists():directory.mkdir(mode=0o700)
    private(directory,directory=True,repo=logs.repo)
    request={'repo':str(logs.repo),'config':cfg['gateway_config'],'config_sha256':cfg['gateway_sha256'],
      'directory':str(directory),'key_file':cfg['key_file'],'payload':job['payload'],'source_pins':cfg['source_pins'],'retry_retained':retry_retained,'read_only':read_only}
    command=['node',str(logs.repo/'blockchain/fabric/client/accountability-worker.js')]
    result=subprocess.run(command,input=encoded(request),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=150,cwd=logs.repo)
    require(len(result.stdout)<=16384 and result.returncode==0,'Private-chain worker unavailable; retained plans require reconciliation')
    answer=json.loads(result.stdout);require(set(answer)=={'receipt'},'Worker response differs')
    return answer['receipt']

def recover_pending(logs,root,key):
    # Complete a fully authenticated interrupted atomic write; never discard unknown bytes.
    import re
    for temp in sorted(root.glob('.batch-*.encrypted.pending')):
        require(re.fullmatch(r'\.batch-[0-9]{20}\.encrypted\.pending',temp.name),'Unknown pending write')
        target=root/temp.name[1:-8]
        value=read(temp,key,logs.repo,aad_name=target.name)
        require(target.name==f"batch-{value['start']:020d}.encrypted",'Pending filename differs')
        expected=make_batch(logs,key,value['start'],value['end'])
        require(all(value[k]==v for k,v in expected.items()) and value['phase'] in ('PENDING','VERIFIED'),'Pending write binding differs')
        if target.exists():
            previous=read(target,key,logs.repo)
            require(all(previous[k]==v for k,v in expected.items()),'Pending write changes batch')
            require(previous['phase']!='VERIFIED' or previous==value,'Verified batch rollback refused')
        if value['phase']=='VERIFIED':
            receipt=value['receipt'];require(receipt['payload']==value['payload'] and receipt['status']=='FINAL' and receipt['verification']['validation_code']=='VALID' and receipt['verification']['organizations']==['Org1MSP','Org2MSP'])
        # Re-fsync exact bytes before publishing the recovered pointer.
        with temp.open('rb') as f:os.fsync(f.fileno())
        os.replace(temp,target)
        fd=os.open(root,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)

def tick(logs,worker=run_worker):
    cfg,root,key=configuration(logs)
    with lock(root):
        recover_pending(logs,root,key)
        jobs,end=journal(logs,root,key);pending=next(((p,j) for p,j in jobs if j['phase']=='PENDING'),None)
        if pending:path,job=pending
        else:
            with logs.locked() as c:rows,_=logs.verify(c)
            remaining=len(rows)-end
            if not remaining:return
            first=rows[end][1]['recorded_at']
            from datetime import datetime
            if remaining<100 and logs.clock()-datetime.fromisoformat(first).timestamp()<60:return
            job={**make_batch(logs,key,end+1,min(end+100,len(rows))),'phase':'PENDING'}
            path=root/f"batch-{job['start']:020d}.encrypted";save(path,job,key)
        if time.time()<job.get('next_check_at',0):return
        try:
            receipt=worker(logs,cfg,root,key,job)
            require(configuration(logs)[0]==cfg,'Configuration changed during anchoring')
            require(receipt['status']=='FINAL' and receipt['payload']==job['payload'] and
              receipt['verification']['validation_code']=='VALID' and receipt['verification']['organizations']==['Org1MSP','Org2MSP'])
            require(make_batch(logs,key,job['start'],job['end'])['payload']==job['payload'],'Log prefix changed during anchoring')
            job.update(phase='VERIFIED',receipt=receipt,verified_at=time.time());job.pop('last_error',None);job.pop('next_check_at',None)
        except Exception:
            job.update(last_error='ANCHOR_UNCERTAIN_OR_UNAVAILABLE_RECONCILE_RETAINED_PLAN',next_check_at=time.time()+60)
        save(path,job,key)
