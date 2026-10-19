"""Bounded child protocol to the dedicated retained dual-chain coordinator."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
from .core import canonical, check
from app.access.store import private

def write_private(path, value):
    data=canonical(value)
    if path.exists():
        check(private(path).read_bytes()==data,'RETAINED_JOB_DIFFERS')
        return
    with path.open('xb') as f:
        os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

class ChainWorker:
    POLICY='APPLICATION_PROMOTIONS_CHAIN_JOB_V1'
    SCRIPT='blockchain/public/promotions/application-anchor-worker.js'
    def __init__(self,config,root,repo):self.config,self.root,self.repo=config,Path(root),Path(repo)
    def __call__(self,batch,payload,boundary,*,mode='EXECUTE'):
        check(mode in ('EXECUTE','RECONCILE','RETRY_FABRIC','RETRY_PUBLIC'),'WORKER_MODE_INVALID')
        directory=self.root/batch['batch_id']
        if not directory.exists():
            check(mode=='EXECUTE','ORIGINAL_CHAIN_JOB_REQUIRED')
            directory.mkdir(mode=0o700)
        private(directory,directory=True,repo=self.repo)
        j={k:self.config[k] for k in ('fabric_config','fabric_sha256','network_config','network_sha256',
            'destination','wallet_root','wallet_backup','recovery_key')}
        j.update(policy=self.POLICY,mode=mode,directory=str(directory),payload=payload)
        file=directory/('job.json' if mode=='EXECUTE' else ('read-only-job.json' if mode=='RECONCILE' else mode.lower()+'-job.json'));write_private(file,j)
        boundary()
        command=['node',str(self.repo/self.SCRIPT),str(file)]
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            cwd=self.repo,bufsize=0,start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        buffer=b'';result=None;deadline=time.monotonic()+600;requests=0
        try:
            while time.monotonic()<deadline:
                for key,_ in selector.select(timeout=1):
                    chunk=os.read(key.fd,65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer+=chunk;check(len(buffer)<=1024*1024,'WORKER_RESPONSE_LIMIT')
                    while b'\n' in buffer:
                        line,buffer=buffer.split(b'\n',1)
                        message=json.loads(line)
                        if message.get('request')=='SOURCE_CHECK':
                            requests+=1;check(requests<=200,'WORKER_REQUEST_LIMIT')
                            check(type(message.get('id')) is int,'WORKER_REQUEST_INVALID')
                            boundary()
                            child.stdin.write(canonical({'id':message['id'],'ok':True})+b'\n');child.stdin.flush()
                        elif 'result' in message:
                            check(result is None,'WORKER_DUPLICATE_RESULT');result=message['result']
                        else:check(False,'CHAIN_OPERATION_PENDING_OR_FAILED')
                if child.poll() is not None and not selector.get_map():break
            check(child.poll() is not None,'CHAIN_OPERATION_TIMEOUT')
            check(child.returncode==0 and result is not None and not buffer,'CHAIN_OPERATION_PENDING_OR_FAILED')
            boundary();return result
        finally:
            selector.close()
            if child.poll() is None:
                # Any attempted transaction remains retained. Never infer that
                # termination means a remote broadcast did not happen.
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            child.stdin.close();child.stdout.close()
