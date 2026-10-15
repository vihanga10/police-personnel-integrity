"""Operator-only exact retained-transaction recovery; never creates replacement IDs."""
import argparse,json,sys,time,socket
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.accountability_anchor import configuration,lock,journal,save,tick,run_worker,status
from app.access.policy import require
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--retry-retained',action='store_true');a=p.parse_args()
try:
    with socket.socket() as s:require(s.connect_ex(('127.0.0.1',8443))!=0,'Stop the app before operator recovery')
    store,_=configured(a.config);logs=store.accountability
    cfg,root,key=configuration(logs)
    with lock(root):
        jobs,_=journal(logs,root,key);pending=[(f,j) for f,j in jobs if j['phase']=='PENDING'];require(len(pending)==1,'Exactly one pending original batch required')
        f,j=pending[0];j['next_check_at']=0;save(f,j,key)
    tick(logs,lambda *args:run_worker(*args,retry_retained=a.retry_retained,read_only=not a.retry_retained))
    print(json.dumps(status(logs),indent=2))
except Exception as e:print(json.dumps({'status':'STOPPED','error_type':type(e).__name__,'reason':str(e)}));raise SystemExit(1)
