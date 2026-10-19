"""Explicit configured HTTPS launcher; no proxy-header trust, reload or extra worker.

No state initialization, account provisioning, source import or research execution.
"""
import argparse
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.store import private
from app.access.policy import require
import json
from urllib.parse import urlsplit


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--certificate',type=Path,required=True)
    p.add_argument('--tls-key',type=Path,required=True)
    # Hosting on AWS is a later deployment operation; this launcher binds loopback only.
    args=p.parse_args()
    config_file=private(args.config);config=json.loads(config_file.read_text());repo=Path(config['repository'])
    private(config_file,repo=repo)
    certificate=private(args.certificate,repo=repo);key=private(args.tls_key,repo=repo)
    require(certificate!=key and key!=Path(config['key_file']).resolve(),'Separate TLS and storage keys required')
    origin=urlsplit(config['origin']);require(origin.scheme=='https' and origin.hostname in ('127.0.0.1','localhost'),
                                            'This controlled launcher requires a loopback HTTPS origin')
    os.environ['PPI_ACCESS_CONFIG']=str(config_file)
    import uvicorn
    uvicorn.run('app.access.api:application',factory=True,host='127.0.0.1',port=origin.port or 443,
                workers=1,reload=False,proxy_headers=False,access_log=False,server_header=False,
                limit_concurrency=16,timeout_keep_alive=5,timeout_graceful_shutdown=10,
                ssl_certfile=str(certificate),ssl_keyfile=str(key))

if __name__=='__main__':main()
