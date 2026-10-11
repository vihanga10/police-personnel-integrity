"""Controlled loopback HTTPS UI launcher. No provisioning or research execution."""
import argparse
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.policy import require
from app.access.store import private

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--certificate',type=Path,required=True);p.add_argument('--tls-key',type=Path,required=True)
    args=p.parse_args();configfile=private(args.config);config=json.loads(configfile.read_text())
    require(config['policy']=='RESEARCH_WEB_CONFIG_V1','Workspace configuration required')
    access=json.loads(private(config['access_config']).read_text());repo=Path(access['repository'])
    private(configfile,repo=repo);cert=private(args.certificate,repo=repo);key=private(args.tls_key,repo=repo)
    require(key!=cert and key not in (Path(config['key_file']).resolve(),Path(access['key_file']).resolve()),'Separate TLS key required')
    origin=urlsplit(access['origin']);require(origin.scheme=='https' and origin.hostname in ('localhost','127.0.0.1'),'Loopback HTTPS origin required')
    os.environ['PPI_RESEARCH_CONFIG']=str(configfile)
    import uvicorn
    uvicorn.run('app.access.research_app:application',factory=True,host='127.0.0.1',port=origin.port or 443,
        workers=1,reload=False,proxy_headers=False,access_log=False,server_header=False,
        limit_concurrency=16,timeout_keep_alive=5,timeout_graceful_shutdown=10,ssl_certfile=str(cert),ssl_keyfile=str(key))

if __name__=='__main__':main()
