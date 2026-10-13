"""Create a new private findings read/publication network configuration; no RPC calls."""
import argparse,getpass,hashlib,json,os,sys
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.policy import require
from app.access import generated_connection as G,research_connection_runtime as R

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();os.umask(0o077)
    R.private(a.output.parent,directory=True,repo=a.repository);require(not a.output.exists() and not a.output.is_symlink(),'New configuration required; preserve existing pins')
    urls=[getpass.getpass('QuickNode Sepolia HTTPS URL (hidden): '),getpass.getpass('Alchemy Sepolia HTTPS URL (hidden): ')]
    hosts=[]
    for url in urls:
        u=urlsplit(url);require(u.scheme=='https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.port in (None,443) and u.path not in ('','/'),'Tokenized HTTPS provider required')
        require(u.hostname=='eth-sepolia.g.alchemy.com' or u.hostname.endswith('.quiknode.pro'),'Expected existing research providers');hosts.append(u.hostname)
    require(len(set(hosts))==2)
    config=dict(policy='FINDINGS_LIVE_SEPOLIA_NETWORK_V1',rpc_urls=urls,max_fee_gwei='5',priority_fee_gwei='1',max_total_fee_eth='0.025',confirmations=12)
    G.write(a.output,config);print(json.dumps(dict(status='PRIVATE_FINDINGS_NETWORK_PREPARED',file=str(a.output),sha256=hashlib.sha256(a.output.read_bytes()).hexdigest(),rpc_calls=0,chain_submitted=False)))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='STOPPED',error_type=type(e).__name__)));raise SystemExit(1)
