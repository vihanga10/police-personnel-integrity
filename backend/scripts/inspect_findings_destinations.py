"""Bounded filename/config-policy inventory. No keys, source rows or RPC access."""
import argparse,json,os
from pathlib import Path

def inventory(roots):
    found=[];errors=[];count=0;complete=True
    for root in roots:
        if not root.is_dir() or root.is_symlink():errors.append(str(root));continue
        for directory,folders,files in os.walk(root,followlinks=False,onerror=lambda e:errors.append(str(e.filename))):
            folders[:]=[n for n in folders if n not in {'.git','node_modules','.venv'} and not (Path(directory)/n).is_symlink()]
            for name in files:
                count+=1
                if count>10000:complete=False;folders.clear();break
                if name not in {'network.json','gateway.json','client-config.json','config.json','findings-gateway.json','findings-network.json'}:continue
                f=Path(directory)/name
                if f.is_symlink() or f.stat().st_size>1048576:continue
                try:
                    c=json.loads(f.read_bytes());policy=c.get('policy') if type(c) is dict else None
                    if policy:found.append(dict(path=str(f),policy=policy,dedicated_findings=policy in ('FINDINGS_AUTHENTICATED_GATEWAY_V1','FINDINGS_AUTHENTICATED_GATEWAY_V2','FINDINGS_LIVE_SEPOLIA_NETWORK_V1')))
                except Exception:errors.append(str(f))
            if not complete:break
        if not complete:break
    return dict(status='FINDINGS_DESTINATION_CONFIGURATION_INVENTORY',configurations=found,search_complete=complete and not errors,unreadable_or_missing=errors[:10],fresh_chain_verification=False,chain_submitted=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--network-root',type=Path,required=True);p.add_argument('--findings-root',type=Path,required=True);a=p.parse_args();print(json.dumps(inventory([a.network_root,a.findings_root]),indent=2))
