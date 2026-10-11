"""Export a private name/NIC signing draft after full original anchored replay.

An externally reviewed signed MEMBERSHIP envelope supplies current web scope.
No CSV event timestamp is treated as a system date; no posting text grants scope.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.directory import export_directory
from app.access.policy import encoded,require
from app.access.store import private


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--membership',type=Path,required=True)
    p.add_argument('--generation',type=int,required=True)
    p.add_argument('--output',type=Path,required=True)
    for field in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
                  'bundle-attempt','binding-attempt','commitment-attempt','audit-gate-attempt'):
        p.add_argument('--'+field,type=Path,required=True)
    args=p.parse_args()
    try:
        repo=args.repository.resolve()
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(), 'Committed source required')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        config=json.loads(private(args.config,repo=repo).read_text())
        require(config['policy']=='SCOPED_ACCESS_CONFIG_V1' and Path(config['repository']).resolve()==repo,'Configured repository differs')
        keys={k:base64.b64decode(v,validate=True) for k,v in config['authority_keys'].items()}
        membership=json.loads(private(args.membership,repo=repo).read_text())
        output=args.output.absolute();private(output.parent,directory=True,repo=repo)
        require(not output.exists() and not output.is_symlink(),'New private draft required')
        draft=export_directory(args,repo,revision,membership,keys,generation=args.generation)
        with output.open('xb') as file:
            os.chmod(file.fileno(),0o600);file.write(encoded(draft));file.flush();os.fsync(file.fileno())
        print('Private directory signing draft exported; administrator signature still required before import.')
    except Exception:
        raise SystemExit('Directory export stopped. Fresh full replay readiness, current signed membership and private paths are required. No source or access-state change.')

if __name__=='__main__':main()
