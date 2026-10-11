"""Explicit administration of the separate encrypted UI cache/request store."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.policy import require
from app.access.store import private

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('init','presentation','disclosure','check'))
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--envelope',type=Path)
    args=parser.parse_args()
    try:
        store,_=configured(args.config,create=args.action=='init')
        if args.action in ('presentation','disclosure'):
            require(args.envelope is not None,'Private signed envelope required')
            file=private(args.envelope,repo=store.repo)
            require(file.stat().st_size <= 16*1024*1024,'Bounded envelope required')
            envelope=json.loads(file.read_text())
            (store.import_packet if args.action=='presentation' else store.import_grant)(envelope)
        else: require(args.envelope is None,'Inapplicable envelope')
        print('Separate workspace administration completed:',args.action)
        print('No research database, findings decision or blockchain submission selected. Existing sessions require sign-in again.')
    except Exception:
        raise SystemExit('Workspace administration stopped. Check private configuration, signature, generation and disclosure assessment. No default data or account was created.')

if __name__=='__main__':main()
