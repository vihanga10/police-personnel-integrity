"""Explicit private access-state administration. Never modifies research storage.

Configuration and administrative grants must already be privately reviewed.
No shared/default user, public registration or administrator signing key is created.
"""
import argparse
import getpass
import json
from pathlib import Path
import sys
import warnings

# Supports python scripts/manage_scoped_access.py from the existing backend.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access.api import configured_store
from app.access.store import private
from app.access.policy import require


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('init','account','directory','status'))
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--envelope',type=Path)
    parser.add_argument('--set-password',action='store_true')
    args=parser.parse_args()
    try:
        store,origin=configured_store(args.config,create=args.action=='init')
        if args.action in ('account','directory'):
            require(args.envelope is not None,'Signed private envelope required')
            file=private(args.envelope,repo=store.repo)
            require(file.stat().st_size<=16*1024*1024,'Envelope too large')
            envelope=json.loads(file.read_text())
            if args.action=='account':
                password=None
                if args.set_password:
                    with warnings.catch_warnings():
                        warnings.simplefilter('error',getpass.GetPassWarning)
                        password=getpass.getpass('New password (hidden): ')
                        require(password==getpass.getpass('Confirm password (hidden): '),'Passwords differ')
                store.put_account(envelope,password)
            else: store.put_directory(envelope)
        elif args.envelope or args.set_password: raise ValueError('Inapplicable command option')
        print('Access administration completed:',args.action)
        print('Only the separate access store was selected; no research database or chain change.')
    except Exception:
        raise SystemExit('Access administration stopped. Check private config, signed grants, permissions and version; no default account was created.')

if __name__=='__main__':main()
