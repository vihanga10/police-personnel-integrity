"""Offline signing of explicitly reviewed presentation/disclosure drafts only."""
import argparse
import base64
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.research_app import configured
from app.access import research_policy as P
from app.access.policy import encoded,require
from app.access.store import private

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('config','draft','signing-key','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--key-id',required=True);args=p.parse_args()
    try:
        store,_=configured(args.config)
        draftfile=private(args.draft,repo=store.repo);require(draftfile.stat().st_size<=16*1024*1024,'Bounded draft required')
        value=json.loads(draftfile.read_text());key=Ed25519PrivateKey.from_private_bytes(private(args.signing_key,repo=store.repo).read_bytes())
        require(args.key_id in store.keys and key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==store.keys[args.key_id],'Configured offline signer required')
        envelope=dict(key_id=args.key_id,payload=value,signature=base64.b64encode(key.sign(encoded(value))).decode())
        if value.get('kind')=='PRESENTATION':P.packet(envelope,store.keys,store.clock())
        elif value.get('kind')=='DISCLOSURE':P.grant(envelope,store.keys,store.clock())
        else:raise ValueError('Unsupported signing domain')
        output=args.output.absolute();private(output.parent,directory=True,repo=store.repo)
        require(not output.exists() and not output.is_symlink(),'New private output required')
        with output.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(encoded(envelope));stream.flush();os.fsync(stream.fileno())
        print('Explicitly reviewed workspace draft signed; not imported or activated. Existing sessions require sign-in again.')
    except Exception:raise SystemExit('Workspace signing stopped. No authority was inferred and no default grant was issued.')

if __name__=='__main__':main()
