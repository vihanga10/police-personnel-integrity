"""Offline signing of exact access enrollment/membership/directory grants only.

Authority private material stays outside the repository and web server. This
command cannot issue research audit permits, findings approvals or chain grants.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.access.policy import account,encoded,require,signed
from app.access.directory import validate_directory
from app.access.store import private


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('config','authority-key','payload','output'):p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--key-id',required=True);args=p.parse_args()
    try:
        config=json.loads(private(args.config).read_text());repo=Path(config['repository']).resolve()
        private(args.config,repo=repo);require(config['policy']=='SCOPED_ACCESS_CONFIG_V1','Config differs')
        keys={k:base64.b64decode(v,validate=True) for k,v in config['authority_keys'].items()}
        key=Ed25519PrivateKey.from_private_bytes(private(args.authority_key,repo=repo).read_bytes())
        require(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==keys[args.key_id],'Authority pin differs')
        payload=json.loads(private(args.payload,repo=repo).read_text())
        require(payload['kind'] in ('ACCOUNT','MEMBERSHIP','DIRECTORY'),'Access-only signing domain required')
        envelope={'key_id':args.key_id,'payload':payload,'signature':base64.b64encode(key.sign(encoded(payload))).decode()}
        signed(envelope,keys,payload['kind'])
        if payload['kind']=='ACCOUNT':account(envelope,keys)
        elif payload['kind']=='DIRECTORY':validate_directory(envelope,keys)
        else:
            require(set(payload)=={'policy','kind','issued_at','expires_at','source_public_sha256','officers','review_reference'},'Membership fields differ')
        output=args.output.absolute();private(output.parent,directory=True,repo=repo)
        with output.open('xb') as file:
            os.chmod(file.fileno(),0o600);file.write(encoded(envelope));file.flush();os.fsync(file.fileno())
        print('Exact access grant signed privately. No account imported or chain permission issued.')
    except Exception:raise SystemExit('Access signing stopped. Check authority pin, domain, freshness, schema and private paths.')

if __name__=='__main__':main()
