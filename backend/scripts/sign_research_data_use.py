"""Offline signature for an already reviewed custodian data-use authorization.

Does not grant legal permission, create a key, issue an audit permit or connect
the UI. The configured authority must actually hold the cited authorization.
"""
import argparse
import base64
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.access.policy import encoded, require
from app.access.research_connection import authorization, revision, POLICY
from app.access.research_connection_runtime import read_json, public_keys, signer
from app.access.store import private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('config', 'draft', 'signing-key', 'output'): parser.add_argument('--' + field, type=Path, required=True)
    parser.add_argument('--key-id', required=True); args = parser.parse_args()
    try:
        configfile = private(args.config); config = read_json(configfile, None)
        require(config['policy'] == POLICY, 'Connection configuration required')
        repo = Path(config['repository']).resolve(); private(configfile, repo=repo)
        keys = public_keys(config['authorization_keys']); key = signer(args.signing_key.absolute(), repo)
        require(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == keys[args.key_id], 'Custodian authority pin differs')
        draft = read_json(args.draft.absolute(), repo)
        envelope = dict(key_id=args.key_id, payload=draft, signature=base64.b64encode(key.sign(encoded(draft))).decode())
        authorization(envelope, keys, revision=revision(repo), officers=[])
        output = args.output.absolute(); private(output.parent, directory=True, repo=repo)
        with output.open('xb') as file:
            os.fchmod(file.fileno(), 0o600); file.write(encoded(envelope)); file.flush(); os.fsync(file.fileno())
        print('Reviewed authorization signed; no audit readiness or dataset activation issued.')
    except Exception: raise SystemExit('Data-use signing stopped. Reviewed authorization, current revision, authority pin and private paths are required.')


if __name__ == '__main__': main()
