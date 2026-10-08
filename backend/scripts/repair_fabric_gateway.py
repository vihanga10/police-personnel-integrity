"""Repair only gateway code before the first test commitment; preserve the existing network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4
from app.identity.bind_evidence_destinations import private_path
from app.intake.registration_receipt import save_receipt

OLD_GATEWAY = 'dae9e9b724117a60456c962032faa6a3f758a061b1b60ae4869bbb4de0c7c12b'


def plan(root, repo):
    root = private_path(root, True)
    if root.resolve().is_relative_to(repo.resolve()): raise ValueError('Network root must remain outside Git.')
    config = json.loads(private_path(root/'gateway-config.json').read_text())
    if (config['channel'],config['chaincode']) != ('personnel','officer-evidence-test-v1'):
        raise ValueError('Unexpected test network.')
    block = private_path(root/'genesis.block')
    if hashlib.sha256(block.read_bytes()).hexdigest() != config['genesis_sha256']:
        raise ValueError('Saved genesis file differs.')
    checks = private_path(root/'recovery-checks', True)
    if any(checks.iterdir()): raise ValueError('Repair requires no submitted or prepared test commitments.')
    target = private_path(root/'runtime/client/gateway.js')
    if hashlib.sha256(target.read_bytes()).hexdigest() != OLD_GATEWAY:
        raise ValueError('Runtime gateway source differs.')
    helper = target.parent/'block-identity.js'
    if helper.exists() or helper.is_symlink(): raise ValueError('New runtime helper already exists.')
    source = repo/'blockchain/fabric/client'
    values = {}
    for name in ('gateway.js','block-identity.js'):
        p=source/name
        if not p.is_file() or any(q.is_symlink() for q in (p,*p.parents)):
            raise ValueError('Repository source path differs.')
        values[name]=p.read_bytes()
    return root,target,helper,values


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network-root',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    try:
        repo=Path(__file__).resolve().parents[2]
        if subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip():
            raise ValueError('Commit source before runtime repair.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        root,target,helper,values=plan(args.network_root,repo)
        original=target.read_bytes();attempt=root/('gateway-repair-'+uuid4().hex);attempt.mkdir(mode=0o700)
        (attempt/'gateway-original.js').write_bytes(original)
        staged=target.parent/('.gateway-repair-'+uuid4().hex+'.tmp')
        try:
            with helper.open('xb') as stream:stream.write(values['block-identity.js'])
            with staged.open('xb') as stream:stream.write(values['gateway.js'])
            os.replace(staged,target)
            save_receipt(dict(status='PASSED',code_revision=revision,old_gateway_sha256=OLD_GATEWAY,
                runtime_sources={n:hashlib.sha256(v).hexdigest() for n,v in values.items()},
                network_configuration_changed=False,research_commitments_submitted=0),attempt/'PASSED.json')
        except BaseException:
            target.write_bytes(original);helper.unlink(missing_ok=True);staged.unlink(missing_ok=True);raise
        print('Pre-submission Fabric gateway repair: PASSED')
        print('Original gateway backed up privately. Genesis file, credentials, configuration, ledger and journals unchanged.')
        return 0
    except Exception as error:
        print('Fabric gateway repair stopped:',type(error).__name__)
        print('Preserve the network and journals; no reset requested.')
        return 1


if __name__=='__main__':raise SystemExit(main())
