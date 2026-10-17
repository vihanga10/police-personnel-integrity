"""Deploy the dedicated personnel-intake-anchor-v1 chaincode on the existing local network; never reset it.

preview checks prerequisites and records the existing definitions only.
execute installs, approves and commits sequence 1, then proves every
existing chaincode definition is unchanged on both organizations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.identity.bind_evidence_destinations import private_path
from app.identity.destination_binding import require
from app.intake.registration_receipt import save_receipt

CHAINCODE = 'personnel-intake-anchor-v1'
POLICY = "AND('Org1MSP.peer','Org2MSP.peer')"


def environment(network_root):
    samples = network_root / 'fabric-samples'
    network, orgs = samples / 'test-network', samples / 'test-network/organizations'
    env = dict(os.environ, PATH=str(samples / 'bin') + os.pathsep + os.environ.get('PATH', ''),
               FABRIC_CFG_PATH=str(samples / 'config'), CORE_PEER_TLS_ENABLED='true')

    def peer_env(number):
        org = orgs / ('peerOrganizations/org' + str(number) + '.example.com')
        return dict(env, CORE_PEER_LOCALMSPID='Org' + str(number) + 'MSP',
                    CORE_PEER_MSPCONFIGPATH=str(org / ('users/Admin@org' + str(number) + '.example.com/msp')),
                    CORE_PEER_ADDRESS='localhost:' + ('7051' if number == 1 else '9051'),
                    CORE_PEER_TLS_ROOTCERT_FILE=str(org / ('peers/peer0.org' + str(number) + '.example.com/tls/ca.crt')))
    return network, peer_env


def definitions(peer_env):
    out = {}
    for number in (1, 2):
        value = json.loads(subprocess.check_output(['peer', 'lifecycle', 'chaincode', 'querycommitted', '--channelID', 'personnel',
                                                    '--output', 'json'], env=peer_env(number), stderr=subprocess.PIPE, text=True))
        out['Org' + str(number) + 'MSP'] = {d['name']: d for d in value.get('chaincode_definitions', [])}
    require(out['Org1MSP'] == out['Org2MSP'], 'Organizations report different committed definitions.')
    return out['Org1MSP']


def main():
    home = Path.home() / 'ResearchKeys/police-personnel-integrity'
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['preview', 'execute'])
    p.add_argument('--network-root', type=Path, default=home / 'fabric-local-v1')
    p.add_argument('--state-root', type=Path, default=home / 'application-intake-v1')
    p.add_argument('--dependency-lock', type=Path, default=home / 'application-promotions-v1/fabric-deployment/chaincode/package-lock.json')
    args = p.parse_args()
    os.umask(0o077)
    repo = Path(__file__).resolve().parents[2]
    root = private_path(args.network_root, True)
    require(not root.resolve().is_relative_to(repo.resolve()), 'Network root must remain outside Git.')
    network, peer_env = environment(root)
    before = definitions(peer_env)
    require(CHAINCODE not in before, 'Intake chaincode already committed; inspect it, never replace it.')
    source = repo / 'blockchain/fabric/intake-chaincode'
    sources = {str(f.relative_to(source)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(source.rglob('*'))
               if f.is_file() and 'node_modules' not in f.parts and 'test' not in f.relative_to(source).parts}
    summary = dict(chaincode=CHAINCODE, existing=sorted(before), sources=sources)
    if args.mode == 'preview':
        print(json.dumps(dict(status='PREVIEW_PASSED', **summary), indent=2))
        return 0
    require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(), 'Commit source before deployment.')
    state = args.state_root
    if not state.exists():
        state.mkdir(mode=0o700)
    attempt = state / 'fabric-deployment'
    require(not attempt.exists(), 'Deployment already started; preserve and inspect it before recovery.')
    attempt.mkdir(mode=0o700)
    save_receipt(dict(status='STARTED', original_definitions=before, code_revision=subprocess.check_output(
        ['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(), **summary), attempt / 'STARTED.json')
    target = attempt / 'chaincode'
    for relative in sources:
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes((source / relative).read_bytes())
    lock = json.loads(private_path(args.dependency_lock).read_text())
    lock['name'] = lock['packages']['']['name'] = json.loads((target / 'package.json').read_text())['name']
    (target / 'package-lock.json').write_text(json.dumps(lock, indent=2) + '\n')

    def run(phase, command, cwd):
        print('Phase:', phase, flush=True)
        with (attempt / (phase + '.log')).open('xb') as log:
            result = subprocess.run(command, cwd=cwd, env=peer_env(1), stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        require(result.returncode == 0, 'Deployment phase failed: ' + phase)
    run('dependencies', ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--prefer-offline'], target)
    run('deployment', ['bash', './network.sh', 'deployCC', '-c', 'personnel', '-ccn', CHAINCODE, '-ccp', str(target),
                       '-ccl', 'javascript', '-ccv', '1.0', '-ccs', '1', '-ccep', POLICY], network)
    after = definitions(peer_env)
    added = after.get(CHAINCODE)
    require(added is not None and added['version'] == '1.0' and int(added['sequence']) == 1, 'Committed intake definition differs.')
    require({k: v for k, v in after.items() if k != CHAINCODE} == before, 'An existing chaincode definition changed.')
    save_receipt(dict(status='PASSED', channel='personnel', chaincode=CHAINCODE, organizations=['Org1MSP', 'Org2MSP'],
                      definition=added, original_definitions_unchanged=True, intake_publications_submitted=0), attempt / 'PASSED.json')
    print(json.dumps(dict(status='PASSED', chaincode=CHAINCODE, sequence=1, existing_unchanged=sorted(before)), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
