"""Create a separate local research network, enroll its anchorer and deploy test-only chaincode."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
from uuid import uuid4

from app.intake.registration_receipt import save_receipt
from app.identity.bind_evidence_destinations import private_path
from app.identity.generate_protected_commitments import private_output
from scripts.check_fabric_prerequisites import check

FABRIC = '2.5.16'
CA = '1.5.17'
CHANNEL = 'personnel'
CHAINCODE = 'officer-evidence-test-v1'
NAMES = {'orderer.example.com', 'peer0.org1.example.com', 'peer0.org2.example.com', 'ca_org1', 'ca_org2', 'ca_orderer'}
PORTS = (7050, 7051, 9051, 7053, 7054, 8054, 9054, 9443, 9444, 9445)


def preflight(output, repo, names, port_free, networks=(), volumes=()):
    output = output.expanduser().absolute()
    if output.resolve().is_relative_to(repo) or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('Private network root must be outside Git without symlinks.')
    if output.exists() and any(output.iterdir()): raise ValueError('New empty network directory required; existing material is preserved.')
    if NAMES.intersection(names) or 'fabric_test' in networks or any(
        v.endswith(('orderer.example.com', 'peer0.org1.example.com', 'peer0.org2.example.com')) for v in volumes):
        raise ValueError('Existing Fabric containers/network/ledger volumes must be preserved.')
    if not all(port_free(port) for port in PORTS): raise ValueError('Fabric endpoint port already occupied.')
    return output



def verify_version(content, expected):
    tokens = re.findall(r'(?im)^\s*version\s*:\s*([vV]?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\s*$', content)
    if len(tokens) != 1 or tokens[0].lstrip('vV') != expected:
        raise ValueError('Downloaded binary versions differ.')


def resume_pre_network(output, repo, names, port_free, networks=(), volumes=()):
    """Resume only the known pre-network version-check stop; never an existing ledger."""
    root = private_path(output, True)
    preflight(root/'preflight-only', repo, names, port_free, networks, volumes)
    allowed = {'SETUP_STARTED.json', 'release-source.json', 'release-source', 'fabric-samples', 'logs'}
    for item in root.iterdir():
        if item.name not in allowed and not re.fullmatch(r'SETUP_STOPPED-[0-9a-f]{32}\.json', item.name):
            raise ValueError('Resume requires the original pre-network stop only.')
    started = json.loads(private_path(root/'SETUP_STARTED.json').read_text())
    initial = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '6f6899a^{commit}'], text=True).strip()
    if started != dict(status='STARTED', code_revision=initial, fabric=FABRIC, ca=CA, channel=CHANNEL, chaincode=CHAINCODE):
        raise ValueError('Original setup receipt differs.')
    logs = private_path(root/'logs', True)
    phases = {'release_source', 'downloads', 'peer_binary_version', 'ca_binary_version'}
    if {p.name for p in logs.iterdir()} != {phase+suffix for phase in phases for suffix in ('.log', '.json')}:
        raise ValueError('Resume cannot follow a network-start attempt or other phase.')
    for phase in phases:
        if json.loads(private_path(logs/(phase+'.json')).read_text()) != dict(phase=phase, status='PASSED'):
            raise ValueError('Incomplete download phase.')
    verify_version(private_path(logs/'peer_binary_version.log').read_text(), FABRIC)
    verify_version(private_path(logs/'ca_binary_version.log').read_text(), CA)
    for binary in (root/'fabric-samples/bin/peer', root/'fabric-samples/bin/fabric-ca-client'):
        if not binary.is_file() or any(p.is_symlink() for p in (binary, *binary.parents)):
            raise ValueError('Downloaded binary path differs.')
    release = root/'release-source'
    if any(p.is_symlink() for p in (release, *release.parents)):
        raise ValueError('Source path traverses symlink.')
    receipt = json.loads(private_path(root/'release-source.json').read_text())
    head = subprocess.check_output(['git', '-C', str(release), 'rev-parse', 'HEAD'], text=True).strip()
    digest = hashlib.sha256((release/'scripts/install-fabric.sh').read_bytes()).hexdigest()
    if receipt != dict(release_commit=head, installer_sha256=digest):
        raise ValueError('Captured installer binding differs.')
    for source in (release, root/'fabric-samples'):
        if source.is_symlink() or any(p.is_symlink() for p in source.parents):
            raise ValueError('Source path traverses symlink.')
        for args in (('diff', '--exit-code'), ('diff', '--cached', '--exit-code')):
            if subprocess.run(['git', '-C', str(source), *args], capture_output=True).returncode:
                raise ValueError('Downloaded tracked sources differ.')
    return root


def free(port):
    with socket.socket() as sock:
        try: sock.bind(('127.0.0.1', port)); return True
        except OSError: return False


def one(directory):
    candidates = [p for p in directory.iterdir() if p.is_file() and not p.is_symlink()]
    if len(candidates) != 1: raise ValueError('Expected one certificate/key file.')
    return candidates[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network-root', type=Path, required=True)
    parser.add_argument('--resume-pre-network', action='store_true', help='Resume only the verified v-prefix check stop before network creation.')
    args = parser.parse_args(); root = None
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[2]
        if subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip():
            raise ValueError('Commit source before network setup.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        check()
        names = set(subprocess.check_output(['docker', 'ps', '-a', '--format', '{{.Names}}'], text=True).splitlines())
        networks = subprocess.check_output(['docker', 'network', 'ls', '--format', '{{.Name}}'], text=True).splitlines()
        volumes = subprocess.check_output(['docker', 'volume', 'ls', '--format', '{{.Name}}'], text=True).splitlines()
        if args.resume_pre_network:
            root = resume_pre_network(args.network_root, repo, names, free, networks, volumes)
            save_receipt(dict(status='RESUMED_BEFORE_NETWORK', code_revision=revision), root/'SETUP_RESUMED.json')
            logs = root/'logs'
        else:
            root = preflight(args.network_root, repo, names, free, networks, volumes)
            root = private_output(root, repo)
            save_receipt(dict(status='STARTED', code_revision=revision, fabric=FABRIC, ca=CA, channel=CHANNEL, chaincode=CHAINCODE), root/'SETUP_STARTED.json')
            logs = root/'logs'; logs.mkdir(mode=0o700)
        def run(phase, command, cwd=root, env=None):
            print('Fabric setup phase:', phase, flush=True)
            log = logs/(phase+'.log')
            with log.open('xb') as stream:
                os.chmod(log, 0o600)
                result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
            if result.returncode: raise RuntimeError('External setup phase failed: '+phase)
            save_receipt(dict(phase=phase, status='PASSED'), logs/(phase+'.json'))
        if not args.resume_pre_network:
            run('release_source', ['git', 'clone', '--depth', '1', '--branch', 'v'+FABRIC, 'https://github.com/hyperledger/fabric.git', str(root/'release-source')])
            installer = root/'release-source/scripts/install-fabric.sh'
            save_receipt(dict(release_commit=subprocess.check_output(['git', '-C', str(root/'release-source'), 'rev-parse', 'HEAD'], text=True).strip(),
                              installer_sha256=hashlib.sha256(installer.read_bytes()).hexdigest()), root/'release-source.json')
            run('downloads', ['bash', str(installer), '--fabric-version', FABRIC, '--ca-version', CA, 'docker', 'samples', 'binary'])
        samples = root/'fabric-samples'; network = samples/'test-network'
        prefix = 'resume_' if args.resume_pre_network else ''
        run(prefix+'peer_binary_version', [str(samples/'bin/peer'), 'version'])
        run(prefix+'ca_binary_version', [str(samples/'bin/fabric-ca-client'), 'version'])
        verify_version((logs/(prefix+'peer_binary_version.log')).read_text(), FABRIC)
        verify_version((logs/(prefix+'ca_binary_version.log')).read_text(), CA)
        sample_commit = subprocess.check_output(['git', '-C', str(samples), 'rev-parse', 'HEAD'], text=True).strip()
        save_receipt(dict(samples_commit=sample_commit, network_script_sha256=hashlib.sha256((network/'network.sh').read_bytes()).hexdigest()), root/'sample-source.json')
        # Official sample scripts use fixed names/ports; preflight refuses collisions before creation.
        run('network_start', ['bash', './network.sh', 'up', 'createChannel', '-ca', '-c', CHANNEL, '-i', FABRIC, '-cai', CA], network)
        organizations = network/'organizations'
        org = organizations/'peerOrganizations/org1.example.com'
        tls_ca = organizations/'fabric-ca/org1/tls-cert.pem'
        env = dict(os.environ, PATH=str(samples/'bin')+os.pathsep+os.environ.get('PATH', ''), FABRIC_CA_CLIENT_HOME=str(org))
        secret = os.urandom(32).hex()
        save_receipt(dict(enrollment_name='evidence-anchorer', enrollment_secret=secret), root/'anchorer-enrollment-secret.json')
        run('anchorer_register', ['fabric-ca-client', 'register', '--caname', 'ca-org1', '--id.name', 'evidence-anchorer',
            '--id.secret', secret, '--id.type', 'client', '--id.attrs', 'evidence.anchor=true:ecert', '--tls.certfiles', str(tls_ca)], network, env)
        wallet = root/'anchorer-msp'
        run('anchorer_enroll', ['fabric-ca-client', 'enroll', '-u', 'https://evidence-anchorer:'+secret+'@localhost:7054',
            '--caname', 'ca-org1', '-M', str(wallet), '--tls.certfiles', str(tls_ca)], network, env)
        shutil.copyfile(org/'msp/config.yaml', wallet/'config.yaml')
        runtime = root/'runtime'; runtime.mkdir(mode=0o700)
        # Copy source only. Never copy repository credentials, datasets or attempt artifacts.
        for name in ('chaincode', 'client'):
            source = repo/'blockchain/fabric'/name
            target = runtime/name; target.mkdir(mode=0o700)
            for path in source.rglob('*'):
                if path.is_file() and path.suffix in ('.js', '.json') and not path.is_symlink() and 'node_modules' not in path.parts:
                    destination = target/path.relative_to(source); destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    shutil.copyfile(path, destination)
            run(name+'_lock', ['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], target)
            run(name+'_dependencies', ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], target)
        run('chaincode_deploy', ['bash', './network.sh', 'deployCC', '-c', CHANNEL, '-ccn', CHAINCODE,
            '-ccp', str(runtime/'chaincode'), '-ccl', 'javascript', '-ccv', '1.0', '-ccs', '1',
            '-ccep', "AND('Org1MSP.peer','Org2MSP.peer')"], network)
        org2 = organizations/'peerOrganizations/org2.example.com'
        ca_orderer = organizations/'ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt'
        peer_env = dict(env, CORE_PEER_TLS_ENABLED='true', CORE_PEER_LOCALMSPID='Org1MSP', CORE_PEER_MSPCONFIGPATH=str(wallet),
                        CORE_PEER_ADDRESS='localhost:7051', CORE_PEER_TLS_ROOTCERT_FILE=str(org/'peers/peer0.org1.example.com/tls/ca.crt'),
                        FABRIC_CFG_PATH=str(samples/'config'))
        genesis = root/'genesis.block'
        run('genesis_fetch', ['peer', 'channel', 'fetch', '0', str(genesis), '-c', CHANNEL, '-o', 'localhost:7050',
            '--ordererTLSHostnameOverride', 'orderer.example.com', '--tls', '--cafile', str(ca_orderer)], network, peer_env)
        reader = org/'users/User1@org1.example.com/msp'
        # Key/certificate files and client configuration remain owner-only; no secret reaches stdout.
        for directory in (wallet, reader, organizations):
            for path in directory.rglob('*'):
                if path.is_file() and not path.is_symlink(): os.chmod(path, path.stat().st_mode & ~0o077)
        config = dict(channel=CHANNEL, chaincode=CHAINCODE, genesis_sha256=hashlib.sha256(genesis.read_bytes()).hexdigest(),
            anchorer=dict(certificate=str(one(wallet/'signcerts')), private_key=str(one(wallet/'keystore'))),
            reader=dict(certificate=str(one(reader/'signcerts')), private_key=str(one(reader/'keystore'))), peers=[
                dict(msp_id='Org1MSP', endpoint='localhost:7051', hostname='peer0.org1.example.com', tls_certificate=str(org/'peers/peer0.org1.example.com/tls/ca.crt')),
                dict(msp_id='Org2MSP', endpoint='localhost:9051', hostname='peer0.org2.example.com', tls_certificate=str(org2/'peers/peer0.org2.example.com/tls/ca.crt'))])
        save_receipt(config, root/'gateway-config.json')
        checks = root/'recovery-checks'; checks.mkdir(mode=0o700)
        images = json.loads(subprocess.check_output(['docker', 'image', 'inspect', 'hyperledger/fabric-peer:'+FABRIC,
            'hyperledger/fabric-orderer:'+FABRIC, 'hyperledger/fabric-ca:'+CA], text=True))
        summary = dict(status='PASSED', code_revision=revision, fabric=FABRIC, ca=CA, samples_commit=sample_commit,
            channel=CHANNEL, test_chaincode=CHAINCODE, genesis_sha256=config['genesis_sha256'],
            runtime_lockfiles={n:hashlib.sha256((runtime/n/'package-lock.json').read_bytes()).hexdigest() for n in ('client','chaincode')},
            docker_images=[dict(id=i['Id'], architecture=i['Architecture'], repo_digests=i.get('RepoDigests', [])) for i in images],
            research_commitments_submitted=0)
        save_receipt(summary, root/'SETUP_PASSED.json')
        print('Dedicated Fabric network setup/enrollment/deployment: PASSED'); print(json.dumps(summary, sort_keys=True))
        print('Next: real test-only recovery checker. No research commitments, personnel keys or databases used.')
        return 0
    except Exception as error:
        if root is not None and (root/'SETUP_STARTED.json').exists():
            save_receipt(dict(status='STOPPED', error_type=type(error).__name__), root/('SETUP_STOPPED-'+uuid4().hex+'.json'))
        print('Fabric network setup stopped:', type(error).__name__)
        print('Private setup logs, credentials and any created ledger remain preserved. Do not reset/delete; inspect the last phase before retrying.')
        return 1


if __name__ == '__main__': raise SystemExit(main())
