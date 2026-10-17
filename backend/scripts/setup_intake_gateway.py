"""Enrol the dedicated intake Fabric writer and prepare its pinned, verified gateway config.

Registers two single-enrolment Org1 CA identities: a writer carrying the
intake.anchor=true certificate attribute and a separate TLS client. Every CA
call is journaled (ATTEMPT before, DONE after); an attempt without DONE stops
for inspection instead of retrying. Nothing is endorsed or submitted.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.identity.bind_evidence_destinations import private_path
from app.identity.destination_binding import require
from app.intake.registration_receipt import save_receipt

HOME = Path.home() / 'ResearchKeys/police-personnel-integrity'
NETWORK = HOME / 'fabric-local-v1'
SETUP = HOME / 'application-intake-v1/fabric-gateway-setup'
REPO = Path(__file__).resolve().parents[2]
ORG1 = NETWORK / 'fabric-samples/test-network/organizations/peerOrganizations/org1.example.com'
ORG2 = NETWORK / 'fabric-samples/test-network/organizations/peerOrganizations/org2.example.com'
CA_CERT = ORG1 / 'msp/cacerts/localhost-7054-ca-org1.pem'
POLICY = 'PERSONNEL_INTAKE_AUTHENTICATED_GATEWAY_V2'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def ca(phase, arguments):
    attempt, done = SETUP / (phase + '.ATTEMPT.json'), SETUP / (phase + '.DONE.json')
    if done.exists():
        return
    require(not attempt.exists(), 'Interrupted CA step ' + phase + '; inspect the CA before any retry.')
    save_receipt({'phase': phase}, attempt)
    env = dict(os.environ, FABRIC_CA_CLIENT_HOME=str(SETUP / 'client-home'),
               PATH=str(NETWORK / 'fabric-samples/bin') + os.pathsep + os.environ.get('PATH', ''))
    (SETUP / 'logs').mkdir(mode=0o700, exist_ok=True)
    with (SETUP / 'logs' / (phase + '.log')).open('xb') as log:
        result = subprocess.run(['fabric-ca-client', *arguments, '--caname', 'ca-org1', '--tls.certfiles', str(CA_CERT)],
                                env=env, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    require(result.returncode == 0, 'CA step failed: ' + phase)
    save_receipt({'phase': phase, 'status': 'DONE'}, done)


def msp_pair(directory):
    cert = directory / 'signcerts/cert.pem'
    keys = list((directory / 'keystore').iterdir())
    require(len(keys) == 1, 'Exactly one enrolled private key required.')
    return {'certificate': str(cert), 'private_key': str(keys[0]), 'certificate_sha256': sha(cert), 'private_key_sha256': sha(keys[0])}


def main():
    os.umask(0o077)
    require((HOME / 'application-intake-v1/fabric-deployment/PASSED.json').exists(), 'Deploy the intake chaincode first.')
    for p in (SETUP, SETUP / 'client-home', SETUP / 'material'):
        p.mkdir(mode=0o700, exist_ok=True)
    plan_file = SETUP / 'PLAN.json'
    if not plan_file.exists():
        suffix = secrets.token_hex(8)
        save_receipt({'policy': 'INTAKE_GATEWAY_SETUP_PLAN_V1', 'identities': {
            role: {'name': 'research-intake-' + role + '-v1-' + suffix, 'secret': secrets.token_hex(32)} for role in ('writer', 'tls')}},
            plan_file)
    plan = json.loads(private_path(plan_file).read_text())['identities']
    registrar = ['-u', 'https://localhost:7054', '--mspdir', str(ORG1 / 'msp')]
    ca('writer-register', ['register', *registrar, '--id.name', plan['writer']['name'], '--id.secret', plan['writer']['secret'],
                           '--id.type', 'client', '--id.maxenrollments', '1', '--id.attrs', 'intake.anchor=true:ecert'])
    ca('tls-register', ['register', *registrar, '--id.name', plan['tls']['name'], '--id.secret', plan['tls']['secret'],
                        '--id.type', 'client', '--id.maxenrollments', '1'])
    for role in ('writer', 'tls'):
        ca(role + '-enroll', ['enroll', '-u', 'https://' + plan[role]['name'] + ':' + plan[role]['secret'] + '@localhost:7054',
                              '-M', str(SETUP / (role + '-msp')), '--csr.hosts', 'localhost'])
    text = subprocess.check_output(['openssl', 'x509', '-in', str(SETUP / 'writer-msp/signcerts/cert.pem'), '-noout', '-text'], text=True)
    require('"intake.anchor":"true"' in text and 'promotions.anchor' not in text, 'Writer certificate attribute differs.')
    for name, source in (('genesis.block', NETWORK / 'genesis.block'), ('org1-peer-ca.crt', ORG1 / 'peers/peer0.org1.example.com/tls/ca.crt'),
                         ('org2-peer-ca.crt', ORG2 / 'peers/peer0.org2.example.com/tls/ca.crt')):
        target = SETUP / 'material' / name
        if not target.exists():
            shutil.copyfile(source, target)
            target.chmod(0o600)
        require(sha(target) == sha(source), 'Copied network material differs.')
    material = SETUP / 'material'
    config = {'policy': POLICY, 'destination': {'genesis_sha256': sha(material / 'genesis.block'), 'channel': 'personnel',
              'chaincode': 'personnel-intake-anchor-v1', 'namespace': 'personnel-intake-anchor-v1', 'organizations': ['Org1MSP', 'Org2MSP']},
              'genesis_file': str(material / 'genesis.block'), 'genesis_identity': None,
              'identity': msp_pair(SETUP / 'writer-msp'), 'tls_client': msp_pair(SETUP / 'tls-msp'),
              'peers': [{'msp_id': 'Org' + n + 'MSP', 'endpoint': 'localhost:' + port, 'hostname': 'peer0.org' + n + '.example.com',
                         'tls_certificate': str(material / ('org' + n + '-peer-ca.crt')), 'tls_sha256': sha(material / ('org' + n + '-peer-ca.crt')),
                         'definition_sha256': '0' * 64} for n, port in (('1', '7051'), ('2', '9051'))]}
    draft = SETUP / 'draft-config.json'
    draft.write_text(json.dumps(config))
    draft.chmod(0o600)
    helper = REPO / 'blockchain/fabric/client/intake-gateway-setup.js'
    observed = json.loads(subprocess.check_output(['node', str(helper), 'definitions', str(draft)], cwd=REPO, text=True, timeout=300))
    draft.unlink()
    config['genesis_identity'] = observed['genesis_identity']
    for peer in config['peers']:
        peer['definition_sha256'] = observed['definitions'][peer['msp_id']]
    gateway = SETUP / 'intake-gateway.json'
    canonical = json.dumps(config, sort_keys=True, separators=(',', ':'))
    if gateway.exists():
        require(gateway.read_text() == canonical, 'Existing gateway config differs; inspect before replacing.')
    else:
        with gateway.open('x') as f:
            f.write(canonical)
        gateway.chmod(0o600)
    verified = json.loads(subprocess.check_output(['node', str(helper), 'verify', str(gateway), sha(gateway)], cwd=REPO, text=True, timeout=300))
    require(verified['status'] == 'READ_ONLY_GATEWAY_VERIFIED', 'Read-only gateway verification failed.')
    result = {'policy': POLICY, 'status': 'INTAKE_FABRIC_GATEWAY_VERIFIED', 'configuration_file': str(gateway),
              'configuration_sha256': sha(gateway), 'writer_attribute_verified': True, 'separate_tls_identity': True,
              'fresh_read_only_gateway_checked': True, 'organizations': ['Org1MSP', 'Org2MSP'], 'chain_submitted': False,
              'intake_publications_submitted': 0}
    save_receipt(result, SETUP / 'PASSED.json')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
