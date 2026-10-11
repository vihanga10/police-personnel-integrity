"""Actual mTLS selection from configured encrypted findings; no original batch."""
from copy import deepcopy
import socket
import pytest
from app.access import research_connection_runtime as R
from app.identity import witness_secure_transport as T
from research_connection_fixture import write, pins, seed
from test_findings_tip_witness import witnessed_findings, append, registered, journal
from test_encrypted_findings_journal import output, witnessed, setup, verified, keys, OFFICER
from test_witness_secure_transport import certs, listener


@pytest.fixture
def configured_findings(witnessed_findings, tmp_path):
    d = witnessed_findings; append(d); r = d['t']['r']; j = r.journal
    pki = certs(tmp_path / 'connection-pki', d['t']['d']['t']['s']['clock'][0])
    control = tmp_path / 'connection-control'; control.mkdir(mode=0o700)
    with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    profile = control / 'profile.json'
    pin = T.provision(d['server'], profile_path=profile, endpoint=f'https://127.0.0.1:{port}' + T.PATH,
        ca_certificate=pki['ca'], server_certificate=pki['server'], server_key=pki['server_key'], client_certificates={r.key_id: pki['client']})
    witness = dict(witness_id=d['args']['witness_id'], witness_keys=pins(d['args']['witness_keys']),
        profile=str(profile), profile_sha256=pin, ca_certificate=str(pki['ca']), client_certificate=str(pki['client']), client_key=str(pki['client_key']))
    config = dict(policy='RESEARCH_FINDINGS_RUNTIME_V1',
        journal=dict(root=str(j.root), ledger_id=j.ledger_id, officer_uid=j.officer_uid,
            crypto={'primary': str(tmp_path / 'primary.json'), 'backup': str(tmp_path / 'backup.json')},
            signing_key=str(write(control / 'journal.key', seed(j.signer))), key_id=j.key_id,
            writer_keys=pins(j.writer_keys), reviewer_keys=pins(j.reviewer_keys), authority_keys={}, reviewer_identities={}, authority_scopes={}),
        registry=dict(root=str(r.root), registry_id=r.registry_id,
            crypto={'primary': str(tmp_path / 'tip-primary.json'), 'backup': str(tmp_path / 'tip-backup.json')},
            signing_key=str(write(control / 'registry.key', seed(r.signer))), key_id=r.key_id,
            registry_keys=pins(r.registry_keys), recovery_keys=pins(r.recovery_keys), witness=witness))
    transport = dict(t={'server': d['server']}, port=port, server_args=dict(profile_path=profile,
        expected_profile_sha256=pin, ca_certificate=pki['ca'], server_certificate=pki['server'], server_key=pki['server_key']))
    return dict(config=config, file=write(control / 'findings.json', config), repo=j.repo, transport=transport, original=d)


def test_findings_runtime_reads_real_witness_and_preserves_journals(configured_findings):
    t = configured_findings; d = t['original']
    before = {p: p.read_bytes() for root in (d['server'].root, d['t']['r'].root, d['t']['r'].journal.root) for p in root.iterdir()}
    with listener(t['transport']):
        selected = R.findings(t['file'], t['repo'], OFFICER).select()
    assert len(selected['entries']) == 1 and selected['entries'][0]['entry']['kind'] == 'FINDING'
    assert all(p.read_bytes() == data for p, data in before.items())


@pytest.mark.parametrize('fault', ['officer', 'scope-text', 'witness-scope', 'fixture', 'key-domain'])
def test_findings_runtime_configuration_fails_closed(configured_findings, fault):
    t = configured_findings; c = deepcopy(t['config'])
    if fault == 'officer': c['journal']['officer_uid'] = '00000000-0000-0000-0000-000000000777'
    if fault == 'scope-text': c['journal']['authority_scopes'] = {'authority': 'ALL'}
    if fault == 'witness-scope': c['registry']['witness']['witness_id'] = 'foreign-witness'
    if fault == 'fixture': c['registry']['fixture_transport'] = True
    if fault == 'key-domain': c['registry']['recovery_keys'] = c['journal']['reviewer_keys']
    write(t['file'], c)
    with listener(t['transport']):
        with pytest.raises(Exception): R.findings(t['file'], t['repo'], OFFICER).select()
