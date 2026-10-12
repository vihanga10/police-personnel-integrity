"""Connection acceptance with explicit original-loader substitution only."""
from copy import deepcopy
from datetime import timedelta
import json
import subprocess
import sys
import time
import pytest
from app.access import research_connection as C, research_connection_runtime as R
from app.access.policy import AccessError
from app.access.research_service import ResearchService
from app.identity import audit_gate as A
from app.identity.evidence_bundle_v2 import open_artifact
from research_connection_fixture import connected, setup, verified, keys, exported, inputs, signed, write, OFFICER, PASSWORD
from test_witness_secure_transport import listener
from scoped_access_fixture import grant, identifier


def test_local_check_authenticates_real_encrypted_permit_without_loader_or_network(connected):
    t = connected; before = t['store'].path.read_bytes()
    result = C.Connection(t['configfile']).check([OFFICER])
    assert result['status'] == 'LOCAL_PRECONDITIONS_VERIFIED' and result['source_replay_verified'] is False
    assert t['calls'] == [] and t['store'].path.read_bytes() == before

def test_accountability_config_is_compatible_pinned_and_key_separated(connected):
    import os
    t=connected;control=t['workspace_config'].parent
    root=control/'log-state';root.mkdir(mode=0o700)
    key=write(control/'log.key',os.urandom(32))
    file=write(control/'log-config.json',dict(policy='ACCOUNTABILITY_CONFIG_V1',
        state_directory=str(root),key_file=str(key),reader_grants=[]))
    cfg=json.loads(t['workspace_config'].read_text());cfg['accountability_config']=str(file)
    write(t['workspace_config'],cfg)
    connection=C.Connection(t['configfile'])
    assert connection.check()['status']=='LOCAL_PRECONDITIONS_VERIFIED'
    assert file in connection.pins and key in connection.pins
    write(key,(control/'workspace.key').read_bytes())
    with pytest.raises(ValueError):C.Connection(t['configfile'])


def test_base64_public_key_starting_slash_is_not_a_file_path(connected):
    import base64
    t = connected; runtime = deepcopy(t['runtime'])
    runtime['registry_keys']['extra-public-pin'] = base64.b64encode(b'\xfc' + b'A' * 31).decode()
    assert runtime['registry_keys']['extra-public-pin'].startswith('/')
    write(t['runtime_file'], runtime)
    assert C.Connection(t['configfile']).check()['status'] == 'LOCAL_PRECONDITIONS_VERIFIED'


def test_full_export_uses_one_loader_and_real_mtls_and_separate_unsigned_drafts(connected):
    t = connected; bundle = exported(t)
    assert len(t['calls']) == 1 and bundle['signed'] is False and bundle['ui_connected'] is False
    assert bundle['directory']['officers'][0]['names'] == ['Reported Connection Name', 'R. Connection']
    p = bundle['presentations'][OFFICER]
    assert p['recording_tip_sha256'] == t['client'].head()['sha256'] and p['history']['versions']
    assert all(x['status'] == 'NOT_CONFIGURED' for x in p['anchoring'].values())
    assert bundle['directory']['expires_at'] <= t['authorization']['expires_at']


def test_connect_signed_source_to_existing_scope_search_and_historical_query(connected):
    t = connected; directory, packets, disclosures = inputs(t)
    with listener(t['transport']):
        result = C.Connection(t['configfile']).install(directory, packets, disclosures)
    assert result['status'] == 'SIGNED_UI_CACHE_IMPORTED' and result['research_storage_changed'] is False
    token, csrf = t['store'].access.login('station.one', PASSWORD, 'test-peer')
    service = ResearchService(t['store'])
    workspace = service.workspace(token, OFFICER)
    assert workspace['identity']['names'][0] == 'Reported Connection Name'
    answer = service.history(token, csrf, OFFICER, '2024-12-31', workspace['coverage_start'])
    assert any(c['fields'].get('police_no') == 'fixture-100' for p in answer['projections'] for c in p['candidates'])
    assert workspace['live_research_ready'] is False and workspace['public_finality_verified'] is False


@pytest.mark.parametrize('fault', ['signature', 'source', 'revision', 'expired', 'purpose', 'directory', 'officer', 'custodian', 'extra'])
def test_bad_data_authorization_blocks_before_original_loader(connected, fault):
    t = connected; p = deepcopy(t['authorization'])
    if fault == 'source': p['source_public_sha256'] = 'f' * 64
    if fault == 'revision': p['code_revision'] = 'f' * 40
    if fault == 'expired': p['expires_at'] = int(time.time()) - 1
    if fault == 'purpose': p['purpose'] = 'UNSCOPED_EXPORT'
    if fault == 'directory': p['directory_all_officers'] = False
    if fault == 'officer': p['detail_officer_uids'] = []
    if fault == 'custodian': p['custodian_reference'] = ''
    if fault == 'extra': p['waiver'] = True
    envelope = signed(t['custodian'], 'custodian', p)
    if fault == 'signature': envelope['signature'] = 'AAAA'
    write(t['authorization_file'], envelope)
    with pytest.raises(Exception): C.Connection(t['configfile']).verify([OFFICER])
    assert t['calls'] == []


@pytest.mark.parametrize('fault', ['expired-permit', 'permit-ciphertext', 'publication', 'binding', 'backup', 'dirty-source', 'source-key-reuse'])
def test_local_source_failures_never_reach_loader(connected, fault):
    t = connected; c = t['config']; source = c['source']
    if fault in ('expired-permit', 'permit-ciphertext'):
        file = C.Path(source['audit_gate_attempt']) / 'audit-permit.encrypted.json'
        envelope = json.loads(file.read_text())
        if fault == 'permit-ciphertext': envelope['ciphertext'] = 'AAAA'
        else:
            p = open_artifact(t['s']['crypto'], envelope, A.binding(t['snapshot']['context']))
            p['checked_at'] = (t['s']['clock'][0] - timedelta(hours=1)).isoformat()
            p['issued_at'] = p['checked_at']; p['expires_at'] = (t['s']['clock'][0] - timedelta(minutes=50)).isoformat()
            envelope = A.seal_permit(t['s']['crypto'], t['s']['backup'], p)
        write(file, envelope)
    if fault == 'publication': write(C.Path(source['commitment_attempt']) / 'public-commitments.json', {'changed': True})
    if fault == 'binding': write(C.Path(source['binding_attempt']) / 'destination-bindings.encrypted.json', {'changed': True})
    if fault == 'backup': write(source['backup_key_file'], {'changed': True})
    if fault == 'dirty-source': (t['s']['repo'] / 'source.py').write_text('# Changed source\n')
    if fault == 'source-key-reuse':
        config = json.loads(t['workspace_config'].read_text()); write(config['key_file'], next(iter(t['s']['crypto'].encryption_keys.values())))
    with pytest.raises(Exception): C.Connection(t['configfile']).verify([OFFICER])
    assert t['calls'] == []


@pytest.mark.parametrize('fault', ['profile-pin', 'witness-scope', 'client-certificate', 'fixture-option', 'offline'])
def test_runtime_configuration_and_network_fail_closed(connected, fault):
    t = connected; runtime = deepcopy(t['runtime'])
    if fault == 'profile-pin': runtime['witness']['profile_sha256'] = 'f' * 64
    if fault == 'witness-scope': runtime['witness']['witness_id'] = 'another-witness'
    if fault == 'client-certificate': runtime['witness']['client_certificate'] = runtime['witness']['ca_certificate']
    if fault == 'fixture-option': runtime['fixture_transport'] = True
    write(t['runtime_file'], runtime)
    if fault == 'offline':
        with pytest.raises(Exception): C.Connection(t['configfile']).verify([OFFICER])
    else:
        with listener(t['transport']):
            with pytest.raises(Exception): C.Connection(t['configfile']).verify([OFFICER])
    assert len(t['calls']) == 1


@pytest.mark.parametrize('fault', ['directory-name', 'directory-raw', 'history', 'tip', 'unconfigured-anchoring', 'signature',
    'account-version', 'out-of-scope', 'unassessed', 'restricted', 'overlong-data-use', 'duplicate-packet'])
def test_invalid_signed_connection_never_imports_any_directory(connected, fault):
    t = connected; directory, packets, disclosures = inputs(t)
    if fault == 'directory-name': directory['payload']['officers'][0]['names'][0] = 'Altered Name'
    if fault == 'directory-raw': directory['payload']['officers'][0]['source_raw_id'] = 'e' * 64
    if fault == 'history': packets[0]['payload']['history']['coverage_reference'] = 'changed'
    if fault == 'tip': packets[0]['payload']['recording_tip_sha256'] = 'f' * 64
    if fault == 'unconfigured-anchoring': packets[0]['payload']['anchoring']['public'] = {'status': 'OBSERVED_VALID', 'receipt_sha256': 'a' * 64}
    if fault == 'account-version': disclosures[0]['payload']['account_version'] = 2
    if fault == 'out-of-scope': directory['payload']['officers'][0]['membership']['STATION'] = 'S2'
    if fault == 'unassessed': disclosures[0]['payload']['classification'] = 'UNASSESSED'
    if fault == 'restricted': disclosures[0]['payload']['classification'] = 'CID_CCIB_RESTRICTED'
    if fault == 'overlong-data-use': directory['payload']['expires_at'] = t['authorization']['expires_at'] + 1
    directory = signed(t['admin'], 'test-admin', directory['payload'])
    packets = [signed(t['admin'], 'workspace-test', p['payload']) for p in packets]
    disclosures = [signed(t['admin'], 'workspace-test', p['payload']) for p in disclosures]
    if fault == 'signature': packets[0]['signature'] = 'AAAA'
    if fault == 'duplicate-packet': packets *= 2
    with listener(t['transport']):
        with pytest.raises(Exception): C.Connection(t['configfile']).install(directory, packets, disclosures)
    with t['store'].access.transaction() as c: assert c.execute('SELECT COUNT(*) FROM directory').fetchone()[0] == 0
    with t['store'].transaction() as c: assert c.execute('SELECT COUNT(*) FROM presentations').fetchone()[0] == 0


def test_input_changed_after_snapshot_stops_export(connected, monkeypatch):
    t = connected
    import app.identity.algorithm_snapshot as S
    def changed(*args):
        t['runtime_file'].write_bytes(t['runtime_file'].read_bytes() + b'\n')
        return t['snapshot']
    monkeypatch.setattr(S, 'load_verified_snapshot', changed)
    with pytest.raises(ValueError, match='input changed'): C.Connection(t['configfile']).verify([OFFICER])


def test_exact_current_import_can_resume_after_directory_only(connected, monkeypatch):
    t = connected; directory, packets, disclosures = inputs(t)
    from app.access.research_store import ResearchStore
    original = ResearchStore.import_packet
    monkeypatch.setattr(ResearchStore, 'import_packet', lambda *args: (_ for _ in ()).throw(OSError('fixture interruption')))
    with listener(t['transport']):
        with pytest.raises(OSError): C.Connection(t['configfile']).install(directory, packets, disclosures)
    token, _ = t['store'].access.login('station.one', PASSWORD, 'test-peer')
    with pytest.raises(AccessError): ResearchService(t['store']).workspace(token, OFFICER)
    monkeypatch.setattr(ResearchStore, 'import_packet', original)
    with listener(t['transport']):
        C.Connection(t['configfile']).install(directory, packets, disclosures)
        C.Connection(t['configfile']).install(directory, packets, disclosures)
    with t['store'].access.transaction() as c: assert c.execute('SELECT COUNT(*) FROM directory').fetchone()[0] == 1
    token, _ = t['store'].access.login('station.one', PASSWORD, 'test-peer')
    assert ResearchService(t['store']).workspace(token, OFFICER)['generation'] == 1


def test_revoked_account_blocks_before_signed_cache_import(connected):
    t = connected; directory, packets, disclosures = inputs(t)
    t['store'].access.put_account(grant(t['admin'], active=False, version=2))
    with listener(t['transport']):
        with pytest.raises(ValueError, match='version or scope'): C.Connection(t['configfile']).install(directory, packets, disclosures)


def test_diagnose_cli_never_reads_configuration_or_prints_private_values(connected):
    t = connected
    result = subprocess.run([sys.executable, 'scripts/connect_research_datasets.py', 'diagnose', '--repository', str(t['s']['repo'])],
        capture_output=True, text=True)
    assert result.returncode == 0
    p = json.loads(result.stdout)
    assert p['clean_source'] and not p['network_access'] and not p['database_access']
    assert 'Reported Connection Name' not in result.stdout and '000000001V' not in result.stdout


def test_original_loader_rejection_has_no_fallback(connected, monkeypatch):
    t = connected
    import app.identity.algorithm_snapshot as S
    monkeypatch.setattr(S, 'load_verified_snapshot', lambda *args: (_ for _ in ()).throw(ValueError('fixture replay refused')))
    with pytest.raises(ValueError, match='replay refused'): C.Connection(t['configfile']).verify([OFFICER])


def test_identity_only_connection_does_not_invent_a_history(connected):
    t = connected
    bundle = C.Connection(t['configfile']).export(t['membership'], generation=1, selections={})
    assert bundle['presentations'] == {}
    result = C.Connection(t['configfile']).install(signed(t['admin'], 'test-admin', bundle['directory']), [], [])
    assert result['directory_officers'] == 1 and result['presentations'] == result['disclosures'] == 0
    token, _ = t['store'].access.login('station.one', PASSWORD, 'test-peer')
    with pytest.raises(AccessError): ResearchService(t['store']).workspace(token, OFFICER)


def test_membership_worksheet_requires_review_and_never_infers_posting(connected):
    t = connected; p = C.Connection(t['configfile']).membership_draft('TEST_ONLY_SCOPE_REVIEW')
    assert p['kind'] == 'MEMBERSHIP' and p['officers'][0]['officer_uid'] == OFFICER
    assert all(value is None for value in p['officers'][0]['membership'].values())
    assert 'signature' not in p and len(t['calls']) == 1


def test_offline_data_use_signature_and_existing_output_refusal(connected, tmp_path, monkeypatch):
    from scripts import sign_research_data_use as S
    from research_connection_fixture import seed
    t = connected; draft = write(tmp_path / 'authorization-draft.json', t['authorization'])
    key = write(tmp_path / 'custodian.key', seed(t['custodian'])); output = tmp_path / 'signed.json'
    monkeypatch.setattr(sys, 'argv', ['sign', '--config', str(t['configfile']), '--draft', str(draft),
        '--signing-key', str(key), '--key-id', 'custodian', '--output', str(output)])
    S.main(); before = output.read_bytes()
    C.authorization(json.loads(before), R.public_keys(t['config']['authorization_keys']), revision=C.revision(t['s']['repo']), officers=[OFFICER])
    assert output.stat().st_mode & 0o777 == 0o600 and t['calls'] == []
    with pytest.raises(SystemExit): S.main()
    assert output.read_bytes() == before


def test_restricted_disclosure_requires_an_explicit_clearance(connected):
    t = connected; directory, packets, disclosures = inputs(t)
    p = disclosures[0]['payload']; p.update(classification='CID_CCIB_RESTRICTED', restricted_clearance=True)
    disclosures = [signed(t['admin'], 'workspace-test', p)]
    with listener(t['transport']): C.Connection(t['configfile']).install(directory, packets, disclosures)
    token, _ = t['store'].access.login('station.one', PASSWORD, 'test-peer')
    assert ResearchService(t['store']).workspace(token, OFFICER)['can_request_review'] is False


def test_directory_generation_conflict_preserves_previous_cache(connected):
    t = connected; directory, packets, disclosures = inputs(t)
    future = deepcopy(directory); future['payload']['generation'] = 5
    t['store'].access.put_directory(signed(t['admin'], 'test-admin', future['payload']))
    before = t['store'].path.read_bytes()
    with listener(t['transport']):
        with pytest.raises(ValueError, match='generation conflict'): C.Connection(t['configfile']).install(directory, packets, disclosures)
    assert t['store'].path.read_bytes() == before


def test_private_export_outputs_and_conflict_refusal(connected, tmp_path):
    from scripts.connect_research_datasets import write_export
    t = connected; bundle = exported(t); connection = C.Connection(t['configfile'])
    output = tmp_path / 'export'; write_export(connection, bundle, output)
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())
    assert 'signature' not in json.loads((output / 'directory-draft.json').read_text())
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(ValueError): write_export(connection, bundle, output)
    assert before == {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(ValueError): write_export(connection, bundle, t['store'].root / 'export')


def test_inventory_reads_only_public_metadata_and_artifact_names(connected, tmp_path):
    from scripts.inspect_research_connection import inventory
    t = connected
    secret = tmp_path / 'secret.json'; secret.write_text('{"password":"do-not-include-test-secret"}')
    row = tmp_path / 'officer.csv'; row.write_text('test NIC and private values')
    report = inventory(t['s']['repo'], [tmp_path]); text = json.dumps(report)
    assert 'do-not-include-test-secret' not in text and 'test NIC' not in text
    assert report['artifacts']['bundle_attempt'] == []  # Fixture original-loader substitution is explicit.
    assert len(report['artifacts']['commitment_attempt']) == 1
    assert report['audit_permit'] == 'NOT_AUTHENTICATED' and report['rpc_1'] == 'NOT_TESTED'


def test_http_workflow_uses_signed_connected_source_and_preserves_csrf_scope(connected, tmp_path):
    from http import client
    from urllib.parse import urlsplit
    from research_workspace_https_fixture import server
    t = connected; directory, packets, disclosures = inputs(t)
    with listener(t['transport']): C.Connection(t['configfile']).install(directory, packets, disclosures)
    root = tmp_path / 'web'; root.mkdir(mode=0o700)
    with server(root, prepared=(t['store'], t['admin'], t['workspace_config'])) as (_, _, origin, context, _):
        url = urlsplit(origin); connection = client.HTTPSConnection(url.hostname, url.port, context=context)
        body = json.dumps({'username': 'station.one', 'password': PASSWORD})
        connection.request('POST', '/api/auth/login', body, {'Origin': origin, 'Content-Type': 'application/json'})
        response = connection.getresponse(); data = json.loads(response.read()); assert response.status == 200
        cookie = response.getheader('Set-Cookie').split(';')[0]; csrf = data['csrf_token']
        connection.request('GET', '/api/research/officers/' + OFFICER, headers={'Cookie': cookie})
        response = connection.getresponse(); data = json.loads(response.read())
        assert response.status == 200 and data['identity']['names'][0] == 'Reported Connection Name'
        connection.request('GET', '/api/research/officers/' + identifier(2), headers={'Cookie': cookie})
        response = connection.getresponse(); response.read(); assert response.status == 404
        connection.request('POST', '/api/research/history', json.dumps({'officer_uid': OFFICER, 'effective_on': '2024-12-31', 'known_at': data['coverage_start']}),
            {'Cookie': cookie, 'Origin': origin, 'Content-Type': 'application/json', 'X-CSRF-Token': 'forged'})
        response = connection.getresponse(); response.read(); assert response.status == 403
        connection.close()


@pytest.mark.parametrize('fault', ['public-file', 'symlink', 'unknown-field', 'duplicate-field', 'key-domain'])
def test_private_configuration_boundary(connected, fault):
    t = connected; config = deepcopy(t['config'])
    if fault == 'unknown-field': config['skip_rpc'] = True
    if fault == 'key-domain': config['authorization_keys'] = t['config']['authorization_keys'] = json.loads(t['access_config'].read_text())['authority_keys']
    write(t['configfile'], config)
    if fault == 'public-file': t['configfile'].chmod(0o644)
    if fault == 'symlink':
        p = t['configfile'].with_name('link.json'); p.symlink_to(t['configfile']); t['configfile'] = p
    if fault == 'duplicate-field': t['configfile'].write_text('{"policy":"one","policy":"two"}')
    with pytest.raises(Exception): C.Connection(t['configfile'])
