"""Read-only live chain check: configuration, job, result vetting, safety limits, operator tool and the HTTP route. No chain is contacted."""
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import pytest

from app.access import live_check as L
from app.access.policy import AccessError
from unit_totp_fixture import setup  # noqa: F401  (pytest fixture)
from test_persistent_access import configured as totp_configured
from test_public_demo import asgi, real_intake

REPO = Path(__file__).resolve().parents[2]
ENTRY = {'publication_id': 'a' * 64, 'commitment': 'b' * 64}
META = {'batch_publication_id': 'c' * 64, 'merkle_root': 'd' * 64, 'sepolia_contract': '0x' + '1' * 40, 'sepolia_chain_id': 11155111,
        'sepolia_sealing_block': '0xb52fdb', 'officers': 6596}


def private_file(path, data):
    Path(path).write_text(data)
    Path(path).chmod(0o600)
    return str(path)


def make_config(tmp_path):
    gateway = private_file(tmp_path / 'gateway.json', json.dumps({'chaincode': 'officer-evidence-v1', 'channel': 'personnel', 'reader': {}}))
    network = private_file(tmp_path / 'network.json', json.dumps({'policy': 'SEPOLIA_DEPLOYMENT_NETWORK_V1', 'rpc_urls': ['https://x']}))
    config = {'policy': L.POLICY, 'fabric_gateway_config': gateway, 'fabric_gateway_sha256': 'e' * 64, 'sepolia_network_config': network, 'sepolia_network_sha256': 'f' * 64}
    return config, private_file(tmp_path / 'live-check-config.json', json.dumps(config))


def good(**over):
    base = {'policy': 'ORIGINAL_ANCHOR_LIVE_CHECK_V1', 'read_only': True, 'transactions_submitted': 0, 'checked_at': '2026-10-19T00:00:00.000Z', 'passed': True,
            'fabric': {'status': 'READ', 'passed': True}, 'sepolia': {'status': 'READ', 'passed': True}}
    base.update(over)
    return base


def test_configuration_is_validated_and_the_job_carries_only_public_identifiers(tmp_path):
    config, file = make_config(tmp_path)
    assert L.configured(file, REPO) == config
    for change in ({'policy': 'x'}, {'fabric_gateway_sha256': 'XYZ'}, {'sepolia_network_config': 'relative.json'}, {'extra': 1}):
        bad = tmp_path / 'bad.json'
        bad.write_text(json.dumps({**config, **change}))
        bad.chmod(0o600)
        with pytest.raises(Exception):
            L.configured(bad, REPO)
        bad.unlink()
    open_file = tmp_path / 'open.json'
    open_file.write_text(json.dumps(config))
    open_file.chmod(0o644)
    with pytest.raises(Exception):
        L.configured(open_file, REPO)
    job = L.build_job(config, ENTRY, META)
    assert set(job) == {'batch', 'handle', 'commitment', 'merkle_root', 'contract', 'chain_id', 'sealing_block', 'officers', 'fabric_config', 'fabric_sha256', 'network_config', 'network_sha256'}
    assert job['sealing_block'] == 0xb52fdb and job['handle'] == 'a' * 64 and job['officers'] == 6596


@pytest.mark.parametrize('fabric,sepolia,passed,expected', [
    ({'status': 'READ', 'passed': True}, {'status': 'READ', 'passed': True}, True, 'PASSED'),
    ({'status': 'UNAVAILABLE', 'reason': 'X'}, {'status': 'READ', 'passed': True}, False, 'UNAVAILABLE'),
    ({'status': 'READ', 'passed': True}, {'status': 'UNAVAILABLE', 'reason': 'X'}, False, 'UNAVAILABLE'),
    ({'status': 'READ', 'passed': False}, {'status': 'READ', 'passed': True}, False, 'FAILED'),
    ({'status': 'READ', 'passed': True}, {'status': 'READ', 'passed': False}, False, 'FAILED')])
def test_overall_verdict_never_calls_an_unreadable_chain_verified(tmp_path, fabric, sepolia, passed, expected):
    config, _ = make_config(tmp_path)
    answer = L.check(config, REPO, ENTRY, META, runner=lambda repo, job: good(fabric=fabric, sepolia=sepolia, passed=passed))
    assert answer['overall'] == expected and answer['transactions_submitted'] == 0 and answer['basis'] == 'FRESH_READ_NOW'


@pytest.mark.parametrize('bad', [good(read_only=False), good(transactions_submitted=1), good(transactions_submitted=None), good(policy='x'), {'error': 'X', 'policy': 'ORIGINAL_ANCHOR_LIVE_CHECK_V1', 'read_only': True, 'transactions_submitted': 0, 'passed': False},
                                 good(fabric={'status': 'MAYBE'}), good(sepolia=None), 'text', None])
def test_a_result_that_is_not_read_only_or_malformed_is_never_shown(tmp_path, bad):
    config, _ = make_config(tmp_path)
    with pytest.raises(AccessError) as caught:
        L.check(config, REPO, ENTRY, META, runner=lambda repo, job: bad)
    assert caught.value.code == 'LIVE_CHECK_FAILED'


def test_only_one_check_runs_at_a_time_and_the_lock_is_always_released(tmp_path):
    config, _ = make_config(tmp_path)
    def nested(repo, job):
        with pytest.raises(AccessError) as caught:
            L.check(config, REPO, ENTRY, META, runner=lambda r, j: good())
        assert caught.value.code == 'LIVE_CHECK_BUSY' and caught.value.status == 429
        return good()
    assert L.check(config, REPO, ENTRY, META, runner=nested)['overall'] == 'PASSED'
    with pytest.raises(RuntimeError):
        L.check(config, REPO, ENTRY, META, runner=lambda r, j: (_ for _ in ()).throw(RuntimeError('boom')))
    assert L.check(config, REPO, ENTRY, META, runner=lambda r, j: good())['overall'] == 'PASSED'


def test_node_is_run_with_a_minimal_environment_stdin_only_and_failures_are_sanitised(tmp_path, monkeypatch):
    config, _ = make_config(tmp_path)
    seen = {}
    def fake_run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, 0, stdout='noise\n' + json.dumps(good()) + '\n', stderr='SECRET')
    monkeypatch.setattr(L.shutil, 'which', lambda name: '/usr/bin/node')
    monkeypatch.setattr(L.subprocess, 'run', fake_run)
    job = L.build_job(config, ENTRY, META)
    assert L.run_node(REPO, job)['passed'] is True
    assert json.loads(seen['input']) == job and set(seen['env']) == {'PATH', 'NODE_PATH'} and seen['timeout'] == 90 and seen['cwd'] == REPO / 'blockchain/public'
    assert seen['command'] == ['/usr/bin/node', str(REPO / L.SCRIPT)]
    monkeypatch.setattr(L.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired('node', 90)))
    with pytest.raises(AccessError) as caught:
        L.run_node(REPO, job)
    assert caught.value.code == 'LIVE_CHECK_TIMEOUT'
    monkeypatch.setattr(L.subprocess, 'run', lambda c, **k: subprocess.CompletedProcess(c, 1, stdout='not json', stderr='/home/secret/path'))
    with pytest.raises(AccessError) as caught:
        L.run_node(REPO, job)
    assert caught.value.code == 'LIVE_CHECK_FAILED' and 'secret' not in str(caught.value.code)
    monkeypatch.setattr(L.shutil, 'which', lambda name: None)
    with pytest.raises(AccessError) as caught:
        L.run_node(REPO, job)
    assert caught.value.code == 'LIVE_CHECK_UNAVAILABLE'


# ---- Operator tool
def tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location('configure_live_check', Path(__file__).resolve().parents[1] / 'scripts/configure_live_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_app(tmp_path, **workspace):
    app = tmp_path / 'research-app-v1'
    app.mkdir(mode=0o700)
    private_file(app / 'workspace-config.json', json.dumps({'policy': 'RESEARCH_WEB_CONFIG_V1', **workspace}))
    gateway = private_file(tmp_path / 'research-gateway-config.json', json.dumps({'chaincode': 'officer-evidence-v1', 'channel': 'personnel', 'reader': {}}))
    network = private_file(tmp_path / 'network.json', json.dumps({'policy': 'SEPOLIA_DEPLOYMENT_NETWORK_V1', 'rpc_urls': []}))
    return app, gateway, network


def test_operator_tool_enables_the_check_idempotently_with_a_backup_and_pins(tmp_path):
    t = tool()
    app, gateway, network = make_app(tmp_path)
    before = (app / 'workspace-config.json').read_bytes()
    first = t.apply(app, REPO, gateway, network)
    assert first == {'status': 'LIVE_CHECK_CONFIGURED', 'chain_contacted': False, 'keys_printed': False, 'restart_required': True}
    updated = json.loads((app / 'workspace-config.json').read_text())
    config = json.loads((app / 'live-check-config.json').read_text())
    assert updated['live_check_config'] == str(app / 'live-check-config.json') and config['fabric_gateway_sha256'] == t.sha(gateway) and config['sepolia_network_sha256'] == t.sha(network)
    backups = list(app.glob('workspace-config-before-live-check-*.json'))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    for p in [app / 'workspace-config.json', app / 'live-check-config.json', backups[0]]:
        assert not (p.stat().st_mode & 0o077), p
    L.configured(app / 'live-check-config.json', REPO)
    assert t.apply(app, REPO, gateway, network)['status'] == 'LIVE_CHECK_ALREADY_CONFIGURED' and len(list(app.glob('workspace-config-before-live-check-*.json'))) == 1


def test_operator_tool_refuses_unsafe_or_unexpected_situations(tmp_path):
    t = tool()
    app, gateway, network = make_app(tmp_path, intake_read_only=True)
    with pytest.raises(ValueError, match='public read-only'):
        t.apply(app, REPO, gateway, network)
    (tmp_path / 'x').mkdir()
    app2, gateway2, network2 = make_app(tmp_path / 'x')
    private_file(gateway2, json.dumps({'chaincode': 'officer-evidence-test-v1', 'channel': 'personnel', 'reader': {}}))
    with pytest.raises(ValueError, match='Reader-capable'):
        t.apply(app2, REPO, gateway2, network2)
    (tmp_path / 'y').mkdir()
    app3, gateway3, network3 = make_app(tmp_path / 'y')
    t.apply(app3, REPO, gateway3, network3)
    private_file(network3, json.dumps({'policy': 'SEPOLIA_DEPLOYMENT_NETWORK_V1', 'rpc_urls': ['changed']}))
    with pytest.raises(ValueError, match='differs'):
        t.apply(app3, REPO, gateway3, network3)


def test_public_copy_rules_refuse_live_checks(tmp_path):
    from app.access.public_demo import problems
    assert 'LIVE_CHAIN_CHECK_MUST_BE_OFF' in problems({'live_check_config': 'x'}, {'origin': 'https://demo.university.edu', 'totp_required': True})


# ---- HTTP route on a disposable app that mirrors the real layout
class StubRuntime:
    """Stands in for the PostgreSQL/MongoDB-backed worker, which is irrelevant to this read-only route."""
    def __init__(self, workspace, research, file):
        self.service = None
        self.stop = False

    def check_pins(self):
        pass


def test_route_checks_only_an_authorised_officer_logs_the_action_and_never_runs_without_configuration(setup, monkeypatch):
    from app.access import totp
    from app.access.research_app import application
    import app.intake.dataset_pipeline.runtime as dataset_runtime
    d = setup
    totp_configured(d)
    officer, other = d['members'][0]['officer_uid'], d['members'][1]['officer_uid']
    seeds = {p['username']: p['secret'] for p in json.loads((d['app'] / 'totp-enrollment-private.json').read_text())['accounts']}
    runtime = real_intake(d, officer, REPO)
    workspace_file = d['app'] / 'workspace-config.json'
    workspace = json.loads(workspace_file.read_text())
    workspace['personnel_intake_config'] = str(runtime)
    config, live_file = make_config(d['app'].parent)
    workspace['live_check_config'] = live_file
    workspace_file.write_text(json.dumps(workspace))
    access = json.loads(Path(workspace['access_config']).read_text())
    host = access['origin'].split('//')[1]
    monkeypatch.setattr(dataset_runtime, 'Runtime', StubRuntime)
    monkeypatch.setattr(L, 'run_node', lambda repo, job: good())
    monkeypatch.setenv('PPI_RESEARCH_CONFIG', str(workspace_file))
    app = application()
    login = lambda user: asgi(app, 'POST', '/api/auth/login', host=host, origin=access['origin'], body={'username': user, 'password': 'invented-private-fixture-password', 'totp_code': totp.code(seeds[user], int(time.time()) // 30)})
    status, headers, _ = login('research.hq')
    assert status == 200
    token = headers['set-cookie'].split(';')[0]
    csrf = json.loads(asgi(app, 'GET', '/api/auth/session', host=host, cookie=token)[2])['csrf_token']
    path = '/api/research/officers/%s/integrity/live'
    # the Integrity view announces the button
    view = json.loads(asgi(app, 'GET', '/api/research/officers/%s/integrity' % officer, host=host, cookie=token)[2])
    assert view['live_check_available'] is True
    status, _, body = asgi(app, 'POST', path % officer, host=host, origin=access['origin'], body={}, cookie=token, csrf=csrf)
    assert status == 200, body
    answer = json.loads(body)
    assert answer['overall'] == 'PASSED' and answer['basis'] == 'FRESH_READ_NOW' and answer['transactions_submitted'] == 0
    # no CSRF token, wrong origin, extra fields: refused before anything runs
    ran = []
    monkeypatch.setattr(L, 'run_node', lambda repo, job: ran.append(job) or good())
    assert asgi(app, 'POST', path % officer, host=host, origin=access['origin'], body={}, cookie=token)[0] in (401, 403)
    assert asgi(app, 'POST', path % officer, host=host, origin='https://evil.example', body={}, cookie=token, csrf=csrf)[0] == 403
    assert asgi(app, 'POST', path % officer, host=host, origin=access['origin'], body={'x': 1}, cookie=token, csrf=csrf)[0] == 400
    assert asgi(app, 'POST', path % officer, host=host)[0] in (400, 403)
    # an officer outside the account's scope is refused before any chain is read
    scoped = login('research.oic.a')
    assert scoped[0] == 200
    t2 = scoped[1]['set-cookie'].split(';')[0]
    c2 = json.loads(asgi(app, 'GET', '/api/auth/session', host=host, cookie=t2)[2])['csrf_token']
    status, _, _ = asgi(app, 'POST', path % other, host=host, origin=access['origin'], body={}, cookie=t2, csrf=c2)
    assert status in (403, 404) and ran == []
    # an officer with no stored original fingerprint cannot be checked
    status, _, body = asgi(app, 'POST', path % other, host=host, origin=access['origin'], body={}, cookie=token, csrf=csrf)
    assert status == 409 and json.loads(body)['error'] == 'ORIGINAL_FINGERPRINT_NOT_INSTALLED' and ran == []
    # not logged in
    assert asgi(app, 'POST', path % officer, host=host, origin=access['origin'], body={})[0] == 401


def test_route_reports_not_configured_when_the_operator_has_not_enabled_it(setup, monkeypatch):
    from app.access import totp
    from app.access.research_app import application
    import app.intake.dataset_pipeline.runtime as dataset_runtime
    d = setup
    totp_configured(d)
    officer = d['members'][0]['officer_uid']
    seeds = {p['username']: p['secret'] for p in json.loads((d['app'] / 'totp-enrollment-private.json').read_text())['accounts']}
    runtime = real_intake(d, officer, REPO)
    workspace_file = d['app'] / 'workspace-config.json'
    workspace = json.loads(workspace_file.read_text())
    workspace['personnel_intake_config'] = str(runtime)
    workspace_file.write_text(json.dumps(workspace))
    access = json.loads(Path(workspace['access_config']).read_text())
    host = access['origin'].split('//')[1]
    monkeypatch.setattr(dataset_runtime, 'Runtime', StubRuntime)
    monkeypatch.setenv('PPI_RESEARCH_CONFIG', str(workspace_file))
    app = application()
    status, headers, _ = asgi(app, 'POST', '/api/auth/login', host=host, origin=access['origin'], body={'username': 'research.hq', 'password': 'invented-private-fixture-password', 'totp_code': totp.code(seeds['research.hq'], int(time.time()) // 30)})
    token = headers['set-cookie'].split(';')[0]
    csrf = json.loads(asgi(app, 'GET', '/api/auth/session', host=host, cookie=token)[2])['csrf_token']
    assert json.loads(asgi(app, 'GET', '/api/research/officers/%s/integrity' % officer, host=host, cookie=token)[2])['live_check_available'] is False
    status, _, body = asgi(app, 'POST', '/api/research/officers/%s/integrity/live' % officer, host=host, origin=access['origin'], body={}, cookie=token, csrf=csrf)
    assert status == 503 and json.loads(body)['error'] == 'LIVE_CHECK_NOT_CONFIGURED'
