"""Public read-only demonstration copy: configuration rules, launcher preflight and transfer bundle. Disposable files only."""
import asyncio
import json
import os
from pathlib import Path
import pytest

from app.access.api import RequestBoundary
from app.access.public_demo import problems, public_dns_name
from app.access.public_demo_bundle import build

ORIGIN = 'https://demo.university.edu'
GOOD_ACCESS = {'origin': ORIGIN, 'totp_required': True}


def test_public_dns_name_rules():
    assert public_dns_name(ORIGIN) and public_dns_name('https://ppi-demo.duckdns.org')
    for bad in ('https://127.0.0.1:8443', 'https://localhost', 'https://[::1]', 'https://192.168.1.5', 'https://demo.local',
                'https://demo.internal', 'https://demo', 'https://demo.example', 'https://demo.test'):
        assert not public_dns_name(bad), bad


def test_problems_list_every_unsafe_setting_and_nothing_secret():
    assert problems({}, GOOD_ACCESS) == []
    assert 'PUBLIC_HTTPS_DNS_NAME_REQUIRED' in problems({}, {**GOOD_ACCESS, 'origin': 'https://127.0.0.1:8443'})
    assert problems({}, {'origin': ORIGIN}) == ['MANDATORY_TOTP_REQUIRED']
    assert problems({}, {**GOOD_ACCESS, 'totp_required': False}) == ['MANDATORY_TOTP_REQUIRED']
    found = problems({'promotion_intake_config': 'x', 'personnel_intake_config': 'y'}, GOOD_ACCESS, {'anchor_config': 'z'})
    assert found == ['UPLOADS_AND_CHAIN_WRITES_MUST_BE_OFF:promotion_intake_config', 'UPLOADS_AND_CHAIN_WRITES_MUST_BE_OFF:personnel_intake_config',
                     'LOG_ANCHORING_MUST_BE_OFF:anchor_config']


def make_app_root(tmp_path, *, totp=True, extra_workspace=None, anchor=True, extra_file=None):
    root = tmp_path / 'research-app-v1'
    root.mkdir(mode=0o700)
    def put(rel, data=b'synthetic'):
        p = root / rel
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(0o600)
        return str(p)
    for d in ('workspace-state', 'access-state', 'accountability-state'):
        (root / d).mkdir(mode=0o700)
    put('workspace-state/workspace.sqlite3'); put('access-state/access.sqlite3'); put('accountability-state/accountability.sqlite3')
    put('keys/workspace.key', os.urandom(32)); put('keys/access.key', os.urandom(32)); put('keys/log.key', os.urandom(32)); put('grant-hq.json', b'{}')
    access = {'authority_keys': {'k': 'AAAA'}, 'key_file': str(root / 'keys/access.key'), 'origin': 'https://127.0.0.1:8443', 'policy': 'SCOPED_ACCESS_CONFIG_V1',
              'repository': '/laptop/repo', 'state_directory': str(root / 'access-state')}
    if totp:
        access['totp_required'] = True
    log = {'key_file': str(root / 'keys/log.key'), 'policy': 'ACCOUNTABILITY_CONFIG_V1', 'reader_grants': [str(root / 'grant-hq.json')],
           'state_directory': str(root / 'accountability-state')}
    if anchor:
        log['anchor_config'] = '/laptop/anchor.json'
    workspace = {'access_config': put('access-config.json', json.dumps(access).encode()), 'accountability_config': put('accountability-config.json', json.dumps(log).encode()),
                 'key_file': str(root / 'keys/workspace.key'), 'policy': 'RESEARCH_WEB_CONFIG_V1', 'presentation_keys': {'p': 'AAAA'},
                 'state_directory': str(root / 'workspace-state'), 'promotion_intake_config': '/laptop/runtime.json', 'personnel_intake_config': '/laptop/runtime.json',
                 'review_workflow_keys': {'r': 'AAAA'}, 'workflow_assessment_keys': {'w': 'AAAA'}, **(extra_workspace or {})}
    put('workspace-config.json', json.dumps(workspace).encode())
    if extra_file:
        put(*extra_file)
    return root


def test_bundle_copies_only_what_the_web_app_needs_and_rewrites_the_configs(tmp_path):
    root = make_app_root(tmp_path)
    out = tmp_path / 'bundle'
    summary = build(root, out, origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    assert summary['keys_printed'] is False and summary['chain_keys_included'] is False and summary['stores'] == 3
    workspace = json.loads((out / 'private/workspace-config.json').read_text())
    access = json.loads((out / 'private/access-config.json').read_text())
    log = json.loads((out / 'private/accountability-config.json').read_text())
    assert 'promotion_intake_config' not in workspace and 'personnel_intake_config' not in workspace and 'anchor_config' not in log
    assert access['origin'] == ORIGIN and access['totp_required'] is True and access['repository'] == '/srv/ppi/repo'
    assert workspace['state_directory'] == '/srv/ppi/state/workspace' and workspace['key_file'] == '/srv/ppi/keys/workspace.key'
    assert workspace['access_config'] == '/srv/ppi/private/access-config.json' and log['reader_grants'] == ['/srv/ppi/grants/grant-hq.json']
    assert problems(workspace, access, log) == []
    assert all('laptop' not in json.dumps(v) for v in (workspace, access, log))
    for p in [out, *out.rglob('*')]:
        assert not (p.stat().st_mode & 0o077), p
    manifest = json.loads((out / 'MANIFEST.json').read_text())
    assert 'keys/workspace.key' in manifest['files'] and 'state/workspace/workspace.sqlite3' in manifest['files']
    assert (out / 'keys/workspace.key').read_bytes() == (root / 'keys/workspace.key').read_bytes()
    assert not any(name in json.dumps(manifest) for name in ('wallet', 'fabric', 'sepolia'))


@pytest.mark.parametrize('name', ['wallet.json', 'fabric-gateway.json', 'intake-writer.key', 'credentials.json', 'totp-enrollment-private.json'])
def test_bundle_refuses_chain_or_provisioning_material_inside_a_copied_store(tmp_path, name):
    root = make_app_root(tmp_path, extra_file=('workspace-state/' + name,))
    with pytest.raises(ValueError, match='refused'):
        build(root, tmp_path / 'bundle', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    assert not (tmp_path / 'bundle' / 'keys').exists() or not any((tmp_path / 'bundle').rglob('*.key'))


def test_bundle_refuses_sources_outside_the_app_folder_links_and_missing_totp(tmp_path):
    root = make_app_root(tmp_path)
    outside = tmp_path / 'elsewhere'
    outside.mkdir(mode=0o700)
    (outside / 'workspace.key').write_bytes(os.urandom(32))
    config = json.loads((root / 'workspace-config.json').read_text())
    config['key_file'] = str(outside / 'workspace.key')
    (root / 'workspace-config.json').write_text(json.dumps(config))
    with pytest.raises(ValueError, match='outside the application folder'):
        build(root, tmp_path / 'b1', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    (tmp_path / 'second').mkdir()
    root2 = make_app_root(tmp_path / 'second')
    os.symlink(root2 / 'keys/workspace.key', root2 / 'keys/link.key')
    cfg = json.loads((root2 / 'workspace-config.json').read_text())
    cfg['key_file'] = str(root2 / 'keys/link.key')
    (root2 / 'workspace-config.json').write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match='Missing or linked'):
        build(root2, tmp_path / 'b2', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    (tmp_path / 'third').mkdir()
    root3 = make_app_root(tmp_path / 'third', totp=False)
    with pytest.raises(ValueError, match='TOTP'):
        build(root3, tmp_path / 'b3', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    (tmp_path / 'fourth').mkdir()
    with pytest.raises(ValueError, match='Result would not be a safe public demonstration'):
        build(make_app_root(tmp_path / 'fourth'), tmp_path / 'b4', origin='https://127.0.0.1:8443', server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    assert not (tmp_path / 'b1').exists() and not (tmp_path / 'b2').exists() and not (tmp_path / 'b3').exists() and not (tmp_path / 'b4').exists(), 'a refused build leaves nothing behind'


def test_launcher_preflight_refuses_unsafe_configurations_and_needs_the_acknowledgement(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('serve_public_demo', Path(__file__).resolve().parents[1] / 'scripts/serve_public_demo.py')
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    root = make_app_root(tmp_path)
    out = tmp_path / 'bundle'
    build(root, out, origin=ORIGIN, server_root=str(out), server_repo=str(tmp_path / 'repo'))
    (tmp_path / 'repo').mkdir()
    cert, key = tmp_path / 'tls.crt', tmp_path / 'tls.key'
    for f in (cert, key):
        f.write_bytes(b'x'); f.chmod(0o600)
    config = out / 'private/workspace-config.json'
    with pytest.raises(Exception, match='accept-public-synthetic-demo'):
        launcher.prepare(config, cert, key, False)
    configfile, origin, c, k = launcher.prepare(config, cert, key, True)
    assert origin == ORIGIN and c == cert.resolve() and k == key.resolve()
    unsafe = json.loads(config.read_text())
    unsafe['promotion_intake_config'] = '/x'
    config.write_text(json.dumps(unsafe))
    with pytest.raises(Exception, match='UPLOADS_AND_CHAIN_WRITES_MUST_BE_OFF'):
        launcher.prepare(config, cert, key, True)


def test_the_app_boundary_accepts_only_the_exact_public_host_and_origin():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope['path'])
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ok'})

    async def call(host, method='GET', origin=None, scheme='https'):
        headers = [(b'host', host.encode())] + ([(b'origin', origin.encode())] if origin else []) + ([(b'content-type', b'application/json')] if method == 'POST' else [])
        out = []
        async def receive():
            return {'type': 'http.request', 'body': b'{}', 'more_body': False}
        async def send(event):
            out.append(event)
        await RequestBoundary(inner, ORIGIN)({'type': 'http', 'scheme': scheme, 'method': method, 'path': '/x', 'headers': headers, 'query_string': b''}, receive, send)
        return out[0]['status']
    assert asyncio.run(call('demo.university.edu')) == 200
    assert asyncio.run(call('127.0.0.1:8443')) == 403
    assert asyncio.run(call('demo.university.edu', scheme='http')) == 403
    assert asyncio.run(call('demo.university.edu', 'POST', 'https://evil.example')) == 403
    assert asyncio.run(call('demo.university.edu', 'POST', ORIGIN)) == 200


# ---- End-to-end on a disposable app that mirrors the real layout (accounts, TOTP, access log, review keys).
from unit_totp_fixture import setup  # noqa: E402,F401  (pytest fixture)
from test_persistent_access import configured as totp_configured  # noqa: E402


def asgi(app, method, path, *, host, origin=None, body=None, cookie=None, csrf=None):
    headers = [(b'host', host.encode())]
    if origin:
        headers.append((b'origin', origin.encode()))
    if body is not None:
        headers.append((b'content-type', b'application/json'))
    if cookie:
        headers.append((b'cookie', cookie.encode()))
    if csrf:
        headers.append((b'x-csrf-token', csrf.encode()))
    payload = json.dumps(body).encode() if body is not None else b''
    out = []

    async def receive():
        return {'type': 'http.request', 'body': payload, 'more_body': False}

    async def send(event):
        out.append(event)
    asyncio.run(app({'type': 'http', 'scheme': 'https', 'method': method, 'path': path, 'headers': headers, 'query_string': b'',
                     'client': ('203.0.113.9', 5000), 'server': ('127.0.0.1', 8443)}, receive, send))
    start = out[0]
    return start['status'], dict((k.decode().lower(), v.decode()) for k, v in start['headers']), b''.join(e.get('body', b'') for e in out[1:])


def test_bundle_boots_as_a_public_app_with_totp_and_without_uploads_or_chain_writes(setup, monkeypatch):
    from app.access import totp
    from app.access.research_app import application, configured
    d = setup
    totp_configured(d)
    seeds = {p['username']: p['secret'] for p in json.loads((d['app'] / 'totp-enrollment-private.json').read_text())['accounts']}
    out = d['app'].parent / 'bundle'
    summary = build(d['app'], out, origin=ORIGIN, server_root=str(out), server_repo=str(Path(__file__).resolve().parents[2]))
    assert summary['stores'] == 3 and summary['chain_keys_included'] is False
    copied = {p.name for p in out.rglob('*') if p.is_file()}
    assert not any(name in copied for name in ('research-access-signer.key', 'research-presentation-signer.key', 'credentials.json', 'totp-enrollment-private.json', 'accounts.json'))
    store, origin = configured(out / 'private/workspace-config.json')
    assert origin == ORIGIN and store.promotion_intake_config is None and store.personnel_intake_config is None
    monkeypatch.setenv('PPI_RESEARCH_CONFIG', str(out / 'private/workspace-config.json'))
    app = application()
    login = '/api/auth/login'
    good = {'username': 'research.hq', 'password': 'invented-private-fixture-password',
            'totp_code': totp.code(seeds['research.hq'], int(__import__('time').time()) // 30)}
    assert asgi(app, 'POST', login, host='127.0.0.1:8443', origin=ORIGIN, body=good)[0] == 403, 'a request that does not carry the public host is refused'
    assert asgi(app, 'POST', login, host='demo.university.edu', origin='https://evil.example', body=good)[0] == 403
    assert asgi(app, 'POST', login, host='demo.university.edu', origin=ORIGIN, body={k: v for k, v in good.items() if k != 'totp_code'})[0] == 401, 'no second factor, no login'
    assert asgi(app, 'POST', login, host='demo.university.edu', origin=ORIGIN, body={**good, 'totp_code': '000000'})[0] == 401
    status, headers, _ = asgi(app, 'POST', login, host='demo.university.edu', origin=ORIGIN, body=good)
    assert status == 200 and headers['set-cookie'].startswith('__Host-ppi-session=') and 'secure' in headers['set-cookie'].lower() and 'httponly' in headers['set-cookie'].lower()
    # The same code cannot be used twice (replay guard travels with the copied store).
    assert asgi(app, 'POST', login, host='demo.university.edu', origin=ORIGIN, body=good)[0] == 401
    # Upload and chain-write endpoints do not exist in the public copy.
    token = headers['set-cookie'].split(';')[0]
    for path in ('/api/research/intake/capabilities', '/api/research/promotions/capabilities'):
        status, _, body = asgi(app, 'GET', path, host='demo.university.edu', cookie=token)
        assert status == 200 and json.loads(body)['configured' if 'promotions' in path else 'can_upload'] in (False,), path
    csrf = json.loads(asgi(app, 'GET', '/api/auth/session', host='demo.university.edu', cookie=token)[2])['csrf_token']
    for path in ('/api/research/intake/preview', '/api/research/intake/commit', '/api/research/promotions/preview', '/api/research/promotions/commit'):
        status, _, body = asgi(app, 'POST', path, host='demo.university.edu', origin=ORIGIN, body={}, cookie=token, csrf=csrf)
        assert status in (400, 503), (path, status, body)
        assert b'COMMITTED' not in body and b'ACCEPTED' not in body
    assert asgi(app, 'GET', '/api/auth/session', host='demo.university.edu')[0] == 401
