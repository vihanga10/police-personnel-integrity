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


def make_intake(tmp_path, folder, database):
    """An intake folder like the real one: the allowlisted files plus the credentials and chain material that must never leave."""
    state, backup = tmp_path / folder, tmp_path / (folder + '-backup')
    for d in (state, backup, state / 'analysis-v1', state / 'approval-v1', state / 'fabric-deployment', state / 'chain-jobs'):
        d.mkdir(mode=0o700)
    def put(p, data):
        p.write_bytes(data)
        p.chmod(0o600)
        return str(p)
    key = os.urandom(32)
    put(state / 'intake.key', key); put(backup / 'intake.key', key)
    for rel in (database, 'worker.lock', 'analysis-v1/availability.sqlite3', 'approval-v1/decisions.sqlite3'):
        put(state / rel, b'synthetic-store')
    for rel in ('postgres-writer.json', 'mongo-writer.json', 'chain-recovery.key', 'fabric-deployment/channel.json', 'chain-jobs/job.json', 'runtime-before-repin-1.json'):
        put(state / rel, b'SECRET-NEVER-COPY')
    analysis, approval, runtime = state / 'analysis-config.json', state / 'approval-config.json', state / 'runtime.json'
    put(analysis, json.dumps({'policy': 'A', 'intake_config': str(runtime), 'analysis_root': str(state / 'analysis-v1')}).encode())
    put(approval, json.dumps({'policy': 'P', 'decision_root': str(state / 'approval-v1'), 'legacy_queued': {}, 'reviewer_ids': ['r']}).encode())
    put(runtime, json.dumps({'policy': 'PERSONNEL_INTAKE_RUNTIME_V1', 'analysis_config': str(analysis), 'approval_config': str(approval), 'backup_key_file': str(backup / 'intake.key'),
        'key_file': str(state / 'intake.key'), 'state_root': str(state), 'baseline_source_set_sha256': 'b' * 64, 'importer_ids': ['i'], 'source_pins': {'backend/x.py': 'c' * 64},
        'chains': {'fabric': {'gateway': '/laptop/gw'}, 'sepolia': {'wallet': '/laptop/wallet'}}, 'postgres_credentials': str(state / 'postgres-writer.json'),
        'mongo_credentials': str(state / 'mongo-writer.json')}).encode())
    return str(runtime)


def make_app_root(tmp_path, *, totp=True, extra_workspace=None, anchor=True, extra_file=None, intake=True):
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
                 'state_directory': str(root / 'workspace-state'), **({'personnel_intake_config': make_intake(tmp_path, 'application-intake-v1', 'personnel-intake.sqlite3'),
                 'promotion_intake_config': make_intake(tmp_path, 'application-promotions-v1', 'promotion-intake.sqlite3')} if intake else {}),
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
    assert workspace['intake_read_only'] is True and 'anchor_config' not in log
    assert access['origin'] == ORIGIN and access['totp_required'] is True and access['repository'] == '/srv/ppi/repo'
    assert workspace['state_directory'] == '/srv/ppi/state/workspace' and workspace['key_file'] == '/srv/ppi/keys/workspace.key'
    assert workspace['access_config'] == '/srv/ppi/private/access-config.json' and log['reader_grants'] == ['/srv/ppi/grants/grant-hq.json']
    runtimes = {k: json.loads((out / 'private' / (k + '-runtime.json')).read_text()) for k in ('dataset', 'promotion')}
    for kind, runtime in runtimes.items():
        assert not {'chains', 'postgres_credentials', 'mongo_credentials'} & set(runtime), kind
        assert runtime['source_pins'] == {'backend/x.py': 'c' * 64} and runtime['state_root'] == '/srv/ppi/intake/%s/state' % kind
        analysis = json.loads((out / 'private' / (kind + '-analysis-config.json')).read_text())
        approval = json.loads((out / 'private' / (kind + '-approval-config.json')).read_text())
        assert runtime['analysis_config'] == '/srv/ppi/private/%s-analysis-config.json' % kind and analysis['intake_config'] == '/srv/ppi/private/%s-runtime.json' % kind
        assert analysis['analysis_root'] == '/srv/ppi/intake/%s/analysis' % kind and approval['decision_root'] == '/srv/ppi/intake/%s/decisions' % kind
        assert (out / 'intake' / kind / 'keys/intake.key').read_bytes() == (out / 'intake' / kind / 'keys/intake-backup.key').read_bytes()
        assert (out / 'intake' / kind / 'analysis/availability.sqlite3').exists() and (out / 'intake' / kind / 'decisions/decisions.sqlite3').exists()
    assert workspace['personnel_intake_config'] == '/srv/ppi/private/dataset-runtime.json' and workspace['promotion_intake_config'] == '/srv/ppi/private/promotion-runtime.json'
    assert summary['intake_stores_read_only'] == ['dataset', 'promotion']
    assert problems(workspace, access, log, list(runtimes.values())) == []
    assert all('laptop' not in json.dumps(v) for v in (workspace, access, log, *runtimes.values()))
    for forbidden in ('postgres-writer', 'mongo-writer', 'chain-recovery', 'fabric-deployment', 'chain-jobs', 'runtime-before-repin', 'SECRET-NEVER-COPY'):
        assert not any(forbidden in str(p.relative_to(out)) for p in out.rglob('*')), forbidden
        assert not any(forbidden.encode() in p.read_bytes() for p in out.rglob('*') if p.is_file() and p.stat().st_size < 10_000), forbidden
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
    original = config.read_text()
    unsafe = json.loads(original)
    unsafe['intake_read_only'] = False
    config.write_text(json.dumps(unsafe))
    with pytest.raises(Exception, match='UPLOADS_AND_CHAIN_WRITES_MUST_BE_OFF'):
        launcher.prepare(config, cert, key, True)
    config.write_text(original)
    runtime_file = out / 'private/dataset-runtime.json'
    runtime = json.loads(runtime_file.read_text())
    runtime['chains'] = {'fabric': {}}
    runtime_file.write_text(json.dumps(runtime))
    with pytest.raises(Exception, match='INTAKE_RUNTIME_MUST_NOT_HOLD:chains'):
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


def test_bundle_refuses_an_intake_folder_that_is_incomplete_or_has_misplaced_keys(tmp_path):
    root = make_app_root(tmp_path)
    runtime_file = Path(json.loads((root / 'workspace-config.json').read_text())['personnel_intake_config'])
    runtime = json.loads(runtime_file.read_text())
    (Path(runtime['state_root']) / 'personnel-intake.sqlite3').unlink()
    with pytest.raises(ValueError, match='Intake database missing'):
        build(root, tmp_path / 'b1', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    assert not (tmp_path / 'b1').exists()
    (tmp_path / 'again').mkdir()
    root = make_app_root(tmp_path / 'again')
    runtime_file = Path(json.loads((root / 'workspace-config.json').read_text())['personnel_intake_config'])
    runtime = json.loads(runtime_file.read_text())
    stray = tmp_path / 'again' / 'elsewhere.key'
    stray.write_bytes(Path(runtime['key_file']).read_bytes()); stray.chmod(0o600)
    runtime['backup_key_file'] = str(stray)
    runtime_file.write_text(json.dumps(runtime))
    with pytest.raises(ValueError, match='Intake key locations differ'):
        build(root, tmp_path / 'b2', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo')
    assert not (tmp_path / 'b2').exists()


def test_bundle_refuses_stale_intake_pins_when_a_repository_is_given(tmp_path):
    root = make_app_root(tmp_path)
    with pytest.raises(Exception, match='pins out of date|source pins'):
        build(root, tmp_path / 'b', origin=ORIGIN, server_root='/srv/ppi', server_repo='/srv/ppi/repo', repo=Path(__file__).resolve().parents[2])
    assert not (tmp_path / 'b').exists()


# ---- End-to-end with a real on-disk intake (real classes, real config chain), loaded read-only from the bundle.
def real_intake(d, officer, repo):
    import hashlib
    from app.intake.dataset_pipeline import merkle_proof as M
    from app.intake.dataset_pipeline.acceptance import DatasetApprovals, POLICY as APPROVAL_POLICY
    from app.intake.dataset_pipeline.analysis import DatasetAnalysis, POLICY as ANALYSIS_POLICY
    from app.intake.dataset_pipeline.configuration import source_pins
    from app.intake.dataset_pipeline.store import DatasetStore
    base = d['app'].parent
    state, backup = base / 'application-intake-v1', base / 'application-intake-v1-backup'
    for folder in (state, backup, state / 'analysis-v1', state / 'approval-v1'):
        folder.mkdir(mode=0o700)
    key = os.urandom(32)
    for f in (state / 'intake.key', backup / 'intake.key'):
        f.write_bytes(key)
        f.chmod(0o600)
    store = DatasetStore(state, state / 'intake.key', backup / 'intake.key', repo=repo, create=True)
    nodes = [M.leaf_node(hashlib.sha256(('officer-%d' % i).encode()).digest()) for i in range(5)]
    entry = {'publication_id': 'a' * 64, 'commitment': 'b' * 64, 'leaf_index': 2, 'leaf_sha256': nodes[2].hex(), 'proof': M.proof(nodes, 2)}
    meta = {'policy': 'OFFICER_PROTECTED_COMMITMENT_V1', 'key_version': 'commit-v1', 'merkle_root': M.root(nodes), 'batch_publication_id': 'c' * 64, 'batch_commitment': 'd' * 64,
            'public_payload_sha256': 'e' * 64, 'officers': 1, 'leaves': 5, 'sepolia_contract': '0x' + '1' * 40, 'sepolia_chain_id': 11155111, 'sepolia_sealing_block': '0x1',
            'sepolia_sealing_block_hash': '0x2', 'fabric_channel': 'personnel', 'fabric_chaincode': 'officer-evidence-v1', 'verified_on': '2026-10-09', 'verification_basis': 'TEST'}
    store.install_original_commitments(meta, {officer: entry})
    store.install_original_receipts({'batch_publication_id': 'c' * 64, 'merkle_root': meta['merkle_root'], 'chunk_size': 100,
        'fabric': {**{'chunk-%03d' % i: {'transaction_id': '%064x' % (i + 1), 'block_number': 10 + i, 'validation_code': 0} for i in range(66)},
                   'batch': {'transaction_id': 'f' * 64, 'block_number': 5, 'validation_code': 0}, 'seal': {'transaction_id': 'e' * 64, 'block_number': 99, 'validation_code': 0}},
        'sepolia': [{'transaction_hash': '0x%064x' % (i + 1), 'block': hex(1000 + i), 'block_hash': '0x' + '9' * 64} for i in range(68)]})
    runtime, analysis_file, approval_file = state / 'runtime.json', state / 'analysis-config.json', state / 'approval-config.json'
    for f, value in ((analysis_file, {'policy': ANALYSIS_POLICY, 'intake_config': str(runtime), 'analysis_root': str(state / 'analysis-v1')}),
                     (approval_file, {'policy': APPROVAL_POLICY, 'decision_root': str(state / 'approval-v1'), 'reviewer_ids': [str(__import__('uuid').uuid4())], 'legacy_queued': {}}),
                     (runtime, {'policy': 'PERSONNEL_INTAKE_RUNTIME_V1', 'analysis_config': str(analysis_file), 'approval_config': str(approval_file),
                                'backup_key_file': str(backup / 'intake.key'), 'key_file': str(state / 'intake.key'), 'state_root': str(state),
                                'baseline_source_set_sha256': 'a' * 64, 'source_public_sha256': 'a' * 64, 'importer_ids': [str(__import__('uuid').uuid4())],
                                'source_pins': source_pins(repo), 'chains': {'fabric': {}, 'sepolia': {}},
                                'postgres_credentials': str(state / 'postgres-writer.json'), 'mongo_credentials': str(state / 'mongo-writer.json')})):
        f.write_text(json.dumps(value))
        f.chmod(0o600)
    for secret in ('postgres-writer.json', 'mongo-writer.json', 'chain-recovery.key'):
        (state / secret).write_bytes(b'SECRET-NEVER-COPY')
        (state / secret).chmod(0o600)
    analysis = DatasetAnalysis(d['w'], analysis_file, create=True)
    DatasetApprovals(d['w'], analysis, approval_file, create=True)
    return runtime


def test_public_copy_serves_the_stored_fingerprint_and_receipts_from_a_read_only_intake(setup, monkeypatch):
    import time
    from app.access import totp
    from app.access.research_app import application
    repo = Path(__file__).resolve().parents[2]
    d = setup
    totp_configured(d)
    officer = d['members'][0]['officer_uid']
    seeds = {p['username']: p['secret'] for p in json.loads((d['app'] / 'totp-enrollment-private.json').read_text())['accounts']}
    runtime = real_intake(d, officer, repo)
    workspace_file = d['app'] / 'workspace-config.json'
    workspace = json.loads(workspace_file.read_text())
    workspace['personnel_intake_config'] = str(runtime)
    workspace_file.write_text(json.dumps(workspace))
    out = d['app'].parent / 'bundle'
    summary = build(d['app'], out, origin=ORIGIN, server_root=str(out), server_repo=str(repo), repo=repo)
    assert summary['intake_stores_read_only'] == ['dataset']
    assert not any('postgres' in str(p) or 'mongo' in str(p) or 'chain-recovery' in str(p) for p in out.rglob('*'))
    monkeypatch.setenv('PPI_RESEARCH_CONFIG', str(out / 'private/workspace-config.json'))
    app = application()
    status, headers, _ = asgi(app, 'POST', '/api/auth/login', host='demo.university.edu', origin=ORIGIN, body={
        'username': 'research.hq', 'password': 'invented-private-fixture-password', 'totp_code': totp.code(seeds['research.hq'], int(time.time()) // 30)})
    assert status == 200
    token = headers['set-cookie'].split(';')[0]
    status, _, body = asgi(app, 'GET', '/api/research/officers/%s/integrity' % officer, host='demo.university.edu', cookie=token)
    assert status == 200, body
    view = json.loads(body)
    assert view['original_available'] is True and view['original']['inclusion_verified'] is True and view['original']['commitment'] == 'b' * 64
    assert view['original']['anchors']['fabric']['transaction_id'] == '%064x' % 1 and view['original']['anchors']['sepolia']['transaction_hash'] == '0x%064x' % 2
    assert view['all_recomputed_checks_passed'] is True and view['fresh_chain_reads'] is False
    # Still no way to upload or publish from the public copy.
    status, _, body = asgi(app, 'GET', '/api/research/intake/capabilities', host='demo.university.edu', cookie=token)
    assert status == 200 and json.loads(body)['configured'] is False and json.loads(body)['can_upload'] is False
