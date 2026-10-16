"""Explicit generated-record deployment; full original replay is never substituted.

Operator-only, with owned loopback mTLS listeners. These witnesses are separate
stores/key domains on the same computer, not independently administered services.
Original datasets, commitments, network configurations and transactions stay intact.
"""
import base64
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from app.access import directory as D, research_policy as P, research_connection as C
from app.access import research_connection_runtime as R
from app.access.policy import POLICY as ACCESS_POLICY, account, encoded, permitted, require
from app.access.store import private
from app.identity import observed_recording_journal as J, recording_tip_witness as W
from app.identity import witness_secure_transport as T
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest

POLICY = 'GENERATED_DATASET_DEPLOYMENT_V1'
ACCESS_ID = 'research-operator-access'
PRESENTATION_ID = 'research-operator-presentation'
OWNER_ID = 'generated-record-owner'
REVIEW = 'GENERATED_RESEARCH_SCOPE_SIMULATION_V1'
DOMAINS = ('recorder', 'observation', 'recording-registry', 'recording-recovery',
           'recording-witness', 'findings-writer', 'findings-reviewer',
           'findings-registry', 'findings-recovery', 'findings-witness', OWNER_ID)


def write(path, value, *, replace=False):
    """Owner-only, durable publication. Replacements require an existing private file."""
    path = Path(path)
    private(path.parent, directory=True)
    data = value if type(value) is bytes else encoded(value)
    temporary = path.with_name('.stage3-' + uuid4().hex + '.tmp') if replace else path
    if replace: private(path)
    try:
        with temporary.open('xb') as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(data); file.flush(); os.fsync(file.fileno())
        if replace: os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if replace: temporary.unlink(missing_ok=True)


def public(key): return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def pins(keys): return {k: base64.b64encode(v).decode() for k, v in keys.items()}
def signed(key, key_id, payload):
    return dict(key_id=key_id, payload=deepcopy(payload), signature=base64.b64encode(key.sign(encoded(payload))).decode())


def signing(root, repo, domain):
    key = R.signer(root / 'keys' / (domain + '.key'), repo)
    return key, {domain: public(key)}


def create_crypto(root, domain):
    value = dict(active_encryption_key_version='enc-v1', active_lookup_key_version='lookup-v1',
        encryption_keys={'enc-v1': base64.b64encode(os.urandom(32)).decode()},
        lookup_keys={'lookup-v1': base64.b64encode(os.urandom(32)).decode()})
    first, second = root / 'keys' / (domain + '.json'), root / 'key-backup' / (domain + '.json')
    write(first, value); write(second, value)
    return dict(primary=str(first), backup=str(second))


def create_pki(root):
    """Private direct-CA mTLS certificates; distinct from application signing keys."""
    directory = root / 'pki'; directory.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Generated research witness CA')])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .sign(ca_key, hashes.SHA256()))
    write(directory / 'ca.crt', ca.public_bytes(Encoding.PEM))
    write(directory / 'ca.key', ca_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    for role, eku in (('server', ExtendedKeyUsageOID.SERVER_AUTH), ('client', ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Research witness ' + role)]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([eku]), False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(ca_key, hashes.SHA256()))
        write(directory / (role + '.crt'), certificate.public_bytes(Encoding.PEM))
        write(directory / (role + '.key'), key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


def validate_plan(repo, root, app_root):
    private(root, directory=True, repo=repo); private(app_root, directory=True, repo=repo)
    plan = R.fields(R.read_json(root / 'deployment.json', repo),
        ('policy', 'repository', 'app_root', 'source', 'crypto', 'detail_limit', 'effective_on', 'record_origin', 'scope_basis'))
    require(plan['policy'] == POLICY and Path(plan['repository']).resolve() == repo and
        Path(plan['app_root']).resolve() == app_root and plan['record_origin'] == 'GENERATED_RESEARCH_RECORDS' and
        plan['scope_basis'] == REVIEW, 'Generated deployment binding differs')
    require(type(plan['detail_limit']) is int and 2 <= plan['detail_limit'] <= 100)
    date.fromisoformat(plan['effective_on'])
    R.fields(plan['source'], set(C.SOURCE_FIELDS) - {'audit_gate_attempt'})
    for name, path in plan['source'].items(): private(path, directory=name.endswith('_attempt'), repo=repo)
    return plan


def prepare(repo, root, app_root, source, *, detail_limit=2, effective_on=None):
    """No source rows, databases or RPC read. Explicit private provisioning only."""
    repo = Path(repo).resolve(); app_root = Path(app_root).absolute(); root = Path(root).absolute()
    C.revision(repo)
    require(type(detail_limit) is int and 2 <= detail_limit <= 100)
    effective_on = effective_on or datetime.now(timezone.utc).date()
    require(type(effective_on) is date)
    private(app_root, directory=True, repo=repo); private(root.parent, directory=True, repo=repo)
    require(not root.exists() and not root.is_symlink(), 'New deployment root required; existing state must be preserved')
    require(not root.is_relative_to(app_root) and not app_root.is_relative_to(root), 'Separate application and deployment roots required')
    manifest = R.read_json(app_root / 'accounts.json', repo)
    require(manifest['record_origin'] == 'GENERATED_RESEARCH_RECORDS' and len(manifest['accounts']) == 10)
    workspace = R.read_json(app_root / 'workspace-config.json', repo)
    require('accountability_config' in workspace, 'Stage 2 accountability must be provisioned first')
    R.fields(source, set(C.SOURCE_FIELDS) - {'audit_gate_attempt'})
    original_key = Path(source['key_file']).absolute()
    # Original source key can remain inside the repository; only the new copy is
    # used by this operator connection, and it must be byte-for-byte identical.
    from app.identity.bind_evidence_destinations import private_path
    original = private_path(original_key).read_bytes()
    for name, path in source.items():
        if name != 'key_file': private(path, directory=name.endswith('_attempt'), repo=repo)
    R.crypto_pair({'primary': str(private_path(original_key)), 'backup': source['backup_key_file']}, None)
    root.mkdir(mode=0o700)
    for name in ('keys', 'key-backup', 'officers', 'imports'): (root / name).mkdir(mode=0o700)
    copied = root / 'keys' / 'original-identity-copy.json'
    write(copied, original)
    require(copied.read_bytes() == original, 'Original identity copy differs')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    for domain in DOMAINS:
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        write(root / 'keys' / (domain + '.key'), seed); write(root / 'key-backup' / (domain + '.key'), seed)
    crypto = {domain: create_crypto(root, domain) for domain in
              ('recording-registry', 'recording-witness', 'findings-registry', 'findings-witness')}
    create_pki(root)
    write(root / 'deployment.json', dict(policy=POLICY, repository=str(repo), app_root=str(app_root),
        source={**source, 'key_file': str(copied)}, crypto=crypto, detail_limit=detail_limit,
        effective_on=effective_on.isoformat(), record_origin='GENERATED_RESEARCH_RECORDS', scope_basis=REVIEW))
    write(root / 'operator.lock', b'')
    return dict(status='STAGE3_PRIVATE_PREPARATION_PASSED', record_origin='GENERATED_RESEARCH_RECORDS',
        initial_detail_limit=detail_limit, scope_basis='EXPLICIT_SIMULATION', original_identity_copy_exact=True,
        source_rows_read=False, ui_connected=False, blockchain_submission=False)


def memberships(officers):
    """Explicit deterministic simulation; no CSV rank/posting becomes an access grant."""
    return [dict(officer_uid=officer, membership=dict(PROVINCE='RESEARCH_PROVINCE_A',
        DISTRICT='RESEARCH_DISTRICT_A', DIVISION='RESEARCH_DIVISION_' + ('A' if index % 2 == 0 else 'B'),
        STATION='RESEARCH_STATION_' + ('A' if index % 2 == 0 else 'B')))
        for index, officer in enumerate(sorted(officers))]


def witness_service(value, repo):
    value = R.fields(value, ('root', 'witness_id', 'registry_id', 'journal_anchor', 'crypto',
        'signing_key', 'key_id', 'witness_keys', 'writer_keys', 'expected_enrollment'))
    crypto, backup = R.crypto_pair(value['crypto'], repo)
    return W.DurableTipWitness(root=value['root'], repo=repo, witness_id=value['witness_id'],
        registry_id=value['registry_id'], journal_anchor=value['journal_anchor'], crypto=crypto, backup=backup,
        signer=R.signer(value['signing_key'], repo), key_id=value['key_id'],
        witness_keys=R.public_keys(value['witness_keys']), writer_keys=R.public_keys(value['writer_keys']),
        expected_enrollment=value['expected_enrollment'])


@contextmanager
def listener(service, control, root, repo):
    profile = R.read_json(control['profile'], repo)['payload']
    from urllib.parse import urlsplit
    endpoint = urlsplit(profile['endpoint'])
    require(endpoint.hostname == '127.0.0.1', 'Operator witnesses bind loopback only')
    server = T.WitnessHTTPSServer(('127.0.0.1', endpoint.port), service,
        profile_path=control['profile'], expected_profile_sha256=control['profile_sha256'],
        ca_certificate=root / 'pki/ca.crt', server_certificate=root / 'pki/server.crt', server_key=root / 'pki/server.key')
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try: yield server
    finally: server.shutdown(); server.server_close(); thread.join(timeout=10)


def create_witness(root, officer_root, repo, plan, *, domain, registry_id, anchor, writer_keys):
    directory = officer_root / (domain + '-store'); directory.mkdir(mode=0o700)
    signer, keys = signing(root, repo, domain)
    value = dict(root=str(directory), witness_id=domain + '-' + officer_root.name, registry_id=registry_id,
        journal_anchor=anchor, crypto=plan['crypto'][domain], signing_key=str(root / 'keys' / (domain + '.key')),
        key_id=domain, witness_keys=pins(keys), writer_keys=pins(writer_keys), expected_enrollment=None)
    crypto, backup = R.crypto_pair(value['crypto'], repo)
    service = W.DurableTipWitness(root=directory, repo=repo, witness_id=value['witness_id'],
        registry_id=registry_id, journal_anchor=anchor, crypto=crypto, backup=backup,
        signer=signer, key_id=domain, witness_keys=keys, writer_keys=writer_keys)
    value['expected_enrollment'] = service.initialize()
    service_file = officer_root / (domain + '-service.json'); write(service_file, value)
    with socket.socket() as socket_:
        socket_.bind(('127.0.0.1', 0)); port = socket_.getsockname()[1]
    profile_file = officer_root / 'control' / (domain + '-profile.json')
    profile_pin = T.provision(service, profile_path=profile_file,
        endpoint=f'https://127.0.0.1:{port}' + T.PATH,
        ca_certificate=root / 'pki/ca.crt', server_certificate=root / 'pki/server.crt', server_key=root / 'pki/server.key',
        client_certificates={key_id: root / 'pki/client.crt' for key_id in writer_keys}, requests_per_minute=120)
    control = dict(witness_id=value['witness_id'], witness_keys=pins(keys), profile=str(profile_file),
        profile_sha256=profile_pin, ca_certificate=str(root / 'pki/ca.crt'),
        client_certificate=str(root / 'pki/client.crt'), client_key=str(root / 'pki/client.key'))
    return service, control


def open_officer(stack, root, repo, plan, snapshot, officer):
    """Resume only a fully published runtime; ambiguous partial state fails closed."""
    officer_root = root / 'officers' / officer
    if officer_root.exists():
        value = R.fields(R.read_json(officer_root / 'runtime.json', repo),
                        ('recording_config', 'findings_config', 'capture'))
        for domain, section in (('recording-witness', 'recording'), ('findings-witness', 'findings')):
            runtime = R.read_json(value[section + '_config'], repo)
            control = runtime['witness'] if section == 'recording' else runtime['registry']['witness']
            service = witness_service(R.read_json(officer_root / (domain + '-service.json'), repo), repo)
            stack.enter_context(listener(service, control, root, repo))
        return value
    officer_root.mkdir(mode=0o700)
    for name in ('recording-journal', 'recording-registry', 'findings-journal', 'findings-registry', 'capture', 'control'):
        (officer_root / name).mkdir(mode=0o700)
    source_pair = dict(primary=plan['source']['key_file'], backup=plan['source']['backup_key_file'])
    recorder, recorder_keys = signing(root, repo, 'recorder')
    baseline = J.create_loaded_baseline(snapshot, repo, officer, officer_root / 'recording-journal',
                                        recorder, 'recorder', recorder_keys)
    registry_signer, registry_keys = signing(root, repo, 'recording-registry')
    _, observation_keys = signing(root, repo, 'observation'); _, recovery_keys = signing(root, repo, 'recording-recovery')
    registry_id = str(uuid4())
    service, control = create_witness(root, officer_root, repo, plan, domain='recording-witness',
        registry_id=registry_id, anchor=baseline['journal_anchor'], writer_keys=registry_keys)
    stack.enter_context(listener(service, control, root, repo))
    recording = dict(policy='RESEARCH_RECORDING_RUNTIME_V1', registry_root=str(officer_root / 'recording-registry'),
        journal_root=str(officer_root / 'recording-journal'), journal_anchor=baseline['journal_anchor'], registry_id=registry_id,
        registry_crypto=plan['crypto']['recording-registry'], journal_crypto=source_pair,
        signing_key=str(root / 'keys/recording-registry.key'), key_id='recording-registry',
        registry_keys=pins(registry_keys), recorder_keys=pins(recorder_keys), observation_keys=pins(observation_keys),
        recovery_keys=pins(recovery_keys), witness=control)
    recording_file = officer_root / 'recording-runtime.json'; write(recording_file, recording)
    R.recording(recording_file, repo).register(checkpoint_file=baseline['checkpoint_file'], checkpoint_sha256=baseline['checkpoint_sha256'])
    ledger_id, registry_id = str(uuid4()), str(uuid4())
    from app.identity.findings_tip_witness import findings_scope_anchor
    _, writer_keys = signing(root, repo, 'findings-writer'); _, reviewer_keys = signing(root, repo, 'findings-reviewer')
    _, registry_keys = signing(root, repo, 'findings-registry'); _, recovery_keys = signing(root, repo, 'findings-recovery')
    service, control = create_witness(root, officer_root, repo, plan, domain='findings-witness', registry_id=registry_id,
        anchor=findings_scope_anchor(registry_id, ledger_id), writer_keys=registry_keys)
    stack.enter_context(listener(service, control, root, repo))
    findings = dict(policy='RESEARCH_FINDINGS_RUNTIME_V1',
        journal=dict(root=str(officer_root / 'findings-journal'), ledger_id=ledger_id, officer_uid=officer,
            crypto=source_pair, signing_key=str(root / 'keys/findings-writer.key'), key_id='findings-writer',
            writer_keys=pins(writer_keys), reviewer_keys=pins(reviewer_keys), authority_keys={},
            reviewer_identities={}, authority_scopes={}),
        registry=dict(root=str(officer_root / 'findings-registry'), registry_id=registry_id,
            crypto=plan['crypto']['findings-registry'], signing_key=str(root / 'keys/findings-registry.key'),
            key_id='findings-registry', registry_keys=pins(registry_keys), recovery_keys=pins(recovery_keys), witness=control))
    findings_file = officer_root / 'findings-runtime.json'; write(findings_file, findings)
    result = dict(recording_config=str(recording_file), findings_config=str(findings_file),
        capture=dict(operation_id=str(uuid4()), finding_id=str(uuid4()), known_at=baseline['observed_at'],
                     effective_on=plan['effective_on'], destination=str(officer_root / 'capture/comparison.encrypted.json')))
    # Runtime is durable before capture; an interrupted capture retains its exact IDs.
    write(officer_root / 'runtime.json', result)
    return result


def current_accounts(app_root, repo, key):
    from app.access.api import configured_store
    access, _ = configured_store(app_root / 'access-config.json')
    manifest = R.read_json(app_root / 'accounts.json', repo)
    require(manifest['record_origin'] == 'GENERATED_RESEARCH_RECORDS' and len(manifest['accounts']) == 10)
    require(public(key) == access.keys[ACCESS_ID])
    result = []
    with access.transaction() as connection:
        for declared in manifest['accounts']:
            ident = access.index('USER', declared['username'])
            row = connection.execute('SELECT version,value FROM users WHERE id=?', (ident,)).fetchone()
            require(row is not None, 'Stage 1 account missing')
            grant = access.open('USER', ident, row[0], row[1])['grant']
            value = account(grant, access.keys)
            require(value['user_id'] == declared['user_id'] and
                all(value[k] == declared[k] for k in ('role', 'scope_type', 'scope_id', 'active')),
                'Declared simulation account scope differs')
            result.append(value)
    return result


def connect(repo, root, app_root, audit_attempt, *, selected_officers=None, review_policy=None, progress=lambda _: None):
    """Full original replay -> journals -> signed bounded UI copies -> validated import.

    No permit renewal, fallback, historical-date fabrication or chain transaction.
    Stop the app first: opening its access store invalidates earlier sessions.
    """
    repo = Path(repo).resolve(); root = Path(root).absolute(); app_root = Path(app_root).absolute()
    plan = validate_plan(repo, root, app_root)
    lock_path = private(root / 'operator.lock', repo=repo)
    with lock_path.open('rb') as lock:
        require(fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB) is None, 'Another connection operation is active')
        revision = C.revision(repo)
        access_signer = R.signer(app_root / 'keys/research-access-signer.key', repo)
        presentation_signer = R.signer(app_root / 'keys/research-presentation-signer.key', repo)
        accounts = current_accounts(app_root, repo, access_signer)
        workspace = R.read_json(app_root / 'workspace-config.json', repo)
        review_permissions = None
        if review_policy is not None:
            from app.access.stage4_workflow import request_policy
            review_policy_pin = C.file_digest(review_policy, repo, C.CONFIG_MAX_BYTES)
            policy_settings = R.read_json(review_policy, repo)['payload']['settings_file']
            policy_settings_pin = C.file_digest(policy_settings, repo, C.CONFIG_MAX_BYTES)
            review_permissions = request_policy(review_policy, repo, app_root, revision, accounts)
            require(C.file_digest(review_policy, repo, C.CONFIG_MAX_BYTES) == review_policy_pin and
                    C.file_digest(policy_settings, repo, C.CONFIG_MAX_BYTES) == policy_settings_pin, 'Review request policy changed')
        require(public(presentation_signer) == R.public_keys(workspace['presentation_keys'])[PRESENTATION_ID])
        attempt = root / 'imports' / str(uuid4()); attempt.mkdir(mode=0o700)
        owner, owner_keys = signing(root, repo, OWNER_ID); now = int(time.time())
        approval = dict(policy=C.AUTH_POLICY, kind='DATA_USE', issued_at=now-1, expires_at=now+86398,
            source_public_sha256=C.PUBLIC_SHA, code_revision=revision, purpose='SCOPED_RESEARCH_UI',
            directory_all_officers=True, detail_officer_uids='ALL', review_reference=REVIEW,
            custodian_reference='GENERATED_RECORD_OWNER_NOT_POLICE_CUSTODIAN')
        auth_file = attempt / 'generated-owner-authorization.json'; write(auth_file, signed(owner, OWNER_ID, approval))
        source = {**plan['source'], 'audit_gate_attempt': str(Path(audit_attempt).absolute())}
        config = dict(policy=C.POLICY, repository=str(repo), source=source,
            access_config=str(app_root / 'access-config.json'), workspace_config=str(app_root / 'workspace-config.json'),
            data_authorization=str(auth_file), authorization_keys=pins(owner_keys), officers={})
        bootstrap_file = attempt / 'bootstrap-config.json'; write(bootstrap_file, config)
        connection = C.Connection(bootstrap_file)
        progress('FULL_ORIGINAL_BATCH_REPLAY')
        snapshot = connection._snapshot([])  # Exact unchanged production loader, once.
        permit = AlgorithmPermit(snapshot); permit.check(snapshot)
        officers = sorted(C.Connection._identities(snapshot))
        if selected_officers is None:
            selected = officers[:plan['detail_limit']]
            require(len(selected) == plan['detail_limit'], 'Too few original officers for the selected detail batch')
        else:
            require(type(selected_officers) is list and 0 < len(selected_officers) == len(set(selected_officers)) <= 100 and
                    set(selected_officers) <= set(officers), 'Select at most 100 distinct original officer UUIDs')
            selected = sorted(selected_officers)
        membership = dict(policy=ACCESS_POLICY, kind='MEMBERSHIP', issued_at=now-1,
            expires_at=min(int(time.time()) + 3600, approval['expires_at']),
            source_public_sha256=C.PUBLIC_SHA, officers=memberships(officers), review_reference=REVIEW)
        membership_envelope = signed(access_signer, ACCESS_ID, membership)
        write(attempt / 'signed-simulation-membership.json', membership_envelope)
        with ExitStack() as stack:
            runtimes = {}
            for index, officer in enumerate(selected, 1):
                progress('RECORDING_AND_MTLS_WITNESSES_' + str(index) + '_OF_' + str(len(selected)))
                permit.check(snapshot)
                runtime = open_officer(stack, root, repo, plan, snapshot, officer)
                runtimes[officer] = {k: runtime[k] for k in ('recording_config', 'findings_config')}
                recording = R.recording(runtime['recording_config'], repo)
                findings = R.findings(runtime['findings_config'], repo, officer)
                from app.identity.protected_findings_capture import capture_loaded, _recording_transport
                _recording_transport(recording, repo); findings._config()
                # Completed captures are verified by their persisted IDs. A revision
                # change cannot silently re-sign or recreate an earlier intent.
                entries = findings.select()['entries']
                captured = [entry for entry in entries if entry['entry']['operation_id'] == runtime['capture']['operation_id']]
                if not captured:
                    progress('PROTECTED_FINDINGS_CAPTURE_' + str(index))
                    capture_loaded(snapshot, repo, recording, findings, officer_uid=officer,
                        effective_on=date.fromisoformat(runtime['capture']['effective_on']),
                        known_at=datetime.fromisoformat(runtime['capture']['known_at']),
                        operation_id=runtime['capture']['operation_id'], finding_id=runtime['capture']['finding_id'],
                        destination=runtime['capture']['destination'])
                else:
                    require(len(captured) == 1 and captured[0]['entry']['kind'] == 'FINDING' and
                        captured[0]['entry']['finding_id'] == runtime['capture']['finding_id'], 'Persisted capture identity differs')
                permit.check(snapshot)
            config['officers'] = runtimes
            config_file = attempt / 'connection-config.json'; write(config_file, config)
            connection = C.Connection(config_file); connection.check(selected)
            from app.access.research_app import configured
            store, _ = configured(app_root / 'workspace-config.json')
            # Administrative events contain IDs/counts only, never plaintext source rows.
            logs = store.accountability; require(logs is not None, 'Accountability unavailable')
            request_id = str(uuid4())
            def event(outcome, reason):
                logs.append(dict(request_id=request_id, action='DATASET_CONNECTION', phase='ADMINISTRATION', method='OPERATOR',
                    actor=dict(principal_kind='SIGNING_KEY', key_id=OWNER_ID), requested_officer_uid=None,
                    finding_id=None, operation_id=None, subject_user_id=None, peer_reference=None,
                    status=None, outcome=outcome, reason=reason))
            event('ATTEMPT', 'GENERATED_RECORD_SCOPED_IMPORT')
            with store.access.transaction() as database:
                existing = database.execute('SELECT version FROM directory WHERE id=1').fetchone()
                generation = existing[0] + 1 if existing else 1
            directory = D._from_loaded_snapshot(snapshot, membership_envelope, connection.access_keys, generation=generation)
            from app.access.policy import RETAINED_DIRECTORY_POLICY
            directory.update(policy=RETAINED_DIRECTORY_POLICY, expires_at=None, record_origin='GENERATED_RESEARCH_RECORDS')
            directory_envelope = signed(access_signer, ACCESS_ID, directory)
            packets, disclosures = [], []
            members = {entry['officer_uid']: entry for entry in directory['officers']}
            progress('SIGNED_PRESENTATIONS_AND_DISCLOSURES')
            for officer in selected:
                with store.transaction() as database:
                    ident = store.index('OFFICER', officer)
                    existing = database.execute('SELECT version FROM presentations WHERE id=?', (ident,)).fetchone()
                    packet_generation = existing[0] + 1 if existing else 1
                draft = connection._presentation(snapshot, officer, packet_generation)
                draft.update(policy=P.RETAINED_POLICY, expires_at=None, record_origin='GENERATED_RESEARCH_RECORDS', full_records=P.full_records(snapshot, officer))
                packets.append(signed(presentation_signer, PRESENTATION_ID, draft))
                issued = int(time.time())
                for user in accounts:
                    if user['active'] and permitted(user, members[officer]):
                        # Explicit generated ordinary-disclosure simulation only.
                        grant = dict(**P.disclosure_lifetime(user,issued,approval['expires_at']), kind='DISCLOSURE', issued_at=issued,
                            user_id=user['user_id'], account_version=user['version'], officer_uid=officer,
                            source_public_sha256=C.PUBLIC_SHA, assignment='ORDINARY', classification='ORDINARY',
                            restricted_clearance=False,
                            request_reviews=bool(review_permissions and user['user_id'] in review_permissions),
                            reviewer_uid=user['user_id'] if review_permissions and user['user_id'] in review_permissions else None)
                        disclosures.append(signed(presentation_signer, PRESENTATION_ID, grant))
            write(attempt / 'directory.json', directory_envelope)
            for index, envelope in enumerate(packets): write(attempt / ('presentation-' + str(index) + '.json'), envelope)
            for index, envelope in enumerate(disclosures): write(attempt / ('disclosure-' + str(index) + '.json'), envelope)
            write(attempt / 'import.json', dict(policy=C.POLICY, directory=str(attempt/'directory.json'),
                presentations=[str(attempt/('presentation-'+str(index)+'.json')) for index in range(len(packets))],
                disclosures=[str(attempt/('disclosure-'+str(index)+'.json')) for index in range(len(disclosures))]))
            if review_policy is not None:
                require(C.file_digest(review_policy, repo, C.CONFIG_MAX_BYTES) == review_policy_pin and
                    C.file_digest(policy_settings, repo, C.CONFIG_MAX_BYTES) == policy_settings_pin, 'Review request policy changed')
            progress('VALIDATED_SCOPED_CACHE_IMPORT')
            try: result = connection._install_loaded(snapshot, directory_envelope, packets, disclosures)
            except BaseException:
                event('FAILED', 'IMPORT_INCOMPLETE_PRESERVE_EXACT_ATTEMPT'); raise
            event('ALLOWED', 'SIGNED_GENERATED_RECORD_UI_CACHE_IMPORTED')
            summary = dict(**result, record_origin='GENERATED_RESEARCH_RECORDS', scope_basis='EXPLICIT_SIMULATION',
                all_officer_details_connected=len(selected)==len(officers), connected_detail_officers=len(selected),
                detail_copy_expires_at=None, display_lifecycle='RETAINED_LAST_VERIFIED_SNAPSHOT',
                directory_expires_at=directory['expires_at'], original_source_replay=True,
                independently_administered_witnesses=False, findings_chain_anchored=False,
                simulation_disclosures='ORDINARY_REQUESTS_ENABLED' if review_permissions else 'ORDINARY_READ_ONLY', code_revision=revision,
                blockchain_submission=False, import_manifest=str(attempt/'import.json'))
            write(attempt / 'RESULT.json', summary)
            # Publish usable config only after a validated import; retain every earlier attempt.
            write(root / 'connection-config.json', config, replace=(root/'connection-config.json').exists())
            return summary
