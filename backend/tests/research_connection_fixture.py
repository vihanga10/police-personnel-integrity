"""Disposable real crypto, private stores and mTLS; original batch replay substituted.

No original records, operational credentials, real custody authorization or live
RPC/finality. Only load_verified_snapshot and its fixture publication pin differ.
"""
import base64
from copy import deepcopy
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from app.access import research_connection as C, research_connection_runtime as R
from app.access.policy import POLICY, encoded
from app.access.store import AccessStore
from app.access.research_store import ResearchStore
from app.identity import audit_gate as A, recording_tip_witness as W, witness_secure_transport as T
from app.identity.evidence_bundle_v2 import open_artifact
from app.identity.protected_commitment import digest, KEY_POLICY
from app.security.identity_crypto import IdentityCrypto
from test_observed_recording_journal import setup, baseline, OFFICER
from test_protected_recording_review import verified, keys
from test_recording_checkpoint_registry import build_registry
from test_witness_secure_transport import certs, listener
from scoped_access_fixture import grant, identifier, PASSWORD


def write(path, value):
    path = Path(path)
    path.write_bytes(value if type(value) is bytes else encoded(value)); path.chmod(0o600)
    return path


def public(key): return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
def pins(mapping): return {k: base64.b64encode(v).decode() for k, v in mapping.items()}
def signed(key, key_id, payload):
    return dict(key_id=key_id, payload=deepcopy(payload), signature=base64.b64encode(key.sign(encoded(payload))).decode())
def seed(key): return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def connected(setup, tmp_path, monkeypatch):
    s = setup; repo = s['repo']
    def git(*args): return subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()
    git('init', '-b', 'feat/identity-resolution'); git('config', 'user.name', 'Connection Fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    (repo / 'source.py').write_text('# Disposable test revision only.\n'); git('add', '.'); git('commit', '-m', 'Fixture source')
    rev = git('rev-parse', 'HEAD'); snapshot = s['snapshot']; monkeypatch.setattr(C, 'PUBLIC_SHA', digest(snapshot['public']))
    source = {}
    for field in C.SOURCE_FIELDS:
        if field.endswith('_attempt'):
            p = tmp_path / ('fixture-' + field.removesuffix('_attempt').replace('_', '-')); p.mkdir(mode=0o700)
        else: p = tmp_path / (field + '.json')
        source[field] = str(p)
    write(source['key_file'], json.loads((tmp_path / 'primary.json').read_text()))
    write(source['backup_key_file'], json.loads((tmp_path / 'backup.json').read_text()))
    commitment_keys = dict(policy=KEY_POLICY, version='commit-v1', content_key=base64.b64encode(os.urandom(32)).decode(), publication_key=base64.b64encode(os.urandom(32)).decode())
    write(source['commitment_key_file'], commitment_keys); write(source['backup_commitment_key_file'], commitment_keys)
    binding = write(Path(source['binding_attempt']) / 'destination-bindings.encrypted.json', {'fixture': 'bound-original-destination'})
    context = dict(code_revision=rev, bundle_attempt_id=Path(source['bundle_attempt']).name,
        binding_attempt_id=Path(source['binding_attempt']).name, commitment_attempt_id=Path(source['commitment_attempt']).name,
        binding_artifact_sha256=hashlib.sha256(binding.read_bytes()).hexdigest())
    permit = open_artifact(s['crypto'], snapshot['envelope'], A.binding(snapshot['context']))
    permit['context'] = context; snapshot['context'] = context
    snapshot['envelope'] = A.seal_permit(s['crypto'], s['backup'], permit)
    write(Path(source['audit_gate_attempt']) / 'audit-permit.encrypted.json', snapshot['envelope'])
    write(Path(source['commitment_attempt']) / 'public-commitments.json', snapshot['public'])
    raw = 'f' * 64
    snapshot['manifest'] = {'bundles': [{'officer_uid': OFFICER}]}
    snapshot['catalog'][raw] = dict(raw_record_id=raw, filename='officer_personal_information.csv',
        delivery={'complete': True}, candidate_links=[dict(officer_uid=OFFICER, role='officer_nic_no', state='CANDIDATE_NOT_ACCEPTED')],
        original=dict(columns=['officer_nic_no', 'full_name', 'name_with_initials'], values=['000000001V', 'Reported Connection Name', 'R. Connection']))
    snapshot['bindings']['raw_bindings'][raw] = [{'fixture': 'original-profile-binding'}]
    s['clock'][0] -= timedelta(seconds=2)
    pin = baseline(s); registry, recovery, registry_args = build_registry(s, tmp_path, pin['journal_anchor'])
    root = tmp_path / 'witness'; root.mkdir(mode=0o700)
    witness_config = dict(active_encryption_key_version='enc', active_lookup_key_version='lookup',
        encryption_keys={'enc': base64.b64encode(os.urandom(32)).decode()}, lookup_keys={'lookup': base64.b64encode(os.urandom(32)).decode()})
    first = write(tmp_path / 'witness-primary.json', witness_config); second = write(tmp_path / 'witness-backup.json', witness_config)
    witness_key = Ed25519PrivateKey.generate()
    witness = W.DurableTipWitness(root=root, repo=repo, witness_id='connection-test-witness',
        registry_id=registry.registry_id, journal_anchor=registry.anchor, crypto=IdentityCrypto(first), backup=IdentityCrypto(second),
        signer=witness_key, key_id='witness', witness_keys={'witness': public(witness_key)}, writer_keys=registry.registry_keys)
    enrollment = witness.initialize()
    client_args = dict(witness_id=witness.scope['witness_id'], registry_id=registry.registry_id, journal_anchor=registry.anchor,
        signer=registry.signer, key_id=registry.key_id, writer_keys=registry.registry_keys, witness_keys={'witness': public(witness_key)})
    client = W.WitnessClient(**client_args, exchange=witness.exchange)
    W.WitnessedCheckpointRegistry(registry, client).register(checkpoint_file=pin['checkpoint_file'], checkpoint_sha256=pin['checkpoint_sha256'])
    pki = certs(tmp_path / 'pki', s['clock'][0]); control = tmp_path / 'control'; control.mkdir(mode=0o700)
    with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    profile = control / 'profile.json'
    profile_pin = T.provision(witness, profile_path=profile, endpoint=f'https://127.0.0.1:{port}' + T.PATH,
        ca_certificate=pki['ca'], server_certificate=pki['server'], server_key=pki['server_key'], client_certificates={'registry': pki['client']})
    runtime = dict(policy='RESEARCH_RECORDING_RUNTIME_V1', registry_root=str(registry.root), journal_root=str(s['root']),
        journal_anchor=registry.anchor, registry_id=registry.registry_id,
        registry_crypto={'primary': str(tmp_path / 'registry-primary.json'), 'backup': str(tmp_path / 'registry-backup.json')},
        journal_crypto={'primary': source['key_file'], 'backup': source['backup_key_file']},
        signing_key=str(write(control / 'registry.key', seed(registry.signer))), key_id=registry.key_id,
        registry_keys=pins(registry.registry_keys), recorder_keys=pins(registry.recorder_keys),
        observation_keys=pins(registry.observation_keys), recovery_keys=pins(registry.recovery_keys),
        witness=dict(witness_id=witness.scope['witness_id'], witness_keys=pins(client_args['witness_keys']), profile=str(profile),
            profile_sha256=profile_pin, ca_certificate=str(pki['ca']), client_certificate=str(pki['client']), client_key=str(pki['client_key'])))
    runtime_file = write(control / 'recording.json', runtime)
    admin = Ed25519PrivateKey.generate(); custodian = Ed25519PrivateKey.generate()
    access_root = tmp_path / 'access'; access_root.mkdir(mode=0o700)
    workspace_root = tmp_path / 'workspace'; workspace_root.mkdir(mode=0o700)
    access_key = write(control / 'access.key', os.urandom(32)); workspace_key = write(control / 'workspace.key', os.urandom(32))
    access_config = write(control / 'access.json', dict(policy='SCOPED_ACCESS_CONFIG_V1', repository=str(repo),
        state_directory=str(access_root), key_file=str(access_key), authority_keys=pins({'test-admin': public(admin)}), origin='https://127.0.0.1:8443'))
    workspace_config = write(control / 'workspace.json', dict(policy='RESEARCH_WEB_CONFIG_V1', access_config=str(access_config),
        state_directory=str(workspace_root), key_file=str(workspace_key), presentation_keys=pins({'workspace-test': public(admin)})))
    access = AccessStore(access_root, access_key, {'test-admin': public(admin)}, repo=repo, create=True)
    access.put_account(grant(admin), PASSWORD)
    store = ResearchStore(workspace_root, workspace_key, {'workspace-test': public(admin)}, access=access, create=True)
    now = int(time.time())
    authorization = dict(policy=C.AUTH_POLICY, kind='DATA_USE', issued_at=now-1, expires_at=now+1800,
        source_public_sha256=C.PUBLIC_SHA, code_revision=rev, purpose='SCOPED_RESEARCH_UI', directory_all_officers=True,
        detail_officer_uids=[OFFICER], review_reference='TEST_ONLY_AUTHORIZATION', custodian_reference='TEST_ONLY_CUSTODIAN')
    authorization_file = write(control / 'authorization.json', signed(custodian, 'custodian', authorization))
    config = dict(policy=C.POLICY, repository=str(repo), source=source, access_config=str(access_config), workspace_config=str(workspace_config),
        data_authorization=str(authorization_file), authorization_keys=pins({'custodian': public(custodian)}),
        officers={OFFICER: {'recording_config': str(runtime_file), 'findings_config': None}})
    configfile = write(control / 'connection.json', config)
    membership = dict(policy=POLICY, kind='MEMBERSHIP', issued_at=now-1, expires_at=now+1200,
        source_public_sha256=C.PUBLIC_SHA, officers=[{'officer_uid': OFFICER, 'membership': {'PROVINCE': 'P1', 'DISTRICT': 'D1', 'DIVISION': 'V1', 'STATION': 'S1'}}],
        review_reference='TEST_ONLY_SCOPE_REVIEW')
    membership_file = write(control / 'membership.json', signed(admin, 'test-admin', membership))
    seen = []
    def full_loader(args, repository, revision):
        seen.append((args, repository, revision)); return snapshot
    import app.identity.algorithm_snapshot as S
    monkeypatch.setattr(S, 'load_verified_snapshot', full_loader)
    transport = dict(t={'server': witness}, port=port,
        server_args=dict(profile_path=profile, expected_profile_sha256=profile_pin, ca_certificate=pki['ca'], server_certificate=pki['server'], server_key=pki['server_key']))
    return dict(s=s, snapshot=snapshot, config=config, configfile=configfile, runtime=runtime, runtime_file=runtime_file,
        control=control, store=store, admin=admin, custodian=custodian, authorization=authorization,
        authorization_file=authorization_file, membership=membership_file, transport=transport, calls=seen,
        access_config=access_config, workspace_config=workspace_config, registry=registry, client=client)


def exported(t):
    with listener(t['transport']):
        return C.Connection(t['configfile']).export(t['membership'], generation=1, selections={OFFICER: 1})


def inputs(t, bundle=None):
    bundle = bundle or exported(t)
    directory = signed(t['admin'], 'test-admin', bundle['directory'])
    presentations = [signed(t['admin'], 'workspace-test', bundle['presentations'][OFFICER])]
    now = int(time.time())
    disclosure = dict(policy=P_POLICY(), kind='DISCLOSURE', issued_at=now-1, expires_at=now+600,
        user_id=identifier(100), account_version=1, officer_uid=OFFICER, source_public_sha256=C.PUBLIC_SHA,
        assignment='ORDINARY', classification='ORDINARY', restricted_clearance=False, request_reviews=False, reviewer_uid=None)
    return directory, presentations, [signed(t['admin'], 'workspace-test', disclosure)]


def P_POLICY():
    from app.access.research_policy import POLICY
    return POLICY
