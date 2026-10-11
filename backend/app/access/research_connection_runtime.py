"""Private operator configuration of existing recording/findings read adapters.

No callback, fixture transport, service launch, recovery or write operation.
These builders connect to already provisioned journals and mTLS witnesses.
"""
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.access.policy import require
from app.access.store import private as _private
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity import recording_checkpoint_registry as R, recording_tip_witness as W
from app.identity.witness_secure_transport import HTTPSWitnessTransport


def private(path, *, directory=False, repo=None):
    require(isinstance(path, (str, Path)) and Path(path).is_absolute() and
            '..' not in Path(path).parts, 'Absolute non-traversing runtime paths required')
    return _private(path, directory=directory, repo=repo)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate configuration field')
        result[key] = value
    return result


def read_json(path, repo):
    file = private(path, repo=repo)
    require(file.stat().st_size <= 16 * 1024 * 1024, 'Bounded private JSON required')
    return json.loads(file.read_bytes(), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'Configuration fields differ')
    return value


def public_keys(value):
    require(type(value) is dict and value, 'Explicit public key pins required')
    keys = {}
    for name, wire in value.items():
        require(type(name) is str and name.strip() and type(wire) is str, 'Key pin differs')
        key = base64.b64decode(wire, validate=True)
        require(len(key) == 32 and key not in keys.values(), 'Distinct Ed25519 public keys required')
        keys[name] = key
    return keys


def signer(path, repo):
    seed = private(path, repo=repo).read_bytes()
    require(len(seed) == 32, 'Private raw Ed25519 seed required')
    return Ed25519PrivateKey.from_private_bytes(seed)


def crypto_pair(value, repo):
    fields(value, ('primary', 'backup'))
    first = private(value['primary'], repo=repo)
    second = private(value['backup'], repo=repo)
    require(first != second, 'Separate recovery key files required')
    crypto, backup = private_key_file(first), private_key_file(second)
    verify_recovery(crypto, backup)
    return crypto, backup


def witness(value, repo, *, signing_key, key_id, writer_keys, anchor, registry_id):
    fields(value, ('witness_id', 'witness_keys', 'profile', 'profile_sha256',
                  'ca_certificate', 'client_certificate', 'client_key'))
    keys = public_keys(value['witness_keys'])
    transport = HTTPSWitnessTransport(profile_path=private(value['profile'], repo=repo),
        expected_profile_sha256=value['profile_sha256'], witness_keys=keys, repo=repo,
        ca_certificate=value['ca_certificate'], client_certificate=value['client_certificate'],
        client_key=value['client_key'])
    return W.WitnessClient(witness_id=value['witness_id'], registry_id=registry_id,
        journal_anchor=anchor, signer=signing_key, key_id=key_id,
        writer_keys=writer_keys, witness_keys=keys, exchange=transport)


def recording(path, repo):
    value = fields(read_json(path, repo), ('policy', 'registry_root', 'journal_root',
        'journal_anchor', 'registry_id', 'registry_crypto', 'journal_crypto',
        'signing_key', 'key_id', 'registry_keys', 'recorder_keys', 'observation_keys',
        'recovery_keys', 'witness'))
    require(value['policy'] == 'RESEARCH_RECORDING_RUNTIME_V1', 'Recording runtime policy differs')
    crypto, backup = crypto_pair(value['registry_crypto'], repo)
    journal_crypto, journal_backup = crypto_pair(value['journal_crypto'], repo)
    signing_key = signer(value['signing_key'], repo)
    keys = public_keys(value['registry_keys'])
    registry = R.CheckpointRegistry(root=value['registry_root'], journal_root=value['journal_root'],
        repo=repo, journal_anchor=value['journal_anchor'], registry_id=value['registry_id'],
        crypto=crypto, backup=backup, journal_crypto=journal_crypto, journal_backup=journal_backup,
        signer=signing_key, key_id=value['key_id'], registry_keys=keys,
        recorder_keys=public_keys(value['recorder_keys']),
        observation_keys=public_keys(value['observation_keys']),
        recovery_keys=public_keys(value['recovery_keys']))
    client = witness(value['witness'], repo, signing_key=signing_key, key_id=value['key_id'],
                     writer_keys=keys, anchor=value['journal_anchor'], registry_id=value['registry_id'])
    return W.WitnessedCheckpointRegistry(registry, client)


def findings(path, repo, officer_uid):
    from app.identity.encrypted_findings_journal import FindingsJournal
    from app.identity.findings_tip_registry import FindingsTipRegistry
    from app.identity.findings_tip_witness import WitnessedFindingsRegistry, findings_scope_anchor
    value = fields(read_json(path, repo), ('policy', 'journal', 'registry'))
    require(value['policy'] == 'RESEARCH_FINDINGS_RUNTIME_V1', 'Findings runtime policy differs')
    j = fields(value['journal'], ('root', 'ledger_id', 'officer_uid', 'crypto', 'signing_key',
        'key_id', 'writer_keys', 'reviewer_keys', 'authority_keys', 'reviewer_identities', 'authority_scopes'))
    require(j['officer_uid'] == officer_uid, 'Findings officer differs')
    require(type(j['reviewer_identities']) is dict and type(j['authority_scopes']) is dict and
        all(type(k) is str and type(v) is list and all(type(x) is str for x in v)
            for k, v in j['authority_scopes'].items()), 'Explicit findings authority scope lists required')
    crypto, backup = crypto_pair(j['crypto'], repo)
    journal = FindingsJournal(root=j['root'], repo=repo, ledger_id=j['ledger_id'],
        officer_uid=officer_uid, crypto=crypto, backup=backup, signer=signer(j['signing_key'], repo),
        key_id=j['key_id'], writer_keys=public_keys(j['writer_keys']), reviewer_keys=public_keys(j['reviewer_keys']),
        authority_keys=public_keys(j['authority_keys']) if j['authority_keys'] else {},
        reviewer_identities=j['reviewer_identities'],
        authority_scopes={k: tuple(v) for k, v in j['authority_scopes'].items()})
    r = fields(value['registry'], ('root', 'registry_id', 'crypto', 'signing_key', 'key_id',
                                 'registry_keys', 'recovery_keys', 'witness'))
    crypto, backup = crypto_pair(r['crypto'], repo)
    signing_key = signer(r['signing_key'], repo); keys = public_keys(r['registry_keys'])
    registry = FindingsTipRegistry(root=r['root'], journal=journal, registry_id=r['registry_id'],
        crypto=crypto, backup=backup, signer=signing_key, key_id=r['key_id'],
        registry_keys=keys, recovery_keys=public_keys(r['recovery_keys']))
    anchor = findings_scope_anchor(r['registry_id'], j['ledger_id'])
    client = witness(r['witness'], repo, signing_key=signing_key, key_id=r['key_id'],
                     writer_keys=keys, anchor=anchor, registry_id=r['registry_id'])
    return WitnessedFindingsRegistry(registry, client)
