"""Prepare the isolated multi-dataset intake. Commands never reset or edit original data.

initialize: private keys/passwords and the verified-archive baseline index only.
storage:    explicit additive PostgreSQL/MongoDB destinations for uploaded evidence.
wallet / network / public-*: dedicated Sepolia writer, pinned RPC config and contract.
configure:  verify destination receipts and prepare runtime, analysis and approval settings.
enable / disable: stop-server-only, backed-up workspace configuration update.
verify-batch / retry-retained: fresh read-only reconciliation or an exact retained retry.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.access.research_app import configured
from app.access.policy import account
from app.access.store import private
from app.intake.promotion_pipeline.chain_worker import write_private
from app.intake.dataset_pipeline.core import check
from app.intake.dataset_pipeline.store import DatasetStore
from app.intake.dataset_pipeline.configuration import source_pins
from app.intake.dataset_pipeline import provision_storage as D
from app.intake.dataset_pipeline.acceptance import POLICY as APPROVAL_POLICY
from app.intake.dataset_pipeline.analysis import POLICY as ANALYSIS_POLICY
import manage_promotion_pipeline as M

GATEWAY_POLICY = 'PERSONNEL_INTAKE_AUTHENTICATED_GATEWAY_V2'
NETWORK_POLICY = 'PERSONNEL_INTAKE_LIVE_SEPOLIA_NETWORK_V1'
CHAINCODE = 'personnel-intake-anchor-v1'


def read(file, repo):
    return json.loads(private(file, repo=repo).read_bytes())


def sha(file, repo):
    return hashlib.sha256(private(file, repo=repo).read_bytes()).hexdigest()


def directory_of(workspace):
    with workspace.access.transaction() as c:
        return workspace.access._directory(c)


def copy_secret(source, target):
    if not target.exists():
        with target.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(source)
            f.flush()
            os.fsync(f.fileno())
    check(private(target).read_bytes() == source, 'BACKUP_KEY_DIFFERS')


def user_id(workspace, username, role):
    found = []
    with workspace.access.transaction() as c:
        for ident, version, blob in c.execute('SELECT id,version,value FROM users'):
            value = workspace.access.open('USER', ident, version, blob)
            envelope = value.get('account', value.get('grant'))
            if envelope['payload'].get('username') != username:
                continue
            u = account(envelope, workspace.access.keys, now=workspace.clock())
            if u['active'] and u['role'] == role and u['scope_type'] == 'ALL':
                found.append(u['user_id'])
    check(len(found) == 1, 'EXPLICIT_ACTIVE_' + role + '_REQUIRED')
    return found[0]


def initialize(args, workspace, origin):
    M.ensure_stopped(origin)
    check(getattr(workspace, 'accountability', None) is not None, 'DATASET_ACCOUNTABILITY_REQUIRED')
    root, backup = args.state_root, args.backup_root
    for p in (root, backup):
        if not p.exists():
            p.mkdir(mode=0o700)
        private(p, directory=True, repo=args.repository)
    check(not root.is_relative_to(backup) and not backup.is_relative_to(root), 'SEPARATE_BACKUP_ROOT_REQUIRED')
    key = M.new_secret(root / 'intake.key')
    import hmac
    promotion = Path(args.promotion_root) / 'intake.key'
    check(key != workspace.access.key_path.read_bytes() and key != workspace.accountability.key and
          hmac.digest(key, b'RESEARCH_UI_INDEX_V1', 'sha256') != workspace.index_key and
          (not promotion.exists() or private(promotion).read_bytes() != key), 'SEPARATE_INTAKE_KEY_REQUIRED')
    copy_secret(key, backup / 'intake.key')
    recovery = M.new_secret(root / 'chain-recovery.key')
    check(recovery != key, 'CHAIN_RECOVERY_KEY_MUST_DIFFER')
    copy_secret(recovery, backup / 'chain-recovery.key')
    for name in ('chain-jobs', 'mongo-setup', 'analysis-v1', 'approval-v1'):
        p = root / name
        if not p.exists():
            p.mkdir(mode=0o700)
        private(p, directory=True, repo=args.repository)
    for name in ('postgres', 'mongo'):
        file = root / (name + '-writer.json')
        if not file.exists():
            write_private(file, {'username': D.USER, 'password': secrets.token_urlsafe(36)})
        c = read(file, args.repository)
        check(set(c) == {'username', 'password'} and c['username'] == D.USER and len(c['password']) >= 32,
              'WRITER_CREDENTIALS_DIFFER')
    importer = user_id(workspace, args.importer, 'HQ_ADMIN')
    reviewer = user_id(workspace, args.reviewer, 'IGP')
    check(importer != reviewer, 'INDEPENDENT_REVIEWER_REQUIRED')
    store = DatasetStore(root, root / 'intake.key', backup / 'intake.key', repo=args.repository,
                         create=not (root / DatasetStore.FILENAME).exists())
    directory = directory_of(workspace)
    from app.intake.dataset_pipeline.baseline import build
    receipt = json.loads(private(args.archive_receipt).read_bytes())
    print('Indexing the verified original archive…', flush=True)
    value, entries, references, report = build(store, args.archive, receipt, directory)
    try:
        installed = store.verify_baseline(value['source_set_sha256'])
    except Exception:
        installed = store.install_baseline(value, entries, references)
    check(installed == value, 'BASELINE_ALREADY_DIFFERS')
    write_private(root / 'setup.json', {'policy': 'PERSONNEL_INTAKE_PRIVATE_SETUP_V1', 'importer_ids': [importer],
        'reviewer_ids': [reviewer], 'baseline_source_set_sha256': value['source_set_sha256'],
        'source_public_sha256': directory['source_public_sha256'], 'state_root': str(root), 'backup_root': str(backup),
        'archive_sha256': report['archive_sha256']})
    return {'status': 'PERSONNEL_INTAKE_PRIVATE_STATE_PREPARED', 'original_identities_indexed': value['rows'],
            'ambiguous_original_identities': report['ambiguous_identities'], 'original_rows': report['original_rows'],
            'worker_enabled': False, 'chain_submitted': False}


def storage(args, workspace, origin):
    M.ensure_stopped(origin)
    root = args.state_root
    plan = read(root / 'setup.json', args.repository)
    check(plan['source_public_sha256'] == directory_of(workspace)['source_public_sha256'], 'BASELINE_CHANGED')
    pg, mg = read(root / 'postgres-writer.json', args.repository), read(root / 'mongo-writer.json', args.repository)
    import psycopg
    from app.storage.mongo_connection import load_credentials, client
    root_password, _ = load_credentials(args.mongo_bootstrap)
    with psycopg.connect(host='127.0.0.1', port=5432, dbname='police_identity', user=args.postgres_admin, connect_timeout=5) as connection:
        with connection.cursor() as c:
            c.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='personnel_intake'),"
                      "EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)", (D.USER,))
            schema, role = c.fetchone()
        check(schema == role, 'SQL_SETUP_PARTIAL_REQUIRES_INSPECTION')
        started = root / 'POSTGRES_SETUP_ATTEMPT.json'
        if schema:
            check(started.exists(), 'SQL_DESTINATION_NOT_CREATED_BY_THIS_SETUP')
        write_private(started, {'policy': 'PERSONNEL_INTAKE_POSTGRES_SETUP_V1', 'user': D.USER, 'database': 'police_identity',
                                'schema': 'personnel_intake', 'credential_sha256': sha(root / 'postgres-writer.json', args.repository)})
        D.postgres(connection, pg['password'], existing=schema)
    with psycopg.connect(host='127.0.0.1', port=5432, dbname='police_identity', user=D.USER, password=pg['password'],
                         connect_timeout=5) as writer:
        with writer.cursor() as c:
            c.execute('SELECT record_id FROM personnel_intake.evidence LIMIT 0')
    from pymongo import MongoClient

    def authenticate(password):
        with MongoClient('127.0.0.1', 27018, username=D.USER, password=password, authSource=D.DATABASE,
                         serverSelectionTimeoutMS=5000, connectTimeoutMS=5000, socketTimeoutMS=10000, retryWrites=False) as w:
            list(w[D.DATABASE][D.COLLECTION].find({}, limit=1))
    with client(root_password, bootstrap=True) as bootstrap:
        D.mongo(bootstrap[D.DATABASE], mg['password'], root / 'mongo-setup', authenticate=authenticate)
    result = {'policy': 'PERSONNEL_INTAKE_STORAGE_SETUP_V1', 'status': 'PASSED',
              'postgres_credential_sha256': sha(root / 'postgres-writer.json', args.repository),
              'mongo_credential_sha256': sha(root / 'mongo-writer.json', args.repository),
              'schema': 'personnel_intake', 'mongo_database': D.DATABASE, 'collection': D.COLLECTION}
    write_private(root / 'STORAGE_READY.json', result)
    return {'status': 'PERSONNEL_INTAKE_STORAGE_VERIFIED', 'original_records_changed': False, 'chain_submitted': False}


def wallet(args, workspace, origin):
    M.ensure_stopped(origin)
    import subprocess
    program = ("const W=require(process.argv[1]);W.initialize(process.argv[2],process.argv[3]).then(x=>console.log(JSON.stringify(x)))"
               ".catch(()=>{console.error('WALLET_SETUP_STOPPED');process.exitCode=1;});")
    result = subprocess.run(['node', '-e', program, str(args.repository / 'blockchain/public/sepolia-wallet.js'),
                             str(args.wallet_root), str(args.wallet_backup)], capture_output=True, timeout=120)
    check(result.returncode == 0, 'INTAKE_WALLET_SETUP_STOPPED')
    value = json.loads(result.stdout)
    check(value['status'] == 'PASSED' and value['chain_id'] == 11155111, 'INTAKE_WALLET_SETUP_DIFFERS')
    return {'status': 'DEDICATED_INTAKE_WALLET_PREPARED', 'address': value['address'], 'chain_submitted': False,
            'next': 'Fund this new address with Sepolia test ETH before deployment.'}


def network(args, workspace, origin):
    """Reuse the existing two-provider RPC configuration under the dedicated intake policy."""
    M.ensure_stopped(origin)
    private(args.state_root, directory=True, repo=args.repository)
    check(args.network_file.parent == args.state_root, 'INTAKE_NETWORK_LOCATION_DIFFERS')
    value = read(args.existing_network, args.repository)
    check(value['policy'] in ('PROMOTIONS_LIVE_SEPOLIA_NETWORK_V1', 'FINDINGS_LIVE_SEPOLIA_NETWORK_V1'), 'EXISTING_NETWORK_POLICY_DIFFERS')
    write_private(args.network_file, {**value, 'policy': NETWORK_POLICY})
    return {'status': 'PRIVATE_INTAKE_NETWORK_PREPARED', 'sha256': sha(args.network_file, args.repository), 'chain_submitted': False}


def public_operation(args, workspace, origin):
    M.ensure_stopped(origin)
    import subprocess
    mode = {'public-preview': '--preview', 'public-deploy': '--execute', 'public-reconcile': '--reconcile'}[args.command]
    command = ['node', str(args.repository / 'blockchain/public/intake/deploy-live.js'), '--network-file', str(args.network_file),
               '--network-sha256', sha(args.network_file, args.repository), '--wallet-root', str(args.wallet_root),
               '--backup-wallet-root', str(args.wallet_backup), '--journal-root', str(args.state_root / 'deployment'), mode]
    result = subprocess.run(command, cwd=args.repository, capture_output=True, timeout=600)
    check(result.returncode == 0, 'INTAKE_DEPLOYMENT_STOPPED_PRESERVE_JOURNAL')
    value = json.loads(result.stdout)
    check(value.get('scope') == 'DEDICATED_EMPTY_PERSONNEL_INTAKE_CONTRACT', 'DEPLOYMENT_SCOPE_DIFFERS')
    return value


def configure(args, workspace, origin):
    M.ensure_stopped(origin)
    root = args.state_root
    plan = read(root / 'setup.json', args.repository)
    check(plan['source_public_sha256'] == directory_of(workspace)['source_public_sha256'], 'BASELINE_CHANGED')
    ready = read(root / 'STORAGE_READY.json', args.repository)
    check(ready['status'] == 'PASSED' and ready['postgres_credential_sha256'] == sha(root / 'postgres-writer.json', args.repository) and
          ready['mongo_credential_sha256'] == sha(root / 'mongo-writer.json', args.repository), 'STORAGE_SETUP_REQUIRED')
    gateway = read(args.fabric_gateway, args.repository)
    check(gateway['policy'] == GATEWAY_POLICY and gateway['destination']['chaincode'] == CHAINCODE, 'DEDICATED_INTAKE_GATEWAY_REQUIRED')
    receipt = read(args.fabric_gateway.parent / 'PASSED.json', args.repository)
    check(receipt['status'] == 'INTAKE_FABRIC_GATEWAY_VERIFIED' and receipt['configuration_sha256'] == sha(args.fabric_gateway, args.repository),
          'VERIFIED_INTAKE_GATEWAY_REQUIRED')
    deployment = read(root / 'deployment/PASSED.json', args.repository)
    check(deployment['policy'] == 'SEPOLIA_PERSONNEL_INTAKE_CONTRACT_DEPLOYMENT_V1' and deployment['status'] == 'PASSED' and
          deployment['finalized'] is True and deployment['two_rpc_readback'] is True, 'FINALIZED_INTAKE_DEPLOYMENT_REQUIRED')
    info = read(args.wallet_root / 'wallet-info.json', args.repository)
    check(info['address'].lower() == deployment['writer'].lower(), 'INTAKE_WRITER_DIFFERS')
    for other in (args.existing_wallet, args.promotion_wallet):
        if (other / 'wallet-info.json').exists():
            # A dedicated writer prevents nonce races with other publishers.
            check(read(other / 'wallet-info.json', args.repository)['address'].lower() != info['address'].lower(), 'DEDICATED_INTAKE_WALLET_REQUIRED')
    check(sha(args.network_file, args.repository) == deployment['config_sha256'] and
          read(args.network_file, args.repository)['policy'] == NETWORK_POLICY, 'INTAKE_NETWORK_PIN_DIFFERS')
    destination = {'chain_id': 11155111, 'contract': deployment['contract_address'].lower(),
                   'runtime_sha256': deployment['artifact']['runtime_sha256'], 'writer': deployment['writer'].lower(),
                   'namespace': CHAINCODE, 'finality': 'FINALIZED'}
    chains = {'fabric_config': str(args.fabric_gateway), 'fabric_sha256': sha(args.fabric_gateway, args.repository),
              'network_config': str(args.network_file), 'network_sha256': sha(args.network_file, args.repository),
              'destination': destination, 'wallet_root': str(args.wallet_root), 'wallet_backup': str(args.wallet_backup),
              'recovery_key': str(root / 'chain-recovery.key')}
    runtime_file, analysis_file, approval_file = root / 'runtime.json', root / 'analysis-config.json', root / 'approval-config.json'
    write_private(approval_file, {'policy': APPROVAL_POLICY, 'decision_root': str(root / 'approval-v1'),
                                  'reviewer_ids': plan['reviewer_ids'], 'legacy_queued': {}})
    write_private(analysis_file, {'policy': ANALYSIS_POLICY, 'intake_config': str(runtime_file), 'analysis_root': str(root / 'analysis-v1')})
    write_private(runtime_file, {'policy': 'PERSONNEL_INTAKE_RUNTIME_V1', 'state_root': str(root),
        'key_file': str(root / 'intake.key'), 'backup_key_file': str(args.backup_root / 'intake.key'),
        'importer_ids': plan['importer_ids'], 'baseline_source_set_sha256': plan['baseline_source_set_sha256'],
        'source_public_sha256': plan['source_public_sha256'], 'postgres_credentials': str(root / 'postgres-writer.json'),
        'mongo_credentials': str(root / 'mongo-writer.json'), 'chains': chains, 'source_pins': source_pins(args.repository),
        'analysis_config': str(analysis_file), 'approval_config': str(approval_file)})
    # Create the empty append-only journals once, with the runtime key.
    from app.intake.dataset_pipeline.analysis import DatasetAnalysis
    from app.intake.dataset_pipeline.acceptance import DatasetApprovals
    analysis = DatasetAnalysis(workspace, analysis_file, create=True)
    DatasetApprovals(workspace, analysis, approval_file, create=True)
    return {'status': 'PERSONNEL_INTAKE_RUNTIME_CONFIG_PREPARED', 'file': str(runtime_file), 'worker_enabled': False, 'chain_submitted': False}


def refresh_pins(args, workspace, origin):
    """Re-pin reviewed, committed source after an upgrade; only source_pins changes."""
    M.ensure_stopped(origin)
    import subprocess
    check(not subprocess.check_output(['git', '-C', str(args.repository), 'status', '--porcelain'], text=True).strip(),
          'COMMIT_SOURCE_BEFORE_PINNING')
    revision = subprocess.check_output(['git', '-C', str(args.repository), 'rev-parse', 'HEAD'], text=True).strip()
    file = args.state_root / 'runtime.json'
    raw = private(file, repo=args.repository).read_bytes()
    config = json.loads(raw)
    check(config['policy'] == 'PERSONNEL_INTAKE_RUNTIME_V1', 'INTAKE_RUNTIME_REQUIRED')
    pins = source_pins(args.repository)
    if config['source_pins'] == pins:
        return {'status': 'SOURCE_PINS_ALREADY_CURRENT', 'revision': revision}
    backup = args.state_root / ('runtime-before-repin-' + revision[:12] + '.json')
    if backup.exists():
        check(private(backup).read_bytes() == raw, 'RUNTIME_BACKUP_DIFFERS')
    else:
        with backup.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    temp = file.parent / ('runtime-repin-' + secrets.token_hex(8) + '.tmp')
    try:
        write_private(temp, {**config, 'source_pins': pins})
        check(private(file).read_bytes() == raw, 'RUNTIME_CONFIG_CHANGED')
        os.replace(temp, file)
    finally:
        if temp.exists():
            temp.unlink()
    return {'status': 'SOURCE_PINS_REFRESHED', 'revision': revision, 'files_pinned': len(pins), 'backup': str(backup),
            'restart_required': True, 'chain_submitted': False}


def export_registrations(args, workspace, origin):
    """Seal independently accepted new-officer rows for the offline, operator-signed registration step.

    The web tier never signs identities. This manifest is the only hand-off: every row is
    re-verified against its stored ciphertext, both-chain receipt and retained acceptance.
    """
    M.ensure_stopped(origin)
    from app.access.research_service import ResearchService
    from app.intake.dataset_pipeline.analysis import verified_batch
    from app.intake.dataset_pipeline.core import digest
    workspace.personnel_intake_config = str(args.state_root / 'runtime.json')
    research = ResearchService(workspace)
    approvals = research.dataset_acceptance
    check(approvals is not None, 'DATASET_APPROVALS_NOT_CONFIGURED')
    approvals.guard()
    approvals.synchronize(limit=1000)
    rows = []
    for batch, row, head in approvals.accepted_rows('OFFICER_REGISTRATION'):
        publication = verified_batch(approvals.intake, batch)
        check(head['result']['publication'] == publication and head['result']['effect'] == 'REGISTRATION', 'REGISTRATION_BINDING_DIFFERS')
        rows.append({'batch_id': batch['batch_id'], 'source_row': row['row'], 'source_system': batch['source_system'],
                     'source': row['source'], 'acceptance_reference': digest(head), 'review_reference': head['result'].get('review_reference'),
                     'publication_id': publication['publication_id'], 'fabric_transaction_id': publication['fabric_transaction_id'],
                     'public_transaction_id': publication['public_transaction_id']})
    if not rows:
        return {'status': 'NO_ACCEPTED_REGISTRATIONS', 'chain_submitted': False}
    manifest = {'policy': 'PERSONNEL_INTAKE_REGISTRATION_MANIFEST_V1', 'rows': rows,
                'source_public_sha256': directory_of(workspace)['source_public_sha256']}
    ident = digest(manifest)
    target = args.state_root / 'registrations'
    if not target.exists():
        target.mkdir(mode=0o700)
    private(target, directory=True, repo=args.repository)
    file = target / ('registration-manifest-' + ident[:16] + '.sealed')
    if not file.exists():
        with file.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(approvals.intake.seal('REGISTRATION_MANIFEST', ident, manifest))
            f.flush()
            os.fsync(f.fileno())
    check(approvals.intake.open('REGISTRATION_MANIFEST', ident, private(file).read_bytes()) == manifest, 'MANIFEST_READBACK_DIFFERS')
    return {'status': 'REGISTRATION_MANIFEST_SEALED', 'file': str(file), 'manifest_sha256': ident, 'officers': len(rows),
            'directory_changed': False, 'chain_submitted': False,
            'next': 'Apply with the operator registration step while PostgreSQL and the signing keys are available.'}


def export_original_commitments(args, workspace, origin):
    """Install each officer's ORIGINAL anchored commitment and Merkle proof into the intake store (one time).

    Uses the protected commitment artifact and both key copies inside this tool only; no key
    material is printed or stored. Every officer's entry is checked against the published
    payload digest, and the recomputed tree root must equal the root anchored on Fabric and Sepolia.
    """
    M.ensure_stopped(origin)
    from app.identity.bind_evidence_destinations import private_path
    from app.identity.evidence_bundle_v2 import open_artifact
    from app.identity.generate_protected_commitments import load_keys
    from app.identity.protected_commitment import digest as commitment_digest, encoded
    from app.identity.public_anchor_authorization import PUBLIC_SHA
    from app.identity.register_profiles import private_key_file, verify_recovery
    from app.intake.dataset_pipeline import merkle_proof as MP
    evidence = Path.home() / 'ResearchEvidence/police-personnel-integrity/protected-commitment-attempts'
    attempt = sorted(evidence.iterdir())[-1] if args.commitment_attempt is None else args.commitment_attempt
    secrets_dir = args.repository / 'backend/.secrets'
    crypto = private_key_file(private_path(secrets_dir / 'identity-keys.json'))
    backup = private_key_file(private_path(base_keys() / 'identity-keys-initial.json'))
    verify_recovery(crypto, backup)
    public = json.loads(private_path(attempt / 'public-commitments.json').read_text())
    check(commitment_digest(public) == PUBLIC_SHA, 'EXACT_ORIGINAL_PUBLICATION_REQUIRED')
    envelope = json.loads(private_path(attempt / 'commitments.encrypted.json').read_text())
    saved = open_artifact(crypto, envelope, envelope['binding'])
    check(open_artifact(backup, envelope, envelope['binding']) == saved and saved['public'] == public, 'COMMITMENT_RECOVERY_DIFFERS')
    nodes = [MP.leaf_node(encoded(dict(kind='OFFICER', **r))) for r in public['officers']]
    batch_leaf = dict(kind='BATCH', publication_id=public['batch_publication_id'], commitment=public['batch_commitment'])
    nodes.append(MP.leaf_node(encoded(batch_leaf)))
    check(MP.root(nodes) == public['merkle_root'], 'RECOMPUTED_ROOT_DIFFERS_FROM_ANCHORED_ROOT')
    position = {r['publication_id']: i for i, r in enumerate(public['officers'])}
    by_handle = {r['publication_id']: r for r in public['officers']}
    entries = {}
    for item in saved['officers']:
        record = by_handle[item['publication_id']]
        check(record['commitment'] == item['commitment'], 'OFFICER_COMMITMENT_DIFFERS')
        i = position[item['publication_id']]
        entries[item['officer_uid']] = {'publication_id': record['publication_id'], 'commitment': record['commitment'], 'leaf_index': i,
            'leaf_sha256': nodes[i].hex(), 'proof': MP.proof(nodes, i)}
    check(len(entries) == len(public['officers']) == 6596 and len({e['publication_id'] for e in entries.values()}) == 6596, 'OFFICER_INDEX_INCOMPLETE')
    known = {o['officer_uid'] for o in directory_of(workspace)['officers']}
    check(set(entries) == known, 'DIRECTORY_AND_COMMITMENT_OFFICERS_DIFFER')
    # Public anchoring facts recorded when the original batch was verified on both chains (2026-10-09 checkpoint).
    meta = {'policy': public['policy'], 'key_version': public['key_version'], 'merkle_root': public['merkle_root'],
            'batch_publication_id': public['batch_publication_id'], 'batch_commitment': public['batch_commitment'],
            'public_payload_sha256': PUBLIC_SHA, 'officers': len(entries), 'leaves': len(nodes),
            'sepolia_contract': '0x4Ae794040d9794cd3b50BB06Fd41eE540c2435a6', 'sepolia_chain_id': 11155111,
            'sepolia_sealing_block': '0xb52fdb', 'sepolia_sealing_block_hash': '0xb211ead1932bc3a4d083e215e81521750f3a4c23c596ffc5d4c693be861275db',
            'fabric_channel': 'personnel', 'fabric_chaincode': 'officer-evidence-v1', 'verified_on': '2026-10-09',
            'verification_basis': 'FABRIC_68_TRANSACTIONS_AND_SEPOLIA_68_TRANSACTIONS_EXACT_READBACK'}
    store = DatasetStore(args.state_root, args.state_root / 'intake.key', args.backup_root / 'intake.key', repo=args.repository)
    try:
        store.install_original_commitments(meta, entries)
        status = 'ORIGINAL_COMMITMENTS_INSTALLED'
    except Exception as error:
        check(getattr(error, 'code', '') == 'ORIGINAL_COMMITMENTS_ALREADY_INSTALLED', 'ORIGINAL_COMMITMENT_INSTALL_FAILED')
        status = 'ORIGINAL_COMMITMENTS_ALREADY_INSTALLED'
    sample = next(iter(entries))
    got = store.original_commitment(sample)
    check(got is not None and got[0] == entries[sample] and got[1] == meta, 'INSTALLED_COMMITMENT_READBACK_DIFFERS')
    return {'status': status, 'officers': len(entries), 'recomputed_root_matches_anchored_root': True,
            'merkle_root': meta['merkle_root'], 'keys_printed': False, 'chain_submitted': False}


def base_keys():
    return Path.home() / 'ResearchKeys/police-personnel-integrity'


def edit_workspace(args, change, label):
    file = private(args.workspace_config, repo=args.repository)
    raw = file.read_bytes()
    config = json.loads(raw)
    result = change(config)
    if result is not None:
        return result
    backup = args.state_root / ('workspace-before-' + label + '-' + hashlib.sha256(raw).hexdigest()[:16] + '.json')
    if backup.exists():
        check(private(backup).read_bytes() == raw, 'WORKSPACE_BACKUP_DIFFERS')
    else:
        with backup.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    temp = file.parent / ('intake-' + label + '-' + secrets.token_hex(8) + '.tmp')
    try:
        write_private(temp, config)
        check(private(file).read_bytes() == raw, 'WORKSPACE_CONFIG_CHANGED')
        os.replace(temp, file)
        fd = os.open(file.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()


def enable(args, workspace, origin):
    M.ensure_stopped(origin)
    target = str(args.state_root / 'runtime.json')
    from app.intake.dataset_pipeline.runtime import Runtime
    from app.access.research_service import ResearchService
    workspace.personnel_intake_config = target
    runtime = Runtime(workspace, ResearchService(workspace), Path(target))
    try:
        from sqlalchemy import text
        with runtime.engine.connect() as c:
            c.execute(text('SELECT record_id FROM personnel_intake.evidence LIMIT 0'))
        runtime.mongo[D.DATABASE].command('ping')
    finally:
        runtime.engine.dispose()
        runtime.mongo.close()

    def change(config):
        if config.get('personnel_intake_config') == target:
            return {'status': 'PERSONNEL_INTAKE_ALREADY_ENABLED', 'restart_required': True}
        check('personnel_intake_config' not in config, 'OTHER_INTAKE_RUNTIME_ALREADY_CONFIGURED')
        config['personnel_intake_config'] = target
    return edit_workspace(args, change, 'enable') or {'status': 'PERSONNEL_INTAKE_ENABLED', 'restart_required': True,
                                                      'original_records_changed': False, 'chain_submitted': False}


def disable(args, workspace, origin):
    M.ensure_stopped(origin)

    def change(config):
        if 'personnel_intake_config' not in config:
            return {'status': 'PERSONNEL_INTAKE_ALREADY_DISABLED'}
        check(config['personnel_intake_config'] == str(args.state_root / 'runtime.json'), 'OTHER_INTAKE_RUNTIME_CONFIGURED')
        del config['personnel_intake_config']
    return edit_workspace(args, change, 'disable') or {'status': 'PERSONNEL_INTAKE_DISABLED', 'restart_required': True,
        'all_retained_uploads_and_chain_journals_preserved': True, 'chain_submitted': False}


def verify_batch(args, workspace, origin):
    M.ensure_stopped(origin)
    check(args.batch_id is not None, 'BATCH_REFERENCE_REQUIRED')
    from app.intake.dataset_pipeline.runtime import Runtime
    from app.access.research_service import ResearchService
    from app.intake.promotion_pipeline.delivery import reconcile
    workspace.personnel_intake_config = str(args.state_root / 'runtime.json')
    runtime = Runtime(workspace, ResearchService(workspace), args.state_root / 'runtime.json')
    try:
        with runtime.store.worker_lock():
            batch = runtime.store.get(args.batch_id)
            prepared = runtime.store.phase(args.batch_id, 'DOCUMENTS_PREPARED')
            check(prepared is not None, 'NO_ORIGINAL_DELIVERY_TO_VERIFY')

            def boundary():
                runtime.check_pins()
                runtime.service.source_state()
                reconcile(runtime.store, batch, prepared['documents'], runtime.sql, runtime.documents)
            boundary()
            payload, _ = runtime.store.publication(batch)
            mode = 'RECONCILE'
            if args.command == 'retry-retained':
                check(args.chain in ('fabric', 'public'), 'EXPLICIT_RETRY_CHAIN_REQUIRED')
                runtime.authorize(batch)
                mode = 'RETRY_' + args.chain.upper()
                original = boundary

                def boundary():
                    runtime.authorize(batch)
                    original()
            result = runtime.chains(batch, payload, boundary, mode=mode)
            return {'status': result['status'], 'batch_id': args.batch_id, 'dataset': batch['dataset'], 'fresh_chain_reads': True,
                    'transactions_submitted': 0 if mode == 'RECONCILE' else None,
                    'operator_exact_retry_requested': args.command == 'retry-retained', 'replacement_transaction_created': False,
                    'publication_id': payload['publication_id'], 'merkle_root': payload['merkle_root'],
                    'public_contract': runtime.config['chains']['destination']['contract'],
                    'fabric_transaction_id': result.get('fabric', {}).get('transaction_id'),
                    'public_transaction_id': (result.get('public') or {}).get('transaction_id')}
    finally:
        runtime.engine.dispose()
        runtime.mongo.close()


def main():
    home = Path.home()
    base = home / 'ResearchKeys/police-personnel-integrity'
    data = home / 'ResearchData/police-personnel-integrity/verified/BATCH-RAW-001'
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['initialize', 'storage', 'wallet', 'network', 'public-preview', 'public-deploy',
                                       'public-reconcile', 'configure', 'enable', 'disable', 'verify-batch', 'retry-retained', 'refresh-pins', 'export-registrations', 'export-original-commitments'])
    p.add_argument('--repository', type=Path, default=home / 'Developer/police-personnel-integrity')
    p.add_argument('--workspace-config', type=Path, default=base / 'research-app-v1/workspace-config.json')
    p.add_argument('--state-root', type=Path, default=base / 'application-intake-v1')
    p.add_argument('--backup-root', type=Path, default=base / 'application-intake-v1-backup')
    p.add_argument('--promotion-root', type=Path, default=base / 'application-promotions-v1')
    p.add_argument('--archive', type=Path, default=data / 'Step_1_Controlled_Data_Intake_Batch.zip')
    p.add_argument('--archive-receipt', type=Path,
                   default=data / 'receipts/registration-32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2.json')
    p.add_argument('--importer', default='research.hq')
    p.add_argument('--reviewer', default='research.igp')
    p.add_argument('--mongo-bootstrap', type=Path, default=base / 'mongo-v1')
    p.add_argument('--postgres-admin', default=getpass.getuser())
    p.add_argument('--fabric-gateway', type=Path, default=base / 'application-intake-v1/fabric-gateway-setup/intake-gateway.json')
    p.add_argument('--network-file', type=Path, default=base / 'application-intake-v1/intake-network.json')
    p.add_argument('--existing-network', type=Path, default=base / 'application-promotions-v1/promotions-network.json')
    p.add_argument('--wallet-root', type=Path, default=base / 'intake-sepolia-v1')
    p.add_argument('--wallet-backup', type=Path, default=base / 'intake-sepolia-v1-backup')
    p.add_argument('--existing-wallet', type=Path, default=base / 'sepolia-v1')
    p.add_argument('--promotion-wallet', type=Path, default=base / 'promotions-sepolia-v1')
    p.add_argument('--commitment-attempt', type=Path, default=None)
    p.add_argument('--batch-id')
    p.add_argument('--chain', choices=['fabric', 'public'])
    a = p.parse_args()
    os.umask(0o077)
    for value in vars(a).values():
        if isinstance(value, Path):
            check(value.is_absolute() and '..' not in value.parts, 'ABSOLUTE_SETUP_PATH_REQUIRED')
    workspace, origin = configured(a.workspace_config)
    check(workspace.repo == a.repository, 'WORKSPACE_REPOSITORY_DIFFERS')
    handler = (public_operation if a.command.startswith('public-') else
               verify_batch if a.command in ('verify-batch', 'retry-retained') else
               refresh_pins if a.command == 'refresh-pins' else
               export_registrations if a.command == 'export-registrations' else
               export_original_commitments if a.command == 'export-original-commitments' else globals()[a.command])
    print(json.dumps(handler(a, workspace, origin), indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'STOPPED', 'error_type': type(error).__name__,
                          'reason': getattr(error, 'code', 'SETUP_INCOMPLETE_RETAIN_PRIVATE_STATE'),
                          'automatic_redeployment': False, 'transaction_outcome': 'CHECK_RETAINED_JOURNALS_BEFORE_RETRY'}))
        raise SystemExit(1)
