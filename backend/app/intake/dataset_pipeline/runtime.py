"""Opt-in dataset intake runtime; absent configuration leaves the application unchanged.

The worker processes one approved batch at a time through the same resumable,
append-only phases as promotions: prepared ciphertext, PostgreSQL and MongoDB
exact readback, Fabric then Sepolia publication, then visibility to analysis.
"""
import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from app.access.store import private
from app.access.policy import account
from app.intake.promotion_pipeline.chain_worker import ChainWorker
from app.intake.promotion_pipeline.delivery import PostgresDestination, MongoDestination, process
from app.intake.promotion_pipeline.store import PHASES
from .core import check, IntakeError
from .service import DatasetService
from .store import DatasetStore

SQL_TABLE = 'personnel_intake.evidence'
MONGO_DATABASE = 'police_personnel_intake'
COLLECTION = 'upload_events'
WRITER = 'police_intake_writer'
FIELDS = {'policy', 'state_root', 'key_file', 'backup_key_file', 'importer_ids', 'baseline_source_set_sha256',
          'source_public_sha256', 'postgres_credentials', 'mongo_credentials', 'chains', 'source_pins',
          'analysis_config', 'approval_config'}


class IntakeChainWorker(ChainWorker):
    POLICY = 'APPLICATION_PERSONNEL_INTAKE_CHAIN_JOB_V1'
    SCRIPT = 'blockchain/public/intake/application-anchor-worker.js'


class Runtime:
    def __init__(self, workspace, research, file):
        self.workspace, self.research = workspace, research
        self.file = private(file, repo=workspace.repo)
        self.raw = self.file.read_bytes()
        config = json.loads(self.raw)
        check(set(config) == FIELDS and config['policy'] == 'PERSONNEL_INTAKE_RUNTIME_V1', 'INTAKE_CONFIG_FIELDS_DIFFER')
        check(type(config['importer_ids']) is list and 0 < len(config['importer_ids']) <= 5, 'INTAKE_CONFIG_INVALID')
        check(type(config['source_pins']) is dict and bool(config['source_pins']), 'SOURCE_PINS_REQUIRED')
        from .configuration import source_files
        check(set(config['source_pins']) == set(source_files(workspace.repo)), 'SOURCE_PIN_COVERAGE_DIFFERS')
        check(getattr(research, 'dataset_acceptance', None) is not None, 'IGP_APPROVAL_SETUP_REQUIRED')
        self.config = config
        self.store = DatasetStore(config['state_root'], config['key_file'], config['backup_key_file'], repo=workspace.repo)
        # Separate keys: intake evidence, accountability, access and workspace never share material.
        check(self.store.key != workspace.access.key_path.read_bytes() and self.store.key != workspace.accountability.key,
              'SEPARATE_INTAKE_KEY_REQUIRED')
        check(hmac.digest(self.store.key, b'RESEARCH_UI_INDEX_V1', 'sha256') != workspace.index_key,
              'SEPARATE_WORKSPACE_KEY_REQUIRED')
        promotion = getattr(getattr(research, 'promotion_analysis', None), 'intake', None)
        check(promotion is None or promotion.key != self.store.key, 'SEPARATE_DATASET_INTAKE_KEY_REQUIRED')
        self.service = DatasetService(research, self.store, config)
        self.errors, self.stop = {}, False
        self.check_pins()
        self.service.source_state()
        from sqlalchemy import create_engine, URL
        pg = json.loads(private(config['postgres_credentials'], repo=workspace.repo).read_text())
        check(set(pg) == {'username', 'password'} and pg['username'] == WRITER and len(pg['password']) >= 32,
              'SQL_WRITER_CONFIG_INVALID')
        self.engine = create_engine(URL.create('postgresql+psycopg', username=pg['username'], password=pg['password'],
            host='127.0.0.1', port=5432, database='police_identity'), connect_args={'connect_timeout': 5},
            pool_size=1, max_overflow=0, pool_pre_ping=True)
        mg = json.loads(private(config['mongo_credentials'], repo=workspace.repo).read_text())
        check(set(mg) == {'username', 'password'} and mg['username'] == WRITER and len(mg['password']) >= 32,
              'MONGO_WRITER_CONFIG_INVALID')
        from pymongo import MongoClient
        self.mongo = MongoClient('127.0.0.1', 27018, username=mg['username'], password=mg['password'],
            authSource=MONGO_DATABASE, retryWrites=False, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000,
            socketTimeoutMS=10000)
        self.sql = PostgresDestination(self.engine, SQL_TABLE)
        self.documents = MongoDestination(self.mongo[MONGO_DATABASE][COLLECTION], COLLECTION)
        jobs = self.store.root / 'chain-jobs'
        private(jobs, directory=True, repo=workspace.repo)
        self.chains = IntakeChainWorker(config['chains'], jobs, workspace.repo)

    def check_pins(self):
        check(private(self.file).read_bytes() == self.raw, 'INTAKE_CONFIG_CHANGED')
        for relative, expected in self.config['source_pins'].items():
            p = Path(relative)
            check(not p.is_absolute() and '..' not in p.parts and p.parts[0] in {'backend', 'blockchain'}, 'SOURCE_PIN_INVALID')
            check(hashlib.sha256((Path(self.workspace.repo) / p).read_bytes()).hexdigest() == expected, 'INTAKE_SOURCE_CHANGED')

    def authorize(self, batch):
        """Before every phase: unchanged sources, live IGP approval and live importer scope."""
        check(not self.stop, 'WORKER_STOPPING')
        self.check_pins()
        directory = self.service.source_state()
        self.service.approvals.processing_allowed(batch)
        access = self.workspace.access
        with access.transaction() as c:
            found = []
            for ident, version, blob in c.execute('SELECT id,version,value FROM users'):
                value = access.open('USER', ident, version, blob)
                envelope = value['account'] if 'account' in value else value.get('grant')
                if envelope and envelope['payload']['user_id'] == batch['actor']['user_id']:
                    found.append(envelope)
        check(len(found) == 1, 'IMPORTER_ACCOUNT_UNAVAILABLE')
        u = account(found[0], access.keys, now=access.clock())
        check(u['active'] and u['role'] == 'HQ_ADMIN' and u['scope_type'] == 'ALL' and
              u['user_id'] in self.config['importer_ids'] and
              u['version'] == self.store.current_authorization(batch['batch_id'])['account_version'],
              'IMPORTER_AUTHORIZATION_CHANGED')
        from app.security.record_protection import (AssignmentProtection, RecordClassification, DisclosureCategory,
                                                    ProtectionLevel, required_protection)
        known = {o['officer_uid'] for o in directory['officers']}
        for officer in self.service.officers(batch):
            check(officer in known, 'IMPORT_OFFICER_NO_LONGER_CONNECTED')
            grant = self.workspace.get_grant(u['user_id'], officer)
            check(grant['account_version'] == u['version'] and grant['source_public_sha256'] == directory['source_public_sha256'],
                  'IMPORT_DETAIL_GRANT_CHANGED')
            decision = required_protection(assignment=AssignmentProtection(grant['assignment']),
                record_classification=RecordClassification(grant['classification']), category=DisclosureCategory.PERSONNEL_DETAILS)
            check(decision.level is not ProtectionLevel.WITHHOLD and
                  (decision.level is not ProtectionLevel.RESTRICTED or grant['restricted_clearance']), 'IMPORT_DETAIL_ACCESS_WITHHELD')

    def audit_worker_events(self):
        from app.access.accountability import ACTIONS
        ACTIONS.add('DATASET_PIPELINE_WORKER')
        for seq, batch_id, value in self.store.pending_worker_audits():
            batch = self.store.get(batch_id)
            a = batch['actor']
            log_seq = self.workspace.accountability.append({'action': 'DATASET_PIPELINE_WORKER', 'phase': 'ADMINISTRATION',
                'actor': {'user_id': a['user_id'], 'username': a['username'], 'role': 'HQ_ADMIN', 'scope_type': 'ALL',
                          'scope_id': None, 'account_version': a['account_version'], 'authenticated': False,
                          'authentication_state': 'BACKGROUND_WORKER_ON_RETAINED_IMPORT'},
                'outcome': 'ALLOWED' if value['state']['status'] in ('BOTH_CHAINS_VERIFIED', 'CHAIN_CONFIRMATION_PENDING') else 'FAILED',
                'reason': value['state']['status'], 'worker_phase': value['state']['phase'], 'operation_id': batch_id,
                'intake_dataset': batch['dataset'], 'worker_event_reference': str(seq), 'worker_recorded_at': value['recorded_at'],
                'request_id': None, 'requested_officer_uid': None, 'finding_id': None, 'method': 'WORKER', 'status': None,
                'session_reference': None, 'peer_reference': None})
            self.store.acknowledge_worker_audit(seq, log_seq)

    def tick(self):
        try:
            self.audit_worker_events()
        except Exception:
            return  # the preserved outbox retries before any new processing
        # Availability is recorded only now; never backdated to upload or effective dates.
        self.research.dataset_analysis.activate_visible()
        self.service.approvals.synchronize()
        for ident in self.store.pending():
            if self.stop:
                return
            try:
                result = process(self.store, ident, self.sql, self.documents, self.chains, self.authorize)
                self.errors.pop(ident, None)
                status = result['status']
            except BlockingIOError:
                return
            except Exception as error:
                status = error.code if isinstance(error, IntakeError) else 'PROCESSING_STOPPED_RETAINED_STATE_PRESERVED'
                self.errors[ident] = status
            phase = next((p for p in reversed(PHASES) if self.store.phase(ident, p) is not None), 'QUEUED')
            self.store.record_worker_status(ident, {'status': status, 'phase': phase})
            self.audit_worker_events()
            break  # serial batches avoid competing nonces in the dedicated wallet

    async def run(self):
        from starlette.concurrency import run_in_threadpool
        while not self.stop:
            try:
                await run_in_threadpool(self.tick)
            except Exception:
                self.worker_issue = 'WORKER_STOPPED_PENDING_RECONCILIATION'
            for _ in range(15):
                if self.stop:
                    return
                await asyncio.sleep(1)
