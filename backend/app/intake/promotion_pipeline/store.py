"""Dedicated encrypted intake journal. Existing research stores are never edited."""
from contextlib import contextmanager
from copy import deepcopy
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.store import private
from .core import canonical, check, digest, opaque

SCHEMA = '''
CREATE TABLE batches(id TEXT PRIMARY KEY, file_key TEXT UNIQUE NOT NULL, value BLOB NOT NULL);
CREATE TABLE phases(batch TEXT NOT NULL REFERENCES batches(id), phase TEXT NOT NULL, value BLOB NOT NULL,
 PRIMARY KEY(batch,phase));
CREATE TABLE reserved_sources(id TEXT PRIMARY KEY, batch TEXT NOT NULL REFERENCES batches(id), fingerprint TEXT NOT NULL);
CREATE TABLE baseline(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
CREATE TABLE baseline_meta(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
CREATE TABLE operations(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, batch TEXT NOT NULL REFERENCES batches(id));
CREATE TABLE worker_events(seq INTEGER PRIMARY KEY, batch TEXT NOT NULL REFERENCES batches(id), value BLOB NOT NULL);
CREATE TABLE worker_audit(seq INTEGER PRIMARY KEY REFERENCES worker_events(seq), log_sequence INTEGER NOT NULL);
CREATE TABLE authorizations(batch TEXT NOT NULL REFERENCES batches(id), version INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY(batch,version));
CREATE TABLE officer_batches(officer TEXT NOT NULL, batch TEXT NOT NULL REFERENCES batches(id), PRIMARY KEY(officer,batch));
'''
PHASES = ('QUEUED','DOCUMENTS_PREPARED','SQL_STORED','MONGO_STORED','STORAGE_VERIFIED',
          'CHAINS_VERIFIED','VISIBLE')

class IntakeStore:
    def __init__(self, root, key_file, backup_file, *, repo, create=False):
        self.root = private(root, directory=True, repo=repo)
        self.key = private(key_file, repo=repo).read_bytes()
        backup = private(backup_file, repo=repo)
        check(Path(key_file).resolve() != backup.resolve(), 'SEPARATE_BACKUP_REQUIRED')
        check(len(self.key) == 32 and self.key == backup.read_bytes(), 'RECOVERY_KEY_DIFFERS')
        self.aead = AESGCM(self.key)
        self.repo = repo
        self.path = self.root / 'promotion-intake.sqlite3'
        if create and not self.path.exists():
            with self.path.open('xb') as f:
                os.fchmod(f.fileno(), 0o600)
            with sqlite3.connect(self.path) as c:
                c.executescript(SCHEMA)
                for table in ('batches','phases','reserved_sources','operations','baseline','baseline_meta','worker_events','worker_audit','authorizations','officer_batches'):
                    for op in ('UPDATE','DELETE'):
                        c.execute(f"CREATE TRIGGER no_{table}_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END")
                c.execute('PRAGMA user_version=2')
        private(self.path, repo=repo)
        self.lock_path = self.root / 'worker.lock'
        if create and not self.lock_path.exists():
            with self.lock_path.open('xb') as f: os.fchmod(f.fileno(), 0o600)
        private(self.lock_path, repo=repo)
        with self.transaction() as c:
            check(c.execute('PRAGMA user_version').fetchone()[0] == 2, 'INTAKE_SCHEMA_DIFFERS')

    @contextmanager
    def transaction(self):
        private(self.path, repo=self.repo)
        with sqlite3.connect(self.path, timeout=10) as c:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('PRAGMA synchronous=FULL')
            c.execute('BEGIN IMMEDIATE')
            yield c

    @contextmanager
    def worker_lock(self):
        private(self.lock_path, repo=self.repo)
        with self.lock_path.open('r+b') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try: yield
            finally: fcntl.flock(f, fcntl.LOCK_UN)

    def seal(self, kind, identity, value):
        nonce = secrets.token_bytes(12)
        return nonce + self.aead.encrypt(nonce, canonical(value), canonical(['PROMOTION_INTAKE_STORE_V1',kind,identity]))

    def open(self, kind, identity, blob):
        return json.loads(self.aead.decrypt(blob[:12], blob[12:], canonical(['PROMOTION_INTAKE_STORE_V1',kind,identity])))

    def phase(self, batch, phase, value=None):
        check(phase in PHASES, 'PHASE_INVALID')
        with self.transaction() as c:
            row = c.execute('SELECT value FROM phases WHERE batch=? AND phase=?',(batch,phase)).fetchone()
            if row:
                old = self.open('PHASE',[batch,phase],row[0])
                if value is not None: check(old == value, 'PHASE_CONFLICT')
                return old
            if value is not None:
                check(phase != 'QUEUED', 'QUEUE_REQUIRES_RESERVATION')
                preceding = PHASES[PHASES.index(phase)-1]
                check(c.execute('SELECT 1 FROM phases WHERE batch=? AND phase=?',(batch,preceding)).fetchone(), 'PHASE_OUT_OF_ORDER')
                c.execute('INSERT INTO phases VALUES(?,?,?)',(batch,phase,self.seal('PHASE',[batch,phase],value)))
                return deepcopy(value)
        return None

    def verify_baseline(self, expected_pin):
        with self.transaction() as c:
            meta=c.execute('SELECT value FROM baseline_meta WHERE id=1').fetchone()
            check(meta is not None,'BASELINE_INDEX_REQUIRED')
            value=self.open('BASELINE',1,meta[0])
            rows=dict(c.execute('SELECT id,fingerprint FROM baseline'))
            check(value['source_set_sha256']==expected_pin and value['promotions']==len(rows) and
                value['index_sha256']==digest(rows),'BASELINE_INDEX_CHANGED')
        return value

    def duplicate(self, source_id, officer, source):
        ident = opaque(self.key,'SOURCE_ID',source_id)
        fingerprint = opaque(self.key,'SOURCE_ROW',[officer,source])
        with self.transaction() as c:
            row = c.execute('SELECT fingerprint FROM baseline WHERE id=?',(ident,)).fetchone()
            if row is None: row = c.execute('SELECT fingerprint FROM reserved_sources WHERE id=?',(ident,)).fetchone()
        return 'ABSENT' if row is None else 'IDENTICAL' if row[0] == fingerprint else 'CONFLICT'

    def create(self, data, batch, operation):
        file_key = opaque(self.key,'FILE',hashlib.sha256(data).hexdigest())
        fingerprint = opaque(self.key,'OPERATION',[batch['actor']['user_id'],file_key,batch['source_reference']])
        operation_key = opaque(self.key,'OPERATION_ID',operation)
        with self.transaction() as c:
            op = c.execute('SELECT fingerprint,batch FROM operations WHERE id=?',(operation_key,)).fetchone()
            if op:
                check(op[0] == fingerprint, 'OPERATION_CONFLICT')
                return self._batch(c, op[1])
            row = c.execute('SELECT id FROM batches WHERE file_key=?',(file_key,)).fetchone()
            if row:
                retained = self._batch(c,row[0])
                check(retained['actor']['user_id'] == batch['actor']['user_id'], 'FILE_ALREADY_REGISTERED')
                check(retained['source_reference']==batch['source_reference'],'RETAINED_FILE_SOURCE_REFERENCE_DIFFERS')
                c.execute('INSERT INTO operations VALUES(?,?,?)',(operation_key,fingerprint,row[0]))
                return retained
            check(c.execute('SELECT COUNT(*) FROM batches').fetchone()[0] < 1000, 'INTAKE_CAPACITY_REACHED')
            batch = deepcopy(batch)
            batch['batch_id'] = str(uuid4())
            batch['file_sha256'] = hashlib.sha256(data).hexdigest()
            batch['original_base64'] = base64.b64encode(data).decode()
            blob=self.seal('BATCH',batch['batch_id'],batch)
            check(c.execute('SELECT COALESCE(SUM(length(value)),0) FROM batches').fetchone()[0]+len(blob)<=64*1024*1024,'INTAKE_STORAGE_QUOTA_REACHED')
            c.execute('INSERT INTO batches VALUES(?,?,?)',(batch['batch_id'],file_key,blob))
            c.execute('INSERT INTO operations VALUES(?,?,?)',(operation_key,fingerprint,batch['batch_id']))
            return batch

    def _batch(self,c,ident):
        row = c.execute('SELECT value FROM batches WHERE id=?',(ident,)).fetchone()
        check(row is not None, 'BATCH_NOT_FOUND')
        batch = self.open('BATCH',ident,row[0])
        check(batch['batch_id'] == ident and hashlib.sha256(base64.b64decode(batch['original_base64'],validate=True)).hexdigest() == batch['file_sha256'], 'BATCH_BINDING_DIFFERS')
        return batch

    def get(self, ident):
        with self.transaction() as c: return self._batch(c,ident)

    def queue(self, ident, approved):
        with self.transaction() as c:
            batch = self._batch(c,ident)
            prior = c.execute('SELECT value FROM phases WHERE batch=? AND phase=?',(ident,'QUEUED')).fetchone()
            if prior:
                check(self.open('PHASE',[ident,'QUEUED'],prior[0]) == approved, 'COMMIT_CONFLICT')
                return
            check(not any(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']), 'ROWS_REQUIRE_REVIEW')
            rows = [r for r in batch['rows'] if r['status'] == 'READY']
            check(rows, 'NO_NEW_ROWS')
            for r in rows:
                key = opaque(self.key,'SOURCE_ID',r['source']['promotion_id'].strip())
                check(c.execute('SELECT 1 FROM reserved_sources WHERE id=?',(key,)).fetchone() is None, 'SOURCE_RESERVED_AFTER_PREVIEW_REVIEW_REQUIRED')
                c.execute('INSERT INTO reserved_sources VALUES(?,?,?)',(key,ident,opaque(self.key,'SOURCE_ROW',[r['officer_uid'],r['source']])))
            for officer in sorted({r['officer_uid'] for r in rows}):c.execute('INSERT INTO officer_batches VALUES(?,?)',(opaque(self.key,'OFFICER_INDEX',officer),ident))
            c.execute('INSERT INTO phases VALUES(?,?,?)',(ident,'QUEUED',self.seal('PHASE',[ident,'QUEUED'],approved)))

    def current_authorization(self,batch_id):
        with self.transaction() as c:
            row=c.execute('SELECT version,value FROM authorizations WHERE batch=? ORDER BY version DESC LIMIT 1',(batch_id,)).fetchone()
            if row:return self.open('AUTHORIZATION',[batch_id,row[0]],row[1])
            return self._batch(c,batch_id)['actor']

    def renew_authorization(self,batch_id,actor):
        with self.transaction() as c:
            batch=self._batch(c,batch_id)
            check(c.execute("SELECT 1 FROM phases WHERE batch=? AND phase='QUEUED'",(batch_id,)).fetchone(),'IMPORT_NOT_COMMITTED')
            check(actor['user_id']==batch['actor']['user_id'] and actor['account_version']>=batch['actor']['account_version'],'UPLOADER_IDENTITY_DIFFERS')
            row=c.execute('SELECT version,value FROM authorizations WHERE batch=? ORDER BY version DESC LIMIT 1',(batch_id,)).fetchone()
            if row:
                check(actor['account_version']>=row[0],'AUTHORIZATION_VERSION_ROLLBACK')
                if actor['account_version']==row[0]:
                    check(self.open('AUTHORIZATION',[batch_id,row[0]],row[1])==actor,'AUTHORIZATION_CONFLICT');return
            c.execute('INSERT INTO authorizations VALUES(?,?,?)',(batch_id,actor['account_version'],self.seal('AUTHORIZATION',[batch_id,actor['account_version']],actor)))

    def record_worker_status(self,batch,status):
        from datetime import datetime,timezone
        check(set(status)=={'status','phase'} and type(status['status']) is str and len(status['status'])<=100,'WORKER_STATUS_INVALID')
        with self.transaction() as c:
            row=c.execute('SELECT seq,value FROM worker_events WHERE batch=? ORDER BY seq DESC LIMIT 1',(batch,)).fetchone()
            if row:
                existing=self.open('WORKER_EVENT',[batch,row[0]],row[1])
                if existing['state']==status:return row[0],existing
            seq=c.execute('SELECT COALESCE(MAX(seq),0)+1 FROM worker_events').fetchone()[0]
            value={'state':status,'recorded_at':datetime.now(timezone.utc).isoformat()}
            c.execute('INSERT INTO worker_events VALUES(?,?,?)',(seq,batch,self.seal('WORKER_EVENT',[batch,seq],value)))
            return seq,value

    def worker_status(self,batch):
        with self.transaction() as c:
            row=c.execute('SELECT seq,value FROM worker_events WHERE batch=? ORDER BY seq DESC LIMIT 1',(batch,)).fetchone()
            return None if row is None else self.open('WORKER_EVENT',[batch,row[0]],row[1])

    def pending_worker_audits(self):
        with self.transaction() as c:
            return [(seq,batch,self.open('WORKER_EVENT',[batch,seq],value)) for seq,batch,value in c.execute('SELECT seq,batch,value FROM worker_events WHERE seq NOT IN (SELECT seq FROM worker_audit) ORDER BY seq LIMIT 100')]

    def acknowledge_worker_audit(self,seq,log_sequence):
        with self.transaction() as c:
            prior=c.execute('SELECT log_sequence FROM worker_audit WHERE seq=?',(seq,)).fetchone()
            if prior:check(prior[0]==log_sequence,'WORKER_AUDIT_ACK_DIFFERS')
            else:c.execute('INSERT INTO worker_audit VALUES(?,?)',(seq,log_sequence))

    def pending(self):
        with self.transaction() as c:
            return [r[0] for r in c.execute("SELECT batch FROM phases WHERE phase='QUEUED' AND batch NOT IN (SELECT batch FROM phases WHERE phase='VISIBLE') ORDER BY rowid LIMIT 20")]

    def batches(self,limit=20):
        check(type(limit) is int and 1<=limit<=1000,'BATCH_LIST_LIMIT_INVALID')
        with self.transaction() as c:
            return [self._batch(c,r[0]) for r in c.execute('SELECT id FROM batches ORDER BY rowid DESC LIMIT ?',(limit,))]

    def officer_batches(self,officer):
        with self.transaction() as c:
            ids=c.execute("SELECT b.id FROM batches b JOIN officer_batches o ON o.batch=b.id JOIN phases p ON p.batch=b.id AND p.phase='VISIBLE' WHERE o.officer=? ORDER BY b.rowid DESC",(opaque(self.key,'OFFICER_INDEX',officer),)).fetchall()
            return [self._batch(c,ident) for ident, in ids]
