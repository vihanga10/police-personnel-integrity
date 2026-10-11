"""Separate encrypted presentation cache and append-only review REQUEST queue.

This queue is not a findings ledger, witness or chain outbox. It never submits
transactions or accepts a finding. Whole-store rollback requires external pins.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.policy import AccessError, encoded, require, uid
from app.access.store import private
from app.access import research_policy as P

SCHEMA = '''
CREATE TABLE presentations (id TEXT PRIMARY KEY, version INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE disclosures (id TEXT PRIMARY KEY, issued INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE requests (id TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL, value BLOB NOT NULL);
CREATE TABLE events (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, value BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TRIGGER no_request_update BEFORE UPDATE ON requests BEGIN SELECT RAISE(ABORT,'immutable request'); END;
CREATE TRIGGER no_request_delete BEFORE DELETE ON requests BEGIN SELECT RAISE(ABORT,'immutable request'); END;
CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
PRAGMA user_version=1;
'''

class ResearchStore:
    def __init__(self, root, key_file, keys, *, access, create=False):
        self.access = access; self.repo = access.repo; self.clock = access.clock
        self.root = private(root, directory=True, repo=self.repo)
        key = private(key_file, repo=self.repo).read_bytes()
        require(len(key) == 32 and key != access.key_path.read_bytes(), 'Separate presentation key required')
        require(not self.root.is_relative_to(access.root) and not access.root.is_relative_to(self.root), 'Separate access/presentation stores required')
        require(keys and all(type(v) is bytes and len(v) == 32 for v in keys.values()), 'Presentation authority pins required')
        self.keys = deepcopy(keys); self.aead = AESGCM(key); self.index_key = hmac.digest(key, b'RESEARCH_UI_INDEX_V1', 'sha256')
        self.path = self.root / 'workspace.sqlite3'; self.lock = threading.RLock()
        if create:
            with self.path.open('xb') as f: os.chmod(f.fileno(), 0o600)
            with sqlite3.connect(self.path) as c: c.executescript(SCHEMA)
        private(self.path, repo=self.repo)
        with self.transaction() as c:
            require(c.execute('PRAGMA user_version').fetchone()[0] == 1, 'Unknown workspace schema')
            self._events(c)

    def index(self, *items): return hmac.new(self.index_key, encoded(items), hashlib.sha256).hexdigest()
    def seal(self, kind, identity, value):
        nonce = secrets.token_bytes(12)
        return nonce + self.aead.encrypt(nonce, encoded(value), encoded(['RESEARCH_UI_STORE_V1', kind, identity]))
    def open(self, kind, identity, blob):
        return json.loads(self.aead.decrypt(blob[:12], blob[12:], encoded(['RESEARCH_UI_STORE_V1', kind, identity])))

    @contextmanager
    def transaction(self):
        with self.lock:
            private(self.path, repo=self.repo)
            with sqlite3.connect(self.path, timeout=5) as c:
                c.execute('PRAGMA synchronous=FULL'); c.execute('BEGIN IMMEDIATE')
                yield c

    def _events(self, c):
        previous = '0' * 64; result = []
        for sequence, prior, blob, digest in c.execute('SELECT seq,previous,value,digest FROM events ORDER BY seq'):
            require(sequence == len(result) + 1 and prior == previous and digest == self.index(sequence, prior, blob.hex()), 'Workspace event chain differs')
            result.append(self.open('EVENT', sequence, blob)); previous = digest
        return result

    def event(self, c, value):
        self._events(c)
        row = c.execute('SELECT seq,digest FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        sequence, previous = (row[0] + 1, row[1]) if row else (1, '0' * 64)
        blob = self.seal('EVENT', sequence, value)
        c.execute('INSERT INTO events VALUES(?,?,?,?)', (sequence, previous, blob, self.index(sequence, previous, blob.hex())))

    def import_packet(self, envelope):
        p = P.packet(envelope, self.keys, self.clock()); ident = self.index('OFFICER', p['officer_uid'])
        with self.transaction() as c:
            row = c.execute('SELECT version,value FROM presentations WHERE id=?', (ident,)).fetchone()
            if row and row[0] == p['generation'] and self.open('PACKET', ident, row[1]) == envelope: return
            require(row is None or p['generation'] > row[0], 'Presentation generation must advance')
            c.execute('INSERT OR REPLACE INTO presentations VALUES(?,?,?)', (ident, p['generation'], self.seal('PACKET', ident, envelope)))
            self.event(c, dict(kind='PRESENTATION_IMPORTED', officer_uid=p['officer_uid'], generation=p['generation']))

    def import_grant(self, envelope):
        p = P.grant(envelope, self.keys, self.clock()); ident = self.index('GRANT', p['user_id'], p['officer_uid'])
        with self.transaction() as c:
            row = c.execute('SELECT issued,value FROM disclosures WHERE id=?', (ident,)).fetchone()
            if row and row[0] == p['issued_at'] and self.open('GRANT', ident, row[1]) == envelope: return
            require(row is None or p['issued_at'] > row[0], 'Disclosure issuance must advance')
            c.execute('INSERT OR REPLACE INTO disclosures VALUES(?,?,?)', (ident, p['issued_at'], self.seal('GRANT', ident, envelope)))
            self.event(c, dict(kind='DISCLOSURE_IMPORTED', user_id=p['user_id'], officer_uid=p['officer_uid']))

    def get_packet(self, officer):
        ident = self.index('OFFICER', officer)
        with self.transaction() as c:
            row = c.execute('SELECT value FROM presentations WHERE id=?', (ident,)).fetchone()
            if row is None: raise AccessError(503, 'PRESENTATION_NOT_CONFIGURED')
            try: return P.packet(self.open('PACKET', ident, row[0]), self.keys, self.clock())
            except Exception: raise AccessError(503, 'PRESENTATION_EXPIRED_OR_INVALID') from None

    def get_grant(self, user, officer):
        ident = self.index('GRANT', user, officer)
        with self.transaction() as c:
            row = c.execute('SELECT value FROM disclosures WHERE id=?', (ident,)).fetchone()
            try:
                require(row is not None)
                return P.grant(self.open('GRANT', ident, row[0]), self.keys, self.clock())
            except Exception: raise AccessError(403, 'DETAILS_WITHHELD') from None

    def append_request(self, value):
        uid(value['operation_id']); ident = self.index('REQUEST', value['operation_id']); digest = P.fingerprint(value)
        with self.transaction() as c:
            row = c.execute('SELECT owner,digest,value FROM requests WHERE id=?', (ident,)).fetchone()
            if row:
                if row[0] != self.index('USER', value['user_id']) or row[1] != digest: raise AccessError(409, 'OPERATION_CONFLICT')
                return self.open('REQUEST', ident, row[2])
            require(c.execute('SELECT COUNT(*) FROM requests WHERE owner=?', (self.index('USER', value['user_id']),)).fetchone()[0] < 1000, 'Request queue limit reached')
            record = dict(request=value, request_sha256=digest, recorded_at=self.clock(), status='PENDING_AUTHORITY')
            c.execute('INSERT INTO requests VALUES(?,?,?,?)', (ident, self.index('USER', value['user_id']), digest, self.seal('REQUEST', ident, record)))
            self.event(c, dict(kind='REQUEST_RECORDED', operation_id=value['operation_id'], request_sha256=digest))
            return record

    def get_request(self, operation):
        ident = self.index('REQUEST', uid(operation))
        with self.transaction() as c:
            events = self._events(c)
            row = c.execute('SELECT value FROM requests WHERE id=?', (ident,)).fetchone()
            if row is None: raise AccessError(404, 'NOT_FOUND')
            result = self.open('REQUEST', ident, row[0])
            completions = [e for e in events if e.get('kind') == 'PROTECTED_RESULT' and e['operation_id'] == operation]
            require(len(completions) <= 1, 'Conflicting protected results')
            if completions:
                require(completions[0]['request_sha256'] == result['request_sha256'], 'Protected result request differs')
                result['status'] = completions[0]['status']
                result['result_sha256'] = completions[0]['result_sha256']
            return result

    def protected_result(self, operation, request_sha256, status, result_sha256):
        """Internal operator bridge only; no web route or administrative JSON import."""
        require(status in ('REVIEW_RECORDED', 'CORRECTION_RECORDED'), 'Protected result status differs')
        P.sha(request_sha256); P.sha(result_sha256)
        record = self.get_request(operation)
        require(record['request_sha256'] == request_sha256, 'Request binding differs')
        value = dict(kind='PROTECTED_RESULT', operation_id=operation, request_sha256=request_sha256,
                     status=status, result_sha256=result_sha256)
        with self.transaction() as c:
            previous = [e for e in self._events(c) if e.get('kind') == 'PROTECTED_RESULT' and e['operation_id'] == operation]
            if previous: require(previous == [value], 'Protected result cannot change'); return
            self.event(c, value)

    def recent_requests(self, user, officer, version, source_public_sha256):
        """Bounded current-actor recovery; no other officer's queue is returned."""
        with self.transaction() as c:
            self._events(c)
            records = [self.open('REQUEST', ident, blob) for ident,blob in c.execute(
                'SELECT id,value FROM requests WHERE owner=?', (self.index('USER',user),))]
        selected = [r for r in records if r['request']['officer_uid']==officer and
            r['request']['user_id']==user and r['request']['account_version']==version and
            r['request']['source_public_sha256']==source_public_sha256]
        selected.sort(key=lambda r:(r['recorded_at'],r['request']['operation_id']), reverse=True)
        return [self.get_request(r['request']['operation_id']) for r in selected[:20]]
