"""Private, separate SQLite auth store. Does not touch research SQL/Mongo/ledgers.

User grants and identity directory are authenticated and encrypted at rest. Web
sessions use a process-ephemeral key: restart or restored storage invalidates
all prior cookies. Run exactly one ASGI worker for this backend.
"""
import base64
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.access.policy import AccessError, account, encoded, name, permitted, projection, require, username
from app.access.directory import validate_directory
from app.identity.normalization import normalize_identifier

SCHEMA = '''
CREATE TABLE users (id TEXT PRIMARY KEY, owner TEXT NOT NULL UNIQUE, version INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE directory (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE throttle (id TEXT PRIMARY KEY, expires INTEGER NOT NULL, value BLOB NOT NULL);
CREATE TABLE audit (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, value BLOB NOT NULL, digest TEXT NOT NULL);
CREATE TRIGGER immutable_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER immutable_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
PRAGMA user_version=1;
'''


def private(path, *, directory=False, repo=None):
    p = Path(path).absolute()
    require(not any(x.is_symlink() for x in (p, *p.parents)), 'Symlink refused')
    p = p.resolve()
    if repo is not None: require(not p.is_relative_to(Path(repo).resolve()), 'Private state must be outside repository')
    s = p.stat()
    require(s.st_uid == os.getuid() and not s.st_mode & 0o077 and
            (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1),
            'Owner-only ordinary private path required')
    return p


def password_hash(password, *, salt=None):
    require(type(password) is str and 15 <= len(password) <= 128 and '\x00' not in password,
            'Password must contain 15 to 128 characters')
    salt = secrets.token_bytes(16) if salt is None else salt
    value = hashlib.scrypt(password.encode(), salt=salt, n=2**17, r=8, p=1,
                           maxmem=256*1024*1024, dklen=32)
    return {'salt': base64.b64encode(salt).decode(), 'hash': base64.b64encode(value).decode()}


def password_matches(password, record):
    try:
        result = password_hash(password, salt=base64.b64decode(record['salt'], validate=True))
        return hmac.compare_digest(result['hash'], record['hash'])
    except (ValueError, TypeError):
        # Comparable KDF work for rejected short/oversized credentials.
        password_hash('invalid-password-placeholder', salt=b'0'*16)
        return False


class AccessStore:
    def __init__(self, root, key_file, authority_keys, *, repo, create=False, clock=time.time):
        self.root = private(root, directory=True, repo=repo)
        self.key_path = private(key_file, repo=repo)
        key = self.key_path.read_bytes(); require(len(key) == 32, 'Dedicated raw 32-byte access key required')
        require(type(authority_keys) is dict and authority_keys and all(type(k) is str and k and
                type(v) is bytes and len(v) == 32 for k,v in authority_keys.items()), 'Pinned authority keys required')
        self.keys = deepcopy(authority_keys); self.aead = AESGCM(key)
        self.lookup_key = hmac.digest(key, b'ACCESS_INDEX_V1', 'sha256')
        self.boot_key = secrets.token_bytes(32); self.clock = clock
        self.path = self.root / 'access.sqlite3'; self.repo = Path(repo).resolve()
        self.lock = threading.RLock()
        if create:
            with self.path.open('xb') as f: os.chmod(f.fileno(), 0o600)
            with sqlite3.connect(self.path) as c: c.executescript(SCHEMA)
        private(self.path, repo=repo)
        with self.transaction() as c:
            require(c.execute('PRAGMA user_version').fetchone()[0] == 1, 'Unknown access schema')
            self._verify_audit(c)
            c.execute('DELETE FROM sessions')  # Explicit restart logout, only this access DB.
        self.dummy = password_hash(secrets.token_urlsafe(24))

    def index(self, kind, value):
        return hmac.new(self.lookup_key, encoded([kind,value]), hashlib.sha256).hexdigest()

    def seal(self, kind, identity, version, value):
        nonce = secrets.token_bytes(12)
        return nonce + self.aead.encrypt(nonce, encoded(value), encoded(['ACCESS_STORE_V1',kind,identity,version]))

    def open(self, kind, identity, version, blob):
        return json.loads(self.aead.decrypt(blob[:12],blob[12:], encoded(['ACCESS_STORE_V1',kind,identity,version])))

    @contextmanager
    def transaction(self):
        with self.lock:
            private(self.root, directory=True, repo=self.repo); private(self.path, repo=self.repo)
            for suffix in ('-journal','-wal','-shm'):
                p = Path(str(self.path)+suffix)
                if p.exists() or p.is_symlink(): private(p, repo=self.repo)
            c = sqlite3.connect(self.path, timeout=5)
            try:
                c.execute('PRAGMA secure_delete=ON'); c.execute('BEGIN IMMEDIATE')
                yield c
                c.commit()
            except BaseException:
                c.rollback(); raise
            finally: c.close()

    def _verify_audit(self, c):
        previous = '0'*64
        for seq, prev, blob, value in c.execute('SELECT seq,previous,value,digest FROM audit ORDER BY seq'):
            require(prev == previous and hmac.compare_digest(value, self.index('AUDIT', [seq,prev,blob.hex()])), 'Access audit integrity differs')
            self.open('AUDIT',seq,1,blob); previous = value

    def _audit(self, c, event, subject):
        row = c.execute('SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        seq, prev = (row[0]+1,row[1]) if row else (1,'0'*64)
        blob = self.seal('AUDIT',seq,1,{'event':event,'subject':subject,'observed_at':int(self.clock())})
        c.execute('INSERT INTO audit VALUES(?,?,?,?)',(seq,prev,blob,self.index('AUDIT',[seq,prev,blob.hex()])))

    def put_account(self, envelope, password=None):
        p = account(envelope,self.keys,now=self.clock()); identity = self.index('USER',p['username'])
        hashed = password_hash(password) if password is not None else None
        with self.transaction() as c:
            row = c.execute('SELECT version,value FROM users WHERE id=?',(identity,)).fetchone()
            require(not row or p['version'] > row[0], 'Account version must strictly advance')
            old = self.open('USER',identity,row[0],row[1]) if row else None
            require(old is None or old['grant']['payload']['user_id'] == p['user_id'], 'Login owner cannot change')
            require(hashed is not None or old is not None, 'Initial account requires private password')
            value = {'grant':deepcopy(envelope),'password':hashed if hashed is not None else old['password']}
            c.execute('INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,value=excluded.value',
                      (identity,self.index('OWNER',p['user_id']),p['version'],self.seal('USER',identity,p['version'],value)))
            # Auth checks version on every request, including current sessions.
            self._audit(c,'ACCOUNT_VERSION',identity)

    def put_directory(self, envelope):
        p = validate_directory(envelope,self.keys,now=self.clock())
        with self.transaction() as c:
            old = c.execute('SELECT version FROM directory WHERE id=1').fetchone()
            require(not old or p['generation'] > old[0], 'Directory generation must advance')
            c.execute('INSERT INTO directory VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,value=excluded.value',
                      (p['generation'],self.seal('DIRECTORY',1,p['generation'],envelope)))
            self._audit(c,'DIRECTORY_GENERATION',self.index('DIRECTORY',p['generation']))

    def _limit(self, c, kind, subject, count, period=60):
        now = int(self.clock()); ident = self.index('LIMIT',[kind,subject])
        c.execute('DELETE FROM throttle WHERE expires <= ?', (now,))
        row = c.execute('SELECT value FROM throttle WHERE id=?',(ident,)).fetchone()
        value = self.open('LIMIT',ident,1,row[0]) if row else {'until':now+period,'count':0}
        if now >= value['until']: value = {'until':now+period,'count':0}
        if value['count'] >= count: raise AccessError(429,'RATE_LIMITED')
        value['count'] += 1
        c.execute('INSERT INTO throttle VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET expires=excluded.expires,value=excluded.value',
                  (ident,value['until'],self.seal('LIMIT',ident,1,value)))
        # Bound database growth without storing raw addresses or usernames.
        if c.execute('SELECT COUNT(*) FROM throttle').fetchone()[0] > 10000:
            raise AccessError(429,'RATE_LIMITED')

    def login(self, login, password, peer, previous=None):
        try: username(login)
        except ValueError: raise AccessError(401,'INVALID_CREDENTIALS') from None
        ident = self.index('USER',login)
        # Commit consumed attempt counters even when login is denied.
        with self.transaction() as c:
            self._limit(c,'LOGIN_PEER',peer,20)
            self._limit(c,'LOGIN_USER',ident,5)
        with self.transaction() as c:
            row = c.execute('SELECT version,value FROM users WHERE id=?',(ident,)).fetchone()
            value = self.open('USER',ident,row[0],row[1]) if row else None
            match = password_matches(password,value['password'] if value else self.dummy)
            p = None
            if value:
                try: p = account(value['grant'],self.keys,now=self.clock())
                except Exception: pass
            if not match or not p or not p['active']:
                self._audit(c,'LOGIN_DENIED',ident)
                result = None
            else:
                token,csrf = secrets.token_urlsafe(32),secrets.token_urlsafe(32)
                sid = self.session_id(token)
                s = {'user':ident,'version':row[0],'csrf':csrf,'created':self.clock(),'last':self.clock()}
                c.execute('INSERT INTO sessions VALUES(?,?)',(sid,self.seal('SESSION',sid,1,s)))
                if previous: c.execute('DELETE FROM sessions WHERE id=?',(self.session_id(previous),))
                self._audit(c,'LOGIN_OK',ident); result = (token,csrf)
        if result is None: raise AccessError(401,'INVALID_CREDENTIALS')
        return result

    def session_id(self, token):
        return hmac.new(self.boot_key,str(token).encode(),hashlib.sha256).hexdigest()

    def _session(self,c,token,csrf=None):
        if type(token) is not str or not 40 <= len(token) <= 64: raise AccessError(401,'LOGIN_REQUIRED')
        sid = self.session_id(token); row = c.execute('SELECT value FROM sessions WHERE id=?',(sid,)).fetchone()
        if row is None: raise AccessError(401,'LOGIN_REQUIRED')
        s = self.open('SESSION',sid,1,row[0]); now = self.clock()
        if not s['created'] <= now < s['created']+1800 or not s['last'] <= now < s['last']+600:
            raise AccessError(401,'LOGIN_REQUIRED')
        row = c.execute('SELECT version,value FROM users WHERE id=?',(s['user'],)).fetchone()
        if row is None or row[0] != s['version']: raise AccessError(401,'LOGIN_REQUIRED')
        value = self.open('USER',s['user'],row[0],row[1])
        try: p = account(value['grant'],self.keys,now=now)
        except Exception: raise AccessError(403,'ACCESS_DENIED') from None
        if not p['active']: raise AccessError(403,'ACCESS_DENIED')
        if csrf is not None and (type(csrf) is not str or not hmac.compare_digest(csrf,s['csrf'])):
            raise AccessError(403,'CSRF_REQUIRED')
        s['last'] = now
        c.execute('UPDATE sessions SET value=? WHERE id=?',(self.seal('SESSION',sid,1,s),sid))
        return p,s

    def session(self,token):
        with self.transaction() as c:
            p,s = self._session(c,token)
            return {'username':p['username'],'role':p['role'],'scope_type':p['scope_type'],
                    'scope_id':p['scope_id'],'csrf_token':s['csrf'],'expires_at':min(s['created']+1800,p['expires_at'])}

    def logout(self,token,csrf):
        with self.transaction() as c:
            p,s = self._session(c,token,csrf or '')
            c.execute('DELETE FROM sessions WHERE id=?',(self.session_id(token),))
            self._audit(c,'LOGOUT',s['user'])

    def _directory(self,c):
        row = c.execute('SELECT version,value FROM directory WHERE id=1').fetchone()
        if row is None: raise AccessError(503,'DIRECTORY_UNAVAILABLE')
        try: return validate_directory(self.open('DIRECTORY',1,row[0],row[1]),self.keys,now=self.clock())
        except Exception: raise AccessError(503,'DIRECTORY_UNAVAILABLE') from None

    def search(self,token,csrf,kind,query,limit=20,offset=0):
        if kind not in ('NIC','NAME') or type(limit) is not int or not 1<=limit<=50 or type(offset) is not int or not 0<=offset<=10000:
            raise AccessError(400,'INVALID_SEARCH')
        try:
            q = normalize_identifier(query,identifier_type='NIC').value if kind=='NIC' else name(query)
            require(len(q)<=64 if kind=='NIC' else 3<=len(q)<=200, 'Bounded query required')
        except Exception: raise AccessError(400,'INVALID_SEARCH') from None
        with self.transaction() as c:
            p,s = self._session(c,token,csrf or '')
            self._limit(c,'SEARCH',s['user'],60)
            d = self._directory(c)
            # Filter membership BEFORE matching, counting, sorting or pagination.
            allowed = (o for o in d['officers'] if permitted(p,o))
            matches = [o for o in allowed if (o['nic']==q if kind=='NIC' else any(q in name(n) for n in o['names']))]
            matches.sort(key=lambda o:o['officer_uid'])
            self._audit(c,'IDENTITY_SEARCH',s['user'])
            return {'items':[projection(o) for o in matches[offset:offset+limit]],'total':len(matches),
                    'limit':limit,'offset':offset,'directory_generation':d['generation'],
                    'source_public_sha256':d['source_public_sha256']}

    def officer(self,token,officer_uid):
        with self.transaction() as c:
            p,s = self._session(c,token); self._limit(c,'SEARCH',s['user'],60)
            d = self._directory(c)
            found = next((o for o in d['officers'] if o['officer_uid']==officer_uid and permitted(p,o)),None)
            if found is None: raise AccessError(404,'NOT_FOUND')
            self._audit(c,'IDENTITY_READ',s['user']); return projection(found)
