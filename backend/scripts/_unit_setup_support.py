"""Private-store loading, locked SQL transactions and encrypted recovery jobs.
Used only by setup_unit_sdig_totp.py; does not initialize or clear stores.
"""
import argparse, base64, fcntl, hashlib, hmac, json, os, secrets, socket, sqlite3, sys, time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import uuid4, UUID

sys.dont_write_bytecode = True


def require(value, code):
    if not value:
        raise ValueError(code)


def scoped(c, prefix):
    class SQL:
        def execute(self, sql, args=()):
            if sql == 'PRAGMA user_version':
                sql = f'PRAGMA {prefix}.user_version'
            else:
                sql = sql.replace('FROM events', f'FROM {prefix}.events')
            return c.execute(sql, args)
    return SQL()


def load(repo, root):
    sys.path[:0] = [str(repo / 'backend'), str(repo / 'backend/scripts')]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app.access.store import AccessStore, private
    from app.access.research_store import ResearchStore
    from app.access.accountability import AccountabilityStore
    from app.access.policy import encoded
    def read(p):
        return json.loads(private(p, repo=repo).read_text())
    private(root, directory=True, repo=repo)
    wc = read(root / 'workspace-config.json'); ac = read(wc['access_config'])
    lc = read(wc['accountability_config']); manifest = read(root / 'accounts.json')
    require(ac['policy'] == 'SCOPED_ACCESS_CONFIG_V1' and Path(ac['repository']).resolve() == repo,
            'ACCESS_CONFIGURATION_DIFFERS')
    require(wc['policy'] == 'RESEARCH_WEB_CONFIG_V1' and lc['policy'] == 'ACCOUNTABILITY_CONFIG_V1',
            'WORKSPACE_CONFIGURATION_DIFFERS')
    require(manifest['record_origin'] == 'GENERATED_RESEARCH_RECORDS' and len(manifest['accounts']) in (10,12),
            'EXISTING_GENERATED_ACCOUNTS_REQUIRED')
    origin = urlsplit(ac['origin'])
    require(origin.scheme == 'https' and origin.hostname in ('127.0.0.1', 'localhost'), 'LOCAL_HTTPS_REQUIRED')
    with socket.socket() as s:
        s.settimeout(1)
        require(s.connect_ex(('127.0.0.1', origin.port or 443)) != 0, 'STOP_APPLICATION_FIRST')
    public = lambda values: {k: base64.b64decode(v, validate=True) for k, v in values.items()}
    # Never call the constructors: AccessStore initialization deletes sessions.
    a = AccessStore.__new__(AccessStore); a.repo = repo; a.clock = time.time
    a.root = private(ac['state_directory'], directory=True, repo=repo)
    a.key_path = private(ac['key_file'], repo=repo); ak = a.key_path.read_bytes()
    require(len(ak) == 32, 'ACCESS_KEY_FORMAT_DIFFERS')
    a.aead = AESGCM(ak); a.lookup_key = hmac.digest(ak, b'ACCESS_INDEX_V1', 'sha256')
    a.keys = public(ac['authority_keys']); a.path = private(a.root / 'access.sqlite3', repo=repo)
    w = ResearchStore.__new__(ResearchStore); w.repo = repo; w.clock = time.time; w.access = a
    w.root = private(wc['state_directory'], directory=True, repo=repo)
    wk = private(wc['key_file'], repo=repo).read_bytes()
    require(len(wk) == 32 and wk != ak, 'WORKSPACE_KEY_FORMAT_DIFFERS')
    w.aead = AESGCM(wk); w.index_key = hmac.digest(wk, b'RESEARCH_UI_INDEX_V1', 'sha256')
    w.keys = public(wc['presentation_keys']); w.path = private(w.root / 'workspace.sqlite3', repo=repo)
    l = AccountabilityStore.__new__(AccountabilityStore); l.repo = repo; l.clock = time.time; l.access = a
    l.root = private(lc['state_directory'], directory=True, repo=repo)
    l.key_path = private(lc['key_file'], repo=repo); l.key = l.key_path.read_bytes()
    require(len(l.key) == 32 and l.key not in (ak, wk), 'LOG_KEY_FORMAT_DIFFERS')
    l.aead = AESGCM(l.key); l.db = private(l.root / 'accountability.sqlite3', repo=repo)
    l.checkpoint = private(l.root / 'checkpoint.json', repo=repo)
    l.grant_files = tuple(private(p, repo=repo) for p in lc['reader_grants'])
    access_seed = private(root / 'keys/research-access-signer.key', repo=repo).read_bytes()
    presentation_seed = private(root / 'keys/research-presentation-signer.key', repo=repo).read_bytes()
    require(access_seed == private(root / 'key-backup/research-access-signer.key', repo=repo).read_bytes(),
            'ACCESS_SIGNER_BACKUP_DIFFERS')
    require(presentation_seed == private(root / 'key-backup/research-presentation-signer.key', repo=repo).read_bytes(),
            'PRESENTATION_SIGNER_BACKUP_DIFFERS')
    ask = Ed25519PrivateKey.from_private_bytes(access_seed); wsk = Ed25519PrivateKey.from_private_bytes(presentation_seed)
    access_id = next((k for k, v in a.keys.items() if v == ask.public_key().public_bytes_raw()), None)
    workspace_id = next((k for k, v in w.keys.items() if v == wsk.public_key().public_bytes_raw()), None)
    require(access_id and workspace_id, 'EXISTING_SIGNER_TRUST_REQUIRED')
    require(len({access_seed, presentation_seed, ak, wk, l.key}) == 5, 'SEPARATE_KEYS_REQUIRED')
    files = [root/'workspace-config.json', Path(wc['access_config']), Path(wc['accountability_config']),
             root/'accounts.json', a.key_path, Path(wc['key_file']), l.key_path,
             root/'keys/research-access-signer.key', root/'keys/research-presentation-signer.key']
    pins = {str(p): hashlib.sha256(private(p, repo=repo).read_bytes()).hexdigest() for p in files}
    return SimpleNamespace(a=a,w=w,l=l,wk=wk,manifest=manifest,repo=repo,root=root,pins=pins,
                           ask=ask,wsk=wsk,access_id=access_id,workspace_id=workspace_id)


def connect(x, readonly):
    uri = lambda p: p.as_uri() + ('?mode=ro' if readonly else '?mode=rw')
    c = sqlite3.connect(uri(x.a.path), uri=True, timeout=15)
    try:
        c.execute('ATTACH DATABASE ? AS ui', (uri(x.w.path),))
        c.execute('ATTACH DATABASE ? AS logs', (uri(x.l.db),))
        if readonly:
            c.execute('PRAGMA query_only=ON'); c.execute('BEGIN')
        else:
            require(len({p.stat().st_dev for p in (x.a.path,x.w.path,x.l.db)}) == 1,
                    'ATOMIC_RENEWAL_REQUIRES_SAME_FILESYSTEM')
            for prefix in ('main','ui','logs'):
                mode = c.execute(f'PRAGMA {prefix}.journal_mode').fetchone()[0]
                require(mode.lower() in ('delete','truncate','persist'), 'ROLLBACK_JOURNAL_REQUIRED')
                c.execute(f'PRAGMA {prefix}.synchronous=FULL')
            c.execute('BEGIN IMMEDIATE')
        return c
    except BaseException:
        c.close(); raise


def sign(key, key_id, payload):
    from app.access.policy import encoded
    return dict(key_id=key_id, payload=payload, signature=base64.b64encode(key.sign(encoded(payload))).decode())


def write_new(path, data):
    with path.open('xb') as f:
        os.fchmod(f.fileno(),0o600); f.write(data); f.flush(); os.fsync(f.fileno())


def job_write(x, directory, value):
    from app.access.policy import encoded
    nonce=secrets.token_bytes(12)
    blob=nonce+x.w.aead.encrypt(nonce,encoded(value),encoded(['RESEARCH_ACCESS_RENEWAL_JOB_V1',directory.name]))
    tmp=directory/('job-'+secrets.token_hex(8)+'.tmp'); write_new(tmp,blob)
    os.replace(tmp,directory/'job.encrypted')
    fd=os.open(directory,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def job_read(x, directory):
    from app.access.policy import encoded
    from app.access.store import private
    blob=private(directory/'job.encrypted',repo=x.repo).read_bytes()
    return json.loads(x.w.aead.decrypt(blob[:12],blob[12:],encoded(['RESEARCH_ACCESS_RENEWAL_JOB_V1',directory.name])))

