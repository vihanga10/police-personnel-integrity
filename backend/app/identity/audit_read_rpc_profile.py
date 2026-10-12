"""Owner-only read transport profiles. Not custody permission or audit readiness."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import urlsplit

POLICY = 'ANCHORED_AUDIT_READ_RPC_PROFILE_V1'
CONFIG = 'b1fb4596332921c0c68a66504098fb3b4ba988e36d6f79ab465d6b22fc7aba61'
PUBLIC = 'fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b'
ENV_NAMES = ('PPI_AUDIT_READ_RPC_PROFILE', 'PPI_AUDIT_READ_RPC_SHA256')
FIELDS = {'policy', 'code_revision', 'original_config_file', 'original_config_sha256',
          'original_rpc_sha256', 'public_payload_sha256', 'rpc_urls'}

def require(value):
    if not value:
        raise ValueError('Read profile validation failed.')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)

def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()

def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON.')))

def private_path(file, repository):
    p = Path(file).expanduser().absolute()
    require('..' not in p.parts)
    require(not any(x.is_symlink() for x in (p, *p.parents)))
    require(not p.is_relative_to(repository))
    return p

def read(file, repository):
    p = private_path(file, repository)
    parent, s = p.parent.stat(), p.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and not parent.st_mode & 0o077)
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and
            not s.st_mode & 0o077 and s.st_size <= 16384)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require((s.st_ino, s.st_dev, s.st_size) == (opened.st_ino, opened.st_dev, opened.st_size))
        require(opened.st_uid == os.getuid() and opened.st_nlink == 1 and not opened.st_mode & 0o077)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(16385)
    finally:
        os.close(fd)

def revision(repository):
    def git(*parts):
        return subprocess.check_output(['git', '-C', str(repository), *parts], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    require(git('branch', '--show-current') == 'feat/identity-resolution' and not git('status', '--porcelain'))
    head = git('rev-parse', 'HEAD')
    require(re.fullmatch('[0-9a-f]{40}', head))
    return head

def candidate(url, provider):
    require(isinstance(url, str) and 1 <= len(url) <= 4096 and not any(c.isspace() for c in url))
    u = urlsplit(url)
    require(u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.fragment and
            u.port in (None, 443))
    if provider == 0:
        require(u.hostname.endswith('.quiknode.pro') and not u.query and u.path not in ('', '/'))
    else:
        require(u.hostname.endswith('.alchemy.com'))
    return url

def original(wallet_root, repository):
    file = private_path(Path(wallet_root) / 'network.json', repository)
    config = decode(read(file, repository))
    require(sha(canonical(config)) == CONFIG)
    require(isinstance(config.get('rpc_urls'), list) and len(config['rpc_urls']) == 2)
    candidate(config['rpc_urls'][1], 1)
    return file, config

def prepare(wallet_root, profile_file, url, repository):
    head = revision(repository)
    original_file, config = original(wallet_root, repository)
    candidate(url, 0)
    profile = dict(policy=POLICY, code_revision=head, original_config_file=str(original_file),
        original_config_sha256=CONFIG, original_rpc_sha256=[sha(u) for u in config['rpc_urls']],
        public_payload_sha256=PUBLIC, rpc_urls=[url, config['rpc_urls'][1]])
    file = private_path(profile_file, repository)
    require(not file.exists())
    file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = file.parent.stat()
    require(parent.st_uid == os.getuid() and not parent.st_mode & 0o077)
    private_path(file, repository)
    payload = (canonical(profile) + '\n').encode()
    require(len(payload) <= 16384)
    require(revision(repository) == head)
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    inode = os.fstat(fd).st_ino
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(payload); stream.flush(); os.fsync(fd)
        load(file, sha(payload), wallet_root, repository)
    except Exception:
        if not file.is_symlink() and file.stat().st_ino == inode:
            file.unlink()
        raise
    finally:
        os.close(fd)
    return sha(payload)

def load(file, expected_sha, wallet_root, repository):
    require(isinstance(expected_sha, str) and re.fullmatch('[0-9a-f]{64}', expected_sha))
    payload = read(file, repository)
    require(sha(payload) == expected_sha)
    p = decode(payload)
    require(isinstance(p, dict) and set(p) == FIELDS and payload == (canonical(p) + '\n').encode())
    require(p['policy'] == POLICY and p['original_config_sha256'] == CONFIG and p['public_payload_sha256'] == PUBLIC)
    require(p['code_revision'] == revision(repository))
    original_file, config = original(wallet_root, repository)
    require(p['original_config_file'] == str(original_file))
    require(p['original_rpc_sha256'] == [sha(u) for u in config['rpc_urls']])
    require(isinstance(p['rpc_urls'], list) and len(p['rpc_urls']) == 2 and p['rpc_urls'][1] == config['rpc_urls'][1])
    for n, url in enumerate(p['rpc_urls']):
        candidate(url, n)
    require(urlsplit(p['rpc_urls'][0]).hostname != urlsplit(p['rpc_urls'][1]).hostname)
    return p
