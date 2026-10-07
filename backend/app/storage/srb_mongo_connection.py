"""Separate private credentials for the least-privilege SRB writer."""
import json
import os
from pathlib import Path
import secrets
import stat
from pymongo import MongoClient
from app.storage.srb_mongo_contract import APP_USER, DATABASE


def srb_password(directory, *, create=False):
    path = Path(directory).expanduser().absolute()
    # Reject symlink traversal rather than redirecting secrets to an unknown target.
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('SRB credential path is not private.')
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=True)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('SRB credential directory is not private.')
    target = path / 'credentials.json'
    if target.is_symlink():
        raise ValueError('SRB credential file is not private.')
    if create and not target.exists():
        # Exclusive creation never replaces an existing password, even on a retry.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'app_password': secrets.token_urlsafe(48)}, stream)
            stream.write('\n')
    if not target.is_file() or stat.S_IMODE(target.stat().st_mode) & 0o077:
        raise ValueError('SRB credential file is not private.')
    data = json.loads(target.read_text())
    if set(data) != {'app_password'} or not isinstance(data['app_password'], str) or len(data['app_password']) < 32:
        raise ValueError('Invalid SRB credentials.')
    return data['app_password']


def srb_client(password):
    return MongoClient('127.0.0.1', 27018, username=APP_USER, password=password,
                       authSource=DATABASE, serverSelectionTimeoutMS=5000,
                       connectTimeoutMS=5000, socketTimeoutMS=10000,
                       tz_aware=True, retryWrites=False)
