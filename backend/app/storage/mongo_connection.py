"""Private local credentials; never build or print a password-bearing URI."""
import json
import stat
from pathlib import Path
from pymongo import MongoClient
from app.storage.mongo_contract import APP_USER, DATABASE


def load_credentials(directory):
    directory = Path(directory).expanduser()
    # Reject symlinks and permissive modes rather than silently changing permissions.
    for path in (directory, *directory.parents, directory / "credentials.json", directory / "root-password.txt"):
        if path.is_symlink():
            raise ValueError("Credential path is not private.")
    if not directory.is_dir():
        raise ValueError("Invalid credential directory.")
    for path in (directory, directory / "credentials.json", directory / "root-password.txt"):
        if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("Credential path is not private.")
    if not (directory / "credentials.json").is_file() or not (directory / "root-password.txt").is_file():
        raise ValueError("Invalid credential files.")
    data = json.loads((directory / "credentials.json").read_text())
    if set(data) != {"app_password"} or not isinstance(data["app_password"], str) or len(data["app_password"]) < 32:
        raise ValueError("Invalid application credentials.")
    root = (directory / "root-password.txt").read_text().strip()
    if len(root) < 32:
        raise ValueError("Invalid bootstrap credentials.")
    return root, data["app_password"]


def client(password, *, bootstrap=False):
    # This foundation intentionally targets only the dedicated loopback instance.
    return MongoClient("127.0.0.1", 27018,
                       username="police_mongo_bootstrap" if bootstrap else APP_USER,
                       password=password, authSource="admin" if bootstrap else DATABASE,
                       serverSelectionTimeoutMS=5000, connectTimeoutMS=5000,
                       socketTimeoutMS=10000, tz_aware=True, retryWrites=False)
