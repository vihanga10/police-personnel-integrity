"""Create exclusive, private credentials outside the Git checkout."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    target = args.directory.expanduser().absolute()
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()).resolve()
    if root == target.resolve() or root in target.resolve().parents or any(p.is_symlink() for p in (target, *target.parents)):
        raise SystemExit("Stop: credentials must be outside the repository, without symlink paths.")
    # An existing directory is never replaced, even after an interrupted preparation.
    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, value in (
        ("root-password.txt", secrets.token_urlsafe(48) + "\n"),
        ("credentials.json", json.dumps({"app_password": secrets.token_urlsafe(48)}) + "\n"),
    ):
        descriptor = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value)
    print("Private Mongo credentials created. No passwords displayed; no database connection.")


if __name__ == "__main__":
    main()
