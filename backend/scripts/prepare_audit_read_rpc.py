"""Save a separate private QuickNode/Alchemy read profile without editing original evidence."""
import argparse
import getpass
import os
from pathlib import Path
import sys
import warnings
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.identity.audit_read_rpc_profile import prepare, ENV_NAMES

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wallet-root', type=Path, required=True)
    parser.add_argument('--profile-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        if any(os.environ.get(name) for name in ENV_NAMES):
            raise ValueError('Existing read profile environment.')
        warnings.simplefilter('error', getpass.GetPassWarning)
        url = getpass.getpass('Paste QuickNode Sepolia HTTPS URL (hidden): ').strip()
        digest = prepare(args.wallet_root, args.profile_file, url, Path(__file__).resolve().parents[2])
        print('Private read profile saved:', args.profile_file.expanduser().absolute())
        print('Read profile SHA256:', digest)
        print('Original network configuration and journals unchanged. No RPC calls, transactions or audit permit.')
        return 0
    except Exception as error:
        print('Read profile preparation stopped:', type(error).__name__)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
