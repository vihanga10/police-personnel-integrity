"""Run the unchanged complete audit gate with a pinned read-only transport profile."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from app.identity.audit_read_rpc_profile import load, ENV_NAMES
from app.identity.check_audit_gate import INHERITED

def command(args):
    result = [sys.executable, '-u', '-m', 'app.identity.check_audit_gate']
    for name in (*INHERITED, 'output-root'):
        result.extend(['--' + name, str(getattr(args, name.replace('-', '_')))])
    result.extend(['--publication-fee-budget-eth', args.publication_fee_budget_eth])
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (*INHERITED, 'output-root', 'read-profile'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-fee-budget-eth', required=True)
    parser.add_argument('--expected-read-profile-sha256', required=True)
    args = parser.parse_args()
    try:
        repo = Path(__file__).resolve().parents[3]
        if any(os.environ.get(name) for name in ENV_NAMES):
            raise ValueError('Inherited read profile environment refused.')
        load(args.read_profile, args.expected_read_profile_sha256, args.wallet_root, repo)
        env = dict(os.environ)
        env[ENV_NAMES[0]] = str(args.read_profile.expanduser().absolute())
        env[ENV_NAMES[1]] = args.expected_read_profile_sha256
        print('Read-only profile accepted: QUICKNODE + ALCHEMY', flush=True)
        print('Complete original audit gate required; no broadcast mode is available.', flush=True)
        return subprocess.run(command(args), cwd=repo / 'backend', env=env).returncode
    except Exception as error:
        print('Read-profile audit launcher stopped:', type(error).__name__)
        print('No audit started by this launcher; original configuration and journals preserved.')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
