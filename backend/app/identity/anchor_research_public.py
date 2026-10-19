"""Freshly reconcile live evidence/Fabric before validating, publishing or reconciling Sepolia."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
from app.identity.bind_evidence_destinations import private_path
from app.identity.generate_protected_commitments import private_output
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.destination_binding import require
from app.identity.research_anchor import authenticate_gate
from app.identity.public_anchor_authorization import ticket, PUBLIC_SHA
from app.intake.registration_receipt import save_receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inherited = ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
        'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'credential-root', 'network-root')
    for name in (*inherited, 'wallet-root', 'backup-wallet-root', 'output-root', 'fabric-output-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-fee-budget-eth', default='0.025')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--execute', action='store_true')
    modes.add_argument('--reconcile', action='store_true')
    args = parser.parse_args()
    attempt = None
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(), 'Commit source first.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        mode = 'EXECUTE' if args.execute else 'RECONCILE' if args.reconcile else 'VALIDATE'
        output = private_output(args.output_root, repo)
        attempt = output / str(uuid4())
        attempt.mkdir(mode=0o700)
        print('Public research attempt directory:', attempt, flush=True)
        save_receipt(dict(status='STARTED', mode=mode, code_revision=revision), attempt / 'STARTED.json')
        # This existing guarded runner performs live Stage 2 reconciliation and an authenticated
        # destination comparison, then verifies all 68 original Fabric transactions and both peers.
        command = [sys.executable, '-u', '-m', 'app.identity.anchor_research_fabric']
        for name in inherited:
            command.extend(['--' + name, str(getattr(args, name.replace('-', '_')))])
        fabric_output = private_output(args.fabric_output_root, repo)
        before = {p.name for p in fabric_output.iterdir()}
        command.extend(['--output-root', str(fabric_output), '--expected-public-sha256', PUBLIC_SHA, '--reconcile'])
        require(subprocess.run(command, cwd=repo / 'backend').returncode == 0, 'Fresh live/Fabric reconciliation failed.')
        children = [p for p in fabric_output.iterdir() if p.name not in before and p.name != 'journals']
        require(len(children) == 1, 'One fresh Fabric result required.')
        child = children[0]
        reconciliation = json.loads(private_path(child / 'PASSED.json').read_text())
        gates = list((child / 'live-gates').iterdir())
        require(len(gates) == 1, 'One fresh encrypted live gate required.')
        public = json.loads(private_path(args.commitment_attempt / 'public-commitments.json').read_text())
        crypto = private_key_file(private_path(args.key_file))
        backup = private_key_file(private_path(args.backup_key_file))
        require(args.key_file.resolve() != args.backup_key_file.resolve(), 'Separate identity keys required.')
        verify_recovery(crypto, backup)
        envelope = json.loads(private_path(gates[0] / 'live-gate.encrypted.json').read_text())
        gate = authenticate_gate(envelope, crypto, backup, public, revision=revision,
            commitment_attempt_id=args.commitment_attempt.name, expected_sha=PUBLIC_SHA)
        secret = os.urandom(32)
        authorization = ticket(public, gate, reconciliation, mode=mode,
            budget=args.publication_fee_budget_eth, secret=secret)
        save_receipt(authorization, attempt / 'authorization.json')
        # The existing Fabric output root retains its original journals; no Fabric writes occur.
        journal_root = private_output(args.wallet_root / 'publications', repo)
        journal = journal_root / public['batch_publication_id']
        if mode == 'RECONCILE':
            private_path(journal, True)
        else:
            journal.mkdir(mode=0o700, exist_ok=True)
        result_file = attempt / 'public-result.json'
        process = subprocess.run(['node', str(repo / 'blockchain/public/publish-research.js'),
            str(private_path(args.wallet_root, True)), str(private_path(args.backup_wallet_root, True)),
            str(attempt / 'authorization.json'), str(journal), str(result_file), mode, revision],
            input=secret.hex() + '\n', text=True, cwd=repo)
        require(process.returncode == 0, 'Guarded public workflow stopped; original journals preserved.')
        summary = json.loads(private_path(result_file).read_text())
        require(summary['code_revision'] == revision, 'Public result source differs.')
        save_receipt(dict(status=summary['status'], mode=mode, code_revision=revision,
            public_result=summary, fabric_attempt_id=child.name, live_gate_attempt_id=gates[0].name), attempt / 'RESULT.json')
        print('Public workflow result:', summary['status'], flush=True)
        print('Evidence and original Fabric ledger preserved. Classification remains UNASSESSED; audits pending.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(status='STOPPED', error_type=type(error).__name__), attempt / 'STOPPED.json')
        print('Public research workflow stopped:', type(error).__name__)
        print('Original transactions and private journals preserved; do not delete or reset.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
