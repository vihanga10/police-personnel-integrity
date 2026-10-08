"""Read-only live evidence and dual-chain audit readiness; never executes an audit."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
from app.identity.audit_gate import verify_inputs, seal_permit, require_audit_permit
from app.identity.bind_evidence_destinations import private_path
from app.identity.generate_protected_commitments import private_output
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.research_anchor import authenticate_gate
from app.identity.public_anchor_authorization import PUBLIC_SHA
from app.identity.evidence_bundle_v2 import require
from app.intake.registration_receipt import save_receipt

INHERITED = ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
    'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'credential-root', 'network-root',
    'wallet-root', 'backup-wallet-root', 'fabric-output-root')


def publication_hint(wallet_root, public):
    # Absence is a fast blocking hint only. Presence can NEVER authorize an audit.
    journal = wallet_root / 'publications' / public['batch_publication_id']
    if not journal.exists() or not (journal / 'PASSED.json').exists():
        return 'PUBLIC_PUBLICATION_INCOMPLETE'
    private_path(journal, True)
    private_path(journal / 'PASSED.json')
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (*INHERITED, 'output-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--publication-fee-budget-eth', required=True,
        help='Previously reviewed cumulative journal budget; RECONCILE cannot spend it.')
    args = parser.parse_args(); attempt = None
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(), 'Commit source first.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        public = json.loads(private_path(args.commitment_attempt / 'public-commitments.json').read_text())
        # Strict publication validation even on the fast-blocked path.
        from app.identity.protected_commitment import digest
        from app.identity.anchor_gate import publication_plan
        require(digest(public) == PUBLIC_SHA, 'Original publication required.')
        publication_plan(public)
        attempt = private_output(args.output_root, repo) / str(uuid4()); attempt.mkdir(mode=0o700)
        print('Audit gate attempt directory:', attempt, flush=True)
        reason = publication_hint(private_path(args.wallet_root, True), public)
        if reason:
            save_receipt(dict(status='BLOCKED', reason=reason, code_revision=revision,
                audit_executed=False, classification='UNASSESSED'), attempt / 'BLOCKED.json')
            print('Audit gate: BLOCKED | PUBLIC_PUBLICATION_INCOMPLETE')
            print('No audit permit issued. No database/RPC access or blockchain transactions.')
            return 2
        output = attempt / 'public-reconciliation'
        command = [sys.executable, '-u', '-m', 'app.identity.anchor_research_public']
        for name in INHERITED:
            command.extend(['--' + name, str(getattr(args, name.replace('-', '_')))])
        command.extend(['--output-root', str(output), '--publication-fee-budget-eth', args.publication_fee_budget_eth, '--reconcile'])
        require(subprocess.run(command, cwd=repo / 'backend').returncode == 0, 'Fresh public reconciliation failed.')
        children = list(private_path(output, True).iterdir()); require(len(children) == 1, 'One new public result required.')
        result = json.loads(private_path(children[0] / 'RESULT.json').read_text())
        require(result['status'] == 'PASSED', 'Complete public reconciliation required.')
        fabric = json.loads(private_path(args.fabric_output_root / result['fabric_attempt_id'] / 'PASSED.json').read_text())
        # Full public readback can outlast the ten-minute gate. Refresh live evidence
        # AFTER that readback; never extend an expired permit or relax freshness.
        live_output = attempt / 'final-live-gate'
        command = [sys.executable, '-u', '-m', 'app.identity.check_live_anchor_gate']
        for name in INHERITED[:8]:
            command.extend(['--' + name, str(getattr(args, name.replace('-', '_')))])
        command.extend(['--output-root', str(live_output)])
        require(subprocess.run(command, cwd=repo / 'backend').returncode == 0, 'Final live evidence check failed.')
        gates = list(private_path(live_output, True).iterdir()); require(len(gates) == 1, 'One final live result required.')
        crypto = private_key_file(private_path(args.key_file)); backup = private_key_file(private_path(args.backup_key_file))
        require(args.key_file.resolve() != args.backup_key_file.resolve(), 'Separate recovery keys required.')
        verify_recovery(crypto, backup)
        live = authenticate_gate(json.loads(private_path(gates[0] / 'live-gate.encrypted.json').read_text()),
            crypto, backup, public, revision=revision, commitment_attempt_id=args.commitment_attempt.name, expected_sha=PUBLIC_SHA)
        context = dict(code_revision=revision, bundle_attempt_id=args.bundle_attempt.name,
            binding_attempt_id=args.binding_attempt.name, commitment_attempt_id=args.commitment_attempt.name,
            binding_artifact_sha256=live['binding_artifact_sha256'])
        permit = verify_inputs(public, live, fabric, result, context)
        encrypted = seal_permit(crypto, backup, permit)
        require_audit_permit(encrypted, crypto, backup, public, context)
        save_receipt(encrypted, attempt / 'audit-permit.encrypted.json')
        save_receipt(dict(status='READY', policy=permit['policy'], expires_at=permit['expires_at'],
            code_revision=revision, officers=6596, audit_executed=False, classification='UNASSESSED'), attempt / 'READY.json')
        print('Audit gate: READY | exact live evidence and both complete anchors verified')
        print('Encrypted permit expires ten minutes after the final live fingerprint began. No audit executed.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(status='STOPPED', error_type=type(error).__name__, audit_executed=False), attempt / 'STOPPED.json')
        print('Audit gate stopped:', type(error).__name__)
        print('No permit issued; evidence, original journals and ledgers preserved.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
