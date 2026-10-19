"""Read retained promotion evidence without opening application stores or sessions."""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import sys


def inspect(runtime, repo, nic):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.access.store import private
    from app.intake.promotion_pipeline.core import canonical, check, digest

    key = private(runtime['key_file'], repo=repo).read_bytes()
    check(len(key) == 32, 'PRIVATE_KEY_FORMAT_DIFFERS')

    def database(root, name):
        file = private(Path(root) / name, repo=repo)
        connection = sqlite3.connect(file.resolve().as_uri() + '?mode=ro', uri=True)
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        return connection

    def decrypt(cipher, blob, associated):
        return json.loads(cipher.decrypt(blob[:12], blob[12:], canonical(associated)))

    def head(connection, subject):
        if connection is None:
            return None
        policy = 'PROMOTION_INDEPENDENT_APPROVAL_V1'
        cipher = AESGCM(hmac.digest(key, policy.encode(), 'sha256'))
        previous = None
        for version, blob in connection.execute('SELECT version,value FROM events WHERE subject=? ORDER BY version', (subject,)):
            value = decrypt(cipher, blob, [policy, subject, version])
            check(value['policy'] == policy and value['subject'] == subject and value['version'] == version, 'DECISION_BINDING_DIFFERS')
            check(version == (previous['version'] + 1 if previous else 1) and value['supersedes'] == (digest(previous) if previous else None), 'DECISION_LINEAGE_DIFFERS')
            previous = value
        return previous

    analysis = approvals = None
    connections = []
    try:
        intake = database(runtime['state_root'], 'promotion-intake.sqlite3'); connections.append(intake)
        if runtime.get('analysis_config'):
            config = json.loads(private(runtime['analysis_config'], repo=repo).read_bytes())
            analysis = database(config['analysis_root'], 'availability.sqlite3'); connections.append(analysis)
        if runtime.get('approval_config'):
            config = json.loads(private(runtime['approval_config'], repo=repo).read_bytes())
            approvals = database(config['decision_root'], 'decisions.sqlite3'); connections.append(approvals)
        cipher = AESGCM(key); results = []
        for ident, blob in intake.execute('SELECT id,value FROM batches ORDER BY rowid DESC LIMIT 1001'):
            check(len(results) < 1000, 'DIAGNOSTIC_OUTPUT_LIMIT')
            batch = decrypt(cipher, blob, ['PROMOTION_INTAKE_STORE_V1', 'BATCH', ident])
            check(batch['batch_id'] == ident and hashlib.sha256(base64.b64decode(batch['original_base64'], validate=True)).hexdigest() == batch['file_sha256'], 'BATCH_BINDING_DIFFERS')
            matching = [r for r in batch['rows'] if r.get('source', {}).get('officer_nic_no', '').strip() == nic]
            if not matching:
                continue
            phases = {}
            for phase, sealed in intake.execute('SELECT phase,value FROM phases WHERE batch=?', (ident,)):
                phases[phase] = decrypt(cipher, sealed, ['PROMOTION_INTAKE_STORE_V1', 'PHASE', [ident, phase]])
            available = None
            if analysis:
                row = analysis.execute('SELECT value FROM activations WHERE batch=?', (ident,)).fetchone()
                if row:
                    policy = 'PUBLISHED_PROMOTION_ANALYSIS_V1'
                    available = decrypt(AESGCM(hmac.digest(key, policy.encode(), 'sha256')), row[0], [policy, ident])
                    check(available['batch_id'] == ident and available['policy'] == policy, 'AVAILABILITY_BINDING_DIFFERS')
            decisions = []
            for row in matching:
                decision = head(approvals, 'ROW:' + ident + ':' + str(row['row']))
                result = decision.get('result', {}) if decision else {}
                decisions.append(dict(source_row=row['row'], intake_status=row['status'],
                    from_rank=row['source'].get('from_rank'), to_rank=row['source'].get('to_rank'),
                    effective_on=row['source'].get('effective_date'),
                    retained_acceptance_status=result.get('status', 'NO_RETAINED_DECISION'),
                    reasons=result.get('reasons', []), decision_recorded_at=decision.get('recorded_at') if decision else None))
            processing = head(approvals, 'BATCH:' + ident)
            results.append(dict(batch_id=ident, filename=batch['filename'], received_at=batch['received_at'],
                retained_phases=sorted(phases),
                publication_verified_at=phases.get('CHAINS_VERIFIED', {}).get('verification_observed_at'),
                analysis_connected_at=available['available_at'] if available else None,
                processing_decision=processing.get('kind') if processing else None, rows=decisions))
        return dict(status='READ_ONLY_RETAINED_PROMOTION_INSPECTION', nic=nic, batches=results,
                    observations_only=True, fresh_chain_reads=False, current_authority_re_evaluated=False,
                    application_sessions_opened=False, transactions_submitted=0,
                    note='These are retained decisions, not a fresh acceptance or blockchain verification. No private record is changed.')
    finally:
        for connection in connections:
            connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nic', default='930904350V')
    args = parser.parse_args()
    repo = Path.home() / 'Developer/police-personnel-integrity'
    sys.path.insert(0, str(repo / 'backend'))
    from app.access.store import private
    workspace = Path.home() / 'ResearchKeys/police-personnel-integrity/research-app-v1/workspace-config.json'
    config = json.loads(private(workspace, repo=repo).read_bytes())
    runtime = json.loads(private(config['promotion_intake_config'], repo=repo).read_bytes())
    print(json.dumps(inspect(runtime, repo, args.nic.strip()), indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps(dict(status='DIAGNOSTIC_STOPPED', error_type=type(error).__name__,
                              private_records_changed=False, transactions_submitted=0)))
        raise SystemExit(1)
