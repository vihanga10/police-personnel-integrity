"""Fresh-permit actor/date history review with encrypted linked inventories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from app.identity.action_actor_history import ActorHistory, POLICY
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.algorithm_snapshot import load_verified_snapshot
from app.identity.bind_evidence_destinations import private_path
from app.identity.generate_protected_commitments import private_output
from app.identity.historical_reconstruction import require
from app.identity.reconstruct_history import subject_index
from app.identity.run_research_algorithms import protected_result, guard
from app.identity.saved_research_algorithms import SavedRun, matched_actions, both_keys, read_json_bytes, safe_failure, POLICY as REPLAY
from app.intake.registration_receipt import save_receipt


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
        'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'audit-gate-attempt',
        'algorithm-attempt', 'saved-review-attempt', 'output-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    # Action dates come from the verified saved action inventory, not a new cutoff.
    return parser.parse_args(argv)


def verification_receipt(directory, saved):
    directory = private_path(directory, True)
    require(set(p.name for p in directory.iterdir()) == {'verification.encrypted.json', 'PASSED.json'},
        'Complete saved replay verification required.')
    envelope = read_json_bytes(private_path(directory/'verification.encrypted.json').read_bytes())
    report = both_keys(saved.snapshot['crypto'], saved.snapshot['backup'], envelope, envelope['binding'])
    binding = dict(policy=REPLAY, artifact='SAVED_ALGORITHM_VERIFICATION',
        review_revision=report['review_revision'], algorithm_attempt_id=saved.directory.name,
        completion_artifact_sha256=saved.completion_sha, source_context=saved.report['context'])
    require(envelope['binding'] == binding and report['policy'] == REPLAY and report['status'] == 'PASSED' and
        report['mode'] == 'SAVED_RESULT_REPLAY' and report['new_audit_executed'] is False and
        report['live_readiness_claim'] is False and report['algorithm_attempt_id'] == saved.directory.name and
        report['completion_artifact_sha256'] == saved.completion_sha and
        report['source_context'] == saved.report['context'] and report['policies'] == saved.report['policies'] and
        report['on'] == saved.report['on'] and report['officers'] == saved.report['officers'] and
        report['authority_action_records'] == saved.report['authority_action_records'] and
        report['artifact_count'] == len(saved.inventory) and
        report['public_payload_sha256'] == saved.report['public_payload_sha256'] and
        report['classification'] == 'UNASSESSED' and all(report[k] is False for k in
        ('accepted_state_claim', 'accepted_authority_claim', 'accepted_contradiction_claim')),
        'Saved replay receipt differs from this completed run.')
    require(read_json_bytes(private_path(directory/'PASSED.json').read_bytes()) == report,
        'Saved replay plaintext receipt differs.')
    return report


class Writer:
    """Small independent chunks preserve all detail without repeated source rows."""
    def __init__(self, snapshot, directory, base, prefix, artifact, size=100):
        self.snapshot = snapshot; self.directory = directory; self.base = base
        self.prefix = prefix; self.artifact = artifact; self.size = size
        self.pending = []; self.files = 0; self.records = 0

    def add(self, values):
        for value in values:
            self.pending.append(value); self.records += 1
            if len(self.pending) == self.size:self.flush()

    def flush(self):
        if not self.pending:return
        binding = dict(self.base, artifact=self.artifact, chunk=self.files)
        payload = dict(self.base, results=self.pending)
        envelope = protected_result(self.snapshot, payload, binding)
        save_receipt(envelope, self.directory/('%s-%04d.encrypted.json' % (self.prefix, self.files)))
        self.files += 1; self.pending = []


def main(argv=None):
    args = arguments(argv); attempt = None
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(),
            'Commit reviewed source first.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        snapshot = load_verified_snapshot(args, repo, revision)
        snapshot['permit_session'] = AlgorithmPermit(snapshot); guard(snapshot)
        saved = SavedRun(args.algorithm_attempt, snapshot)
        verified = verification_receipt(args.saved_review_attempt, saved); guard(snapshot)
        buckets = subject_index(snapshot['manifest'], snapshot['catalog'])
        require(len(buckets) == 6596, 'Complete anchored actor universe required.')
        selected_uid = saved.selected_uid(buckets)
        catalog = saved.action_catalog(selected_uid)
        attempt = private_output(args.output_root, repo)/str(uuid4()); attempt.mkdir(mode=0o700)
        print('Action actor-history attempt directory:', attempt, flush=True)
        base = dict(policy=POLICY, context=snapshot['context'], public_payload_sha256=saved.report['public_payload_sha256'],
            algorithm_attempt_id=saved.directory.name, completion_artifact_sha256=saved.completion_sha,
            saved_review_attempt_id=args.saved_review_attempt.name, cutoff=saved.report['on'],
            history_policy=saved.report['policies']['history'], classification='UNASSESSED')
        claims = Writer(snapshot, attempt, base, 'claims', 'ACTOR_CLAIM_INVENTORY', size=25)
        states = Writer(snapshot, attempt, base, 'states', 'REPORTED_ACTION_DATE_ACTOR_STATES')
        links = Writer(snapshot, attempt, base, 'actions', 'ACTION_ACTOR_STATE_LINKS')
        history = ActorHistory(buckets, snapshot['bindings']['raw_bindings'], snapshot['captured_at'],
            saved.report['public_payload_sha256'])
        for number, action in enumerate(matched_actions(saved, catalog), 1):
            # Check before a bounded batch and around every encrypted write. No
            # expired computation can issue a completed artifact or PASSED result.
            if number % 100 == 1:guard(snapshot)
            result = history.review(action)
            new_claims, new_states = history.drain()
            claims.add(new_claims); states.add(new_states); links.add((result,))
            if number % 10000 == 0:
                print('Action actor-history progress:', number, '/', saved.report['authority_action_records'], flush=True)
        claims.flush(); states.flush(); links.flush(); guard(snapshot, full=True)
        aggregate = history.aggregate()
        require(aggregate['authority_action_records'] == saved.report['authority_action_records'] and
            aggregate['authority_action_counts'] == saved.report['authority_action_counts'],
            'Action actor-history coverage differs from verified actions.')
        report = dict(base, status='PASSED', review_revision=revision,
            mode='FRESH_PERMIT_REPORTED_ACTION_DATE_REVIEW', **aggregate,
            claim_artifacts=claims.files, state_artifacts=states.files, action_artifacts=links.files,
            accepted_state_claim=False, accepted_authority_claim=False, governing_instruments_assessed=False,
            findings_database_written=False, findings_anchored=False,
            saved_replay_revision=verified['review_revision'])
        inventory = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(attempt.glob('*.encrypted.json'))}
        completion = protected_result(snapshot, dict(report=report, artifacts=inventory),
            dict(base, artifact='ACTOR_HISTORY_COMPLETION'))
        completion_path = attempt/'completion.encrypted.json'; save_receipt(completion, completion_path)
        report['completion_artifact_sha256_current']=hashlib.sha256(completion_path.read_bytes()).hexdigest()
        guard(snapshot); save_receipt(report, attempt/'PASSED.json')
        print('Protected reported action-date actor-history review: PASSED')
        print(json.dumps(report, sort_keys=True))
        print('Reported actor histories and uncertainty only. No accepted authority, findings database, CSV corrections or blockchain writes.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY, status='STOPPED', completed=False, error_type=type(error).__name__),
                attempt/'STOPPED.json')
        print('Action actor-history review stopped:', type(error).__name__)
        print('Failed check:', safe_failure(error))
        print('No completed review issued. Original evidence and private partial outputs preserved.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
