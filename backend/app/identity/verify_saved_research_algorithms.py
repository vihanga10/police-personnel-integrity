"""Protected saved-result replay only; no fresh audit or live database/RPC check."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from app.identity.evidence_bundle_v2 import seal_artifact
from app.identity.generate_protected_commitments import private_output
from app.identity.historical_reconstruction import require
from app.identity.saved_algorithm_snapshot import load_saved_snapshot
from app.identity.saved_research_algorithms import SavedRun, replay, POLICY, safe_failure
from app.intake.registration_receipt import save_receipt


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('key-file', 'backup-key-file', 'commitment-key-file', 'backup-commitment-key-file',
        'bundle-attempt', 'binding-attempt', 'commitment-attempt', 'algorithm-attempt', 'output-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv); attempt = None
    os.umask(0o077)
    try:
        repo = Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip(),
            'Commit reviewed source first.')
        revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        snapshot = load_saved_snapshot(args, repo)
        saved = SavedRun(args.algorithm_attempt, snapshot)
        def progress(kind, count, total):
            print('Saved algorithm replay progress:', kind, count, '/', total, flush=True)
        report = replay(saved, progress=progress)
        report['review_revision'] = revision
        attempt = private_output(args.output_root, repo)/str(uuid4()); attempt.mkdir(mode=0o700)
        print('Saved algorithm verification attempt directory:', attempt, flush=True)
        binding = dict(policy=POLICY, artifact='SAVED_ALGORITHM_VERIFICATION',
            review_revision=revision, algorithm_attempt_id=saved.directory.name,
            completion_artifact_sha256=saved.completion_sha, source_context=saved.report['context'])
        save_receipt(seal_artifact(snapshot['crypto'], snapshot['backup'], report, binding),
            attempt/'verification.encrypted.json')
        save_receipt(report, attempt/'PASSED.json')
        print('Protected saved research algorithm replay: PASSED')
        print(json.dumps(report, sort_keys=True))
        print('Archived result replay only. No new historical query, live readiness, database/RPC access or blockchain writes.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY, status='STOPPED', completed=False, error_type=type(error).__name__),
                attempt/'STOPPED.json')
        print('Saved algorithm verification stopped:', type(error).__name__)
        print('Failed check:', safe_failure(error))
        print('No completed verification issued. Original evidence and saved results preserved.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
