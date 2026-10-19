"""The troubleshooting path must not mutate sessions, decisions or journals."""
import hashlib
import json
from pathlib import Path
from scripts.inspect_promotion_evidence import inspect
from test_promotion_approvals import e, batch, visible, assess
from test_promotion_analysis import connected, env


def files(root):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and p.suffix in {'.sqlite3', '.json'}}


def test_inspection_reports_retained_pending_then_accepted_without_writing(e, tmp_path):
    b = batch(e); visible(e, b); e['engine'].synchronize()
    analysis_config = tmp_path / 'diagnostic-analysis.json'
    analysis_config.write_text(json.dumps({'analysis_root': str(e['analysis'].journal.root)}))
    analysis_config.chmod(0o600)
    runtime = dict(state_root=str(e['intake'].root), key_file=str(tmp_path / 'intake-key'),
                   approval_config=str(e['engine'].file), analysis_config=str(analysis_config))
    before = files(tmp_path)
    result = inspect(runtime, e['store'].repo, '000000001V')
    assert before == files(tmp_path)
    row = result['batches'][0]
    assert row['analysis_connected_at'] and row['publication_verified_at']
    assert row['processing_decision'] == 'APPROVE'
    assert row['rows'][0]['retained_acceptance_status'] == 'PENDING_REVIEW'
    assert 'AUTHORITY_CANNOT_VERIFY' in row['rows'][0]['reasons']
    assert result['transactions_submitted'] == 0 and not result['application_sessions_opened']
    assess(e, b); e['engine'].synchronize(); before = files(tmp_path)
    assert inspect(runtime, e['store'].repo, '000000001V')['batches'][0]['rows'][0]['retained_acceptance_status'] == 'ACCEPTED'
    assert before == files(tmp_path)
    assert inspect(runtime, e['store'].repo, 'UNKNOWN')['batches'] == []
