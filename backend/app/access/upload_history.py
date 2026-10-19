"""Read-only history of every upload through the intake pipelines, for authorised log readers.

Shows record type, uploader, row counts and a timestamped timeline of each stage:
preview, IGP submission and decision, worker stages, both-chain verification,
analysis availability, and each row's evaluation and independent review. No
officer identifiers or row values are returned; only counts, statuses, actors,
reasons and ledger transaction references that are already opaque.
"""
from datetime import datetime

POLICY = 'UPLOAD_PIPELINE_HISTORY_V1'
APPROVAL_STAGES = {'SUBMIT': 'SUBMITTED_FOR_IGP_APPROVAL', 'APPROVE': 'IGP_APPROVED_PROCESSING',
                   'REJECT': 'IGP_REJECTED', 'REQUEST_CHANGES': 'IGP_REQUESTED_CHANGES'}


def when(value):
    return datetime.fromisoformat(value).timestamp()


def person(actor):
    actor = actor or {}
    return {'username': actor.get('username'), 'role': actor.get('role')}


def batch_history(kind, intake, approvals, analysis, batch):
    ident = batch['batch_id']
    events = [{'stage': 'UPLOAD_PREVIEW_RETAINED', 'at': batch['received_at'], 'actor': person(batch['actor']),
               'detail': batch['filename']}]
    if approvals is not None:
        for entry in approvals.journal.rows('BATCH:' + ident):
            stage = APPROVAL_STAGES.get(entry['kind'])
            if stage:
                events.append({'stage': stage, 'at': entry['recorded_at'], 'actor': person(entry.get('actor')),
                               'detail': entry.get('reason'), 'version': entry['version']})
    last = None
    for observation in intake.worker_history(ident):
        key = (observation['state']['status'], observation['state']['phase'])
        if key != last:
            events.append({'stage': 'WORKER_STAGE', 'at': observation['recorded_at'], 'actor': None,
                           'detail': observation['state']['phase'] + ' · ' + observation['state']['status']})
        last = key
    receipt = intake.phase(ident, 'CHAINS_VERIFIED')
    if receipt is not None:
        events.append({'stage': 'BOTH_CHAINS_VERIFIED', 'at': receipt['verification_observed_at'], 'actor': None,
                       'detail': 'Fabric ' + receipt['fabric']['transaction_id'] + ' · Sepolia ' + receipt['public']['transaction_id']})
    activation = analysis.journal.get(ident) if analysis is not None else None
    if activation is not None:
        events.append({'stage': 'CONNECTED_TO_ANALYSIS', 'at': activation['available_at'], 'actor': None, 'detail': None})
    counts = {'ACCEPTED': 0, 'PENDING_REVIEW': 0, 'NOT_ACCEPTED': 0}
    if approvals is not None:
        for row in batch['rows']:
            if row['status'] != 'READY':
                continue
            evaluations = approvals.journal.rows('ROW:' + ident + ':' + str(row['row']))
            for entry in evaluations:
                events.append({'stage': 'ROW_EVALUATED', 'at': entry['recorded_at'], 'actor': None,
                               'detail': 'Row ' + str(row['row']) + ' · ' + entry['result']['status'], 'version': entry['version']})
            if evaluations:
                counts[evaluations[-1]['result']['status']] += 1
            for entry in approvals.journal.rows('REVIEW:' + ident + ':' + str(row['row'])):
                events.append({'stage': 'ROW_REVIEWED', 'at': entry['recorded_at'], 'actor': person(entry.get('actor')),
                               'detail': 'Row ' + str(row['row']) + ' · ' + entry['kind'] + ' · ' + entry['reason'] +
                                         ' · evidence ' + entry['evidence_reference']})
    events.sort(key=lambda e: when(e['at']))
    return {'batch_id': ident, 'record_type': kind[0], 'record_type_label': kind[1], 'filename': batch['filename'],
            'uploader': person(batch['actor']), 'received_at': batch['received_at'], 'source_reference': batch['source_reference'],
            'source_system': batch.get('source_system', 'PF_REGISTRY'), 'file_sha256': batch['file_sha256'],
            'rows': {'total': len(batch['rows']), 'ready': sum(r['status'] == 'READY' for r in batch['rows']),
                     'duplicate': sum(r['status'] == 'DUPLICATE' for r in batch['rows']),
                     'needs_review': sum(r['status'] == 'NEEDS_REVIEW' for r in batch['rows'])},
            'acceptance': counts, 'current_stage': events[-1]['stage'], 'last_event_at': events[-1]['at'], 'events': events}


def history(sources, limit=50):
    """sources: iterable of (kind, intake, approvals, analysis); newest uploads first."""
    from app.intake.dataset_pipeline.registry import dataset
    items = []
    for kind, intake, approvals, analysis in sources:
        for batch in intake.batches(limit=200):
            label = (batch['dataset'], dataset(batch['dataset']).label) if kind is None else kind
            items.append(batch_history(label, intake, approvals, analysis, batch))
    items.sort(key=lambda i: when(i['received_at']), reverse=True)
    types = {}
    for item in items:
        types[item['record_type_label']] = types.get(item['record_type_label'], 0) + 1
    return {'policy': POLICY, 'items': items[:limit], 'total': len(items), 'record_types': dict(sorted(types.items())),
            'basis': 'RETAINED_ENCRYPTED_INTAKE_AND_DECISION_JOURNALS', 'fresh_chain_reads': False}
