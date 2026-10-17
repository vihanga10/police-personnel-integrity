"""Current-session authorization and bounded dataset upload interface.

HQ uploads; a different configured IGP account decides processing and reviews
pending rows. Every call re-checks the signed session, CSRF and scope before
and after reading retained evidence. Nothing here writes personnel sources.
"""
import base64
from datetime import datetime, timezone
from uuid import UUID
from app.access.policy import AccessError
from app.intake.promotion_pipeline.store import PHASES
from .core import IntakeError, check, parse, validate_rows, digest, MAX_BYTES, MAX_ROWS
from .registry import DATASETS, dataset
from .store import REFERENCES

UPLOAD_FIELDS = {'operation_id', 'dataset', 'filename', 'source_reference', 'source_system', 'csv_base64'}


def text(value, low, high, code):
    check(type(value) is str and low <= len(value.strip()) <= high and not any(ord(c) < 32 for c in value), code)
    return value


class DatasetService:
    def __init__(self, research, store, config):
        self.research, self.workspace, self.access = research, research.store, research.access
        self.store, self.config = store, config
        self.approvals = getattr(research, 'dataset_acceptance', None)

    def actor(self, token, csrf=None, *, upload=False):
        with self.access.transaction() as c:
            user, _ = self.access._session(c, token, csrf)
            may_upload = (user['role'] == 'HQ_ADMIN' and user['scope_type'] == 'ALL' and
                          user['user_id'] in self.config['importer_ids'])
            if upload and not may_upload:
                raise AccessError(403, 'DATASET_IMPORT_FORBIDDEN')
            if not upload and not (may_upload or user['role'] == 'IGP' and user['scope_type'] == 'ALL'):
                raise AccessError(403, 'DATASET_IMPORT_INSPECTION_FORBIDDEN')
            return user

    def audit(self, token, action, batch, operation_id):
        logs = getattr(self.workspace, 'accountability', None)
        if logs is None:
            return  # isolated service fixtures only; the runtime requires logs
        from app.access.accountability import ACTIONS
        ACTIONS.add(action)
        actor = logs.actor(token)
        if not actor.get('authenticated'):
            raise AccessError(401, 'LOGIN_REQUIRED')
        logs.append({'action': action, 'phase': 'ADMINISTRATION', 'method': 'POST', 'status': None, 'outcome': 'ALLOWED',
            'actor': actor, 'request_id': None, 'operation_id': operation_id, 'finding_id': None, 'requested_officer_uid': None,
            'session_reference': logs.session_reference(token), 'peer_reference': None, 'reason': None,
            'intake_batch_id': batch['batch_id'], 'intake_dataset': batch['dataset'], 'file_sha256': batch['file_sha256'],
            'row_count': len(batch['rows']), 'basis': 'AUTHENTICATED_RETAINED_INTAKE_OPERATION'})

    def source_state(self):
        with self.access.transaction() as c:
            directory = self.access._directory(c)
        self.store.verify_baseline(self.config['baseline_source_set_sha256'])
        check(directory['source_public_sha256'] == self.config['source_public_sha256'], 'BASELINE_SOURCE_CHANGED')
        return directory

    def officers(self, batch):
        return sorted({o for r in batch['rows'] if r['status'] == 'READY' for o in self.store.row_officers(r)})

    def scoped(self, token, csrf, batch):
        # Scoped full-detail grants remain mandatory for every affected officer.
        for officer in self.officers(batch):
            self.research.authorized(token, officer, csrf=csrf, charge=False)

    def preview(self, token, csrf, request):
        user = self.actor(token, csrf, upload=True)
        check(set(request) == UPLOAD_FIELDS, 'UPLOAD_FIELDS_DIFFER')
        try:
            valid = type(request['operation_id']) is str and str(UUID(request['operation_id'])) == request['operation_id']
        except (ValueError, AttributeError, TypeError):
            valid = False
        check(valid, 'OPERATION_ID_INVALID')
        try:
            spec = dataset(request['dataset'])
        except (ValueError, TypeError):
            raise IntakeError('DATASET_UNSUPPORTED') from None
        check(request['source_system'] in spec.source_systems, 'SOURCE_SYSTEM_NOT_REGISTERED_FOR_DATASET')
        name = request['filename']
        check(type(name) is str and 1 <= len(name) <= 100 and name.endswith('.csv') and '/' not in name and
              '\\' not in name and not any(ord(c) < 32 for c in name), 'CSV_FILENAME_INVALID')
        reference = text(request['source_reference'], 3, 200, 'SOURCE_REFERENCE_REQUIRED')
        check(type(request['csv_base64']) is str and len(request['csv_base64']) <= 4 * ((MAX_BYTES + 2) // 3), 'CSV_SIZE_LIMIT')
        try:
            data = base64.b64decode(request['csv_base64'], validate=True)
        except Exception:
            raise IntakeError('CSV_ENCODING_INVALID') from None
        rows = parse(data, spec)
        directory = self.source_state()
        by_nic = {}
        for officer in directory['officers']:
            by_nic.setdefault(officer['nic'].strip().upper(), []).append(officer['officer_uid'])
        stations = self.store.stations()

        def references(row):
            from app.identity.srb_plan import SourceReference
            out = {}
            for column, filename in REFERENCES.items():
                items = self.store.references(column, row[column]) if row[column].strip() else []
                out[column] = tuple(SourceReference(filename, i['raw_record_id'], UUID(i['officer_uid'])) for i in items
                                    if i['filename'] == filename)
            return out
        now = datetime.fromtimestamp(self.workspace.clock(), timezone.utc)
        results = validate_rows(spec, rows, resolve=lambda nic: by_nic.get(nic.strip().upper(), []),
            existing=self.store.duplicate, stations=stations,
            references=references if spec.filename == 'restriction_overrides.csv' else None, now=now)
        # Recheck authorization and source binding immediately before retention.
        check(self.actor(token, csrf, upload=True) == user, 'ACCOUNT_CHANGED')
        check(self.source_state() == directory, 'DIRECTORY_CHANGED')
        batch = self.store.create(data, {'actor': {'user_id': user['user_id'], 'username': user['username'],
            'account_version': user['version']}, 'received_at': now.isoformat(), 'source_reference': reference.strip(),
            'source_system': request['source_system'], 'dataset': spec.code, 'filename': name,
            'baseline_source_set_sha256': self.config['baseline_source_set_sha256'], 'rows': results}, request['operation_id'])
        check(batch['dataset'] == spec.code, 'RETAINED_FILE_DATASET_DIFFERS')
        self.actor(token, csrf, upload=True)
        self.audit(token, 'DATASET_PREVIEW_RETAINED', batch, request['operation_id'])
        return self.summary(batch)

    def summary(self, batch):
        spec = dataset(batch['dataset'])
        phases = [p for p in PHASES if self.store.phase(batch['batch_id'], p) is not None]
        status = ('NEEDS_REVIEW' if any(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']) else
                  'DUPLICATES_ONLY' if all(r['status'] == 'DUPLICATE' for r in batch['rows']) else
                  phases[-1] if phases else 'PREVIEW_READY')
        receipt = self.store.phase(batch['batch_id'], 'CHAINS_VERIFIED')
        answer = {'batch_id': batch['batch_id'], 'dataset': spec.code, 'dataset_label': spec.label,
            'dataset_filename': spec.filename, 'effect': spec.effect, 'filename': batch['filename'],
            'received_at': batch['received_at'], 'source_reference': batch['source_reference'],
            'source_system': batch['source_system'], 'status': status, 'file_sha256': batch['file_sha256'],
            'ready_rows': sum(r['status'] == 'READY' for r in batch['rows']),
            'duplicate_rows': sum(r['status'] == 'DUPLICATE' for r in batch['rows']),
            'review_rows': sum(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']),
            'rows': [{'row': r['row'], 'status': r['status'], 'issues': r['issues'], 'officer_uid': r['officer_uid'],
                      'subjects': r['subjects'], 'fields': r['source']} for r in batch['rows']],
            'publication': None if receipt is None else {
                'status': 'BOTH_CHAINS_VERIFIED', 'dataset': receipt['fabric']['payload']['dataset'],
                'publication_id': receipt['fabric']['payload']['publication_id'],
                'merkle_root': receipt['fabric']['payload']['merkle_root'], 'observed_at': receipt['verification_observed_at'],
                'fabric_chaincode': receipt['fabric']['destination']['chaincode'],
                'public_contract': receipt['public']['destination']['contract'],
                'fabric_transaction_id': receipt['fabric']['transaction_id'],
                'public_transaction_id': receipt['public']['transaction_id'], 'receipt_basis': 'RETAINED_VERIFICATION_OBSERVATION'},
            'authority': 'NOT_ASSESSED', 'processing_observation': self.store.worker_status(batch['batch_id'])}
        analysis = getattr(self.research, 'dataset_analysis', None)
        if analysis is not None:
            activation = analysis.journal.get(batch['batch_id'])
            answer['analysis_status'] = 'CONNECTED_TO_ANALYSIS' if activation else 'WAITING_FOR_VERIFIED_AVAILABILITY'
            answer['analysis_recorded_at'] = activation['available_at'] if activation else None
        if self.approvals is not None:
            decision = self.approvals.approval(batch)
            answer.update(processing_approval_reference=digest(decision) if decision else None,
                          processing_approval=decision, processing_approval_version=decision['version'] if decision else 0)
            if decision and decision['kind'] != 'APPROVE':
                answer['status'] = {'SUBMIT': 'AWAITING_IGP_APPROVAL', 'REJECT': 'REJECTED',
                                    'REQUEST_CHANGES': 'CHANGES_REQUESTED'}[decision['kind']]
            answer['row_acceptance'] = []
            for r in batch['rows']:
                head = self.approvals.journal.head('ROW:' + batch['batch_id'] + ':' + str(r['row'])) if r['status'] == 'READY' else None
                if head is None:
                    continue
                review = self.approvals.journal.head('REVIEW:' + batch['batch_id'] + ':' + str(r['row']))
                answer['row_acceptance'].append({'row': r['row'], 'status': head['result']['status'],
                    'reasons': head['result']['reasons'], 'effect': head['result']['effect'],
                    'effective_on': head['result']['effective_on'], 'acceptance_basis': head['result'].get('acceptance_basis'),
                    'evaluation_reference': digest(head), 'evaluation_version': head['version'], 'recorded_at': head['recorded_at'],
                    'row_review': None if review is None else {k: review[k] for k in
                        ('kind', 'version', 'recorded_at', 'reason', 'evidence_reference', 'actor')},
                    'row_review_version': review['version'] if review else 0,
                    'row_review_blocked': sorted(set(head['result']['reasons']) & self.approvals.BLOCKING)})
            answer['accepted_rows'] = sum(a['status'] == 'ACCEPTED' for a in answer['row_acceptance'])
            answer['pending_rows'] = sum(a['status'] == 'PENDING_REVIEW' for a in answer['row_acceptance'])
        return answer

    def capabilities(self, token):
        user = self.actor(token)
        try:
            self.actor(token, upload=True)
            upload = True
        except AccessError:
            upload = False
        reviewer = self.approvals is not None and self.approvals.reviewer(user)
        return {'configured': True, 'can_upload': upload, 'can_inspect': True, 'can_approve': reviewer,
            'requires_igp_approval': self.approvals is not None,
            'pending_approval_count': self.approval_count(token) if reviewer else 0,
            'datasets': [{'code': d.code, 'filename': d.filename, 'label': d.label, 'columns': list(d.columns),
                          'source_systems': list(d.source_systems), 'effect': d.effect, 'evidence_role': d.evidence_role,
                          'multi_subject': d.multi_subject} for d in DATASETS.values()],
            'maximum_bytes': MAX_BYTES, 'maximum_rows': MAX_ROWS}

    def decide(self, token, csrf, request):
        user = self.actor(token, csrf)
        if self.approvals is None:
            raise AccessError(503, 'IGP_APPROVAL_NOT_CONFIGURED')
        if not self.approvals.reviewer(user):
            raise AccessError(403, 'IGP_APPROVAL_FORBIDDEN')
        batch = self.store.get(request['batch_id'])
        self.source_state()
        self.scoped(token, csrf, batch)
        check(self.actor(token, csrf) == user, 'ACCOUNT_CHANGED')
        decision = self.approvals.decide(batch, user, request)
        self.approvals.audit_outbox()
        if decision['kind'] == 'APPROVE':
            self.approvals.queue(batch)
        return self.summary(batch)

    def review(self, token, csrf, request):
        user = self.actor(token, csrf)
        if self.approvals is None:
            raise AccessError(503, 'IGP_APPROVAL_NOT_CONFIGURED')
        if not self.approvals.reviewer(user):
            raise AccessError(403, 'IGP_APPROVAL_FORBIDDEN')
        batch = self.store.get(request['batch_id'])
        self.source_state()
        self.scoped(token, csrf, batch)
        check(self.actor(token, csrf) == user, 'ACCOUNT_CHANGED')
        self.approvals.review_row(batch, user, request)
        self.approvals.synchronize()
        self.approvals.audit_outbox()
        return self.summary(batch)

    def commit(self, token, csrf, request):
        user = self.actor(token, csrf, upload=True)
        check(set(request) == {'batch_id', 'file_sha256'}, 'COMMIT_FIELDS_DIFFER')
        batch = self.store.get(request['batch_id'])
        check(batch['actor']['user_id'] == user['user_id'] and batch['actor']['account_version'] == user['version'],
              'UPLOADER_ACCOUNT_CHANGED')
        check(batch['file_sha256'] == request['file_sha256'], 'PREVIEW_FILE_CHANGED')
        self.source_state()
        self.scoped(token, csrf, batch)
        self.actor(token, csrf, upload=True)
        check(self.approvals is not None, 'IGP_APPROVAL_NOT_CONFIGURED')
        self.approvals.request(batch, user)
        self.approvals.audit_outbox()
        return self.summary(batch)

    def resume(self, token, csrf, request):
        user = self.actor(token, csrf, upload=True)
        check(set(request) == {'batch_id', 'file_sha256'}, 'RESUME_FIELDS_DIFFER')
        batch = self.store.get(request['batch_id'])
        check(batch['actor']['user_id'] == user['user_id'] and batch['file_sha256'] == request['file_sha256'],
              'UPLOADER_IDENTITY_DIFFERS')
        self.source_state()
        self.scoped(token, csrf, batch)
        check(self.actor(token, csrf, upload=True) == user, 'ACCOUNT_CHANGED')
        self.audit(token, 'DATASET_IMPORT_REAUTHORIZATION_RECEIVED', batch, batch['batch_id'])
        self.store.renew_authorization(batch['batch_id'], {'user_id': user['user_id'], 'username': user['username'],
                                                           'account_version': user['version']})
        return self.summary(batch)

    def approval_count(self, token):
        user = self.actor(token)
        if self.approvals is None or not self.approvals.reviewer(user):
            return 0
        self.approvals.guard()
        batches = self.store.batches(limit=1000)
        count = sum((self.approvals.approval(b) or {}).get('kind') == 'SUBMIT' for b in batches)
        count += sum(self.approvals.journal.head('ROW:' + b['batch_id'] + ':' + str(r['row'])) is not None and
                     self.approvals.journal.head('ROW:' + b['batch_id'] + ':' + str(r['row']))['result']['status'] == 'PENDING_REVIEW'
                     for b in batches for r in b['rows'] if r['status'] == 'READY')
        check(self.actor(token) == user, 'ACCOUNT_CHANGED')
        return count

    def listing(self, token, offset=0, code=None):
        user = self.actor(token)
        check(type(offset) is int and 0 <= offset <= 1000, 'BATCH_PAGE_INVALID')
        batches = [b for b in self.store.batches(limit=1000) if code is None or b['dataset'] == code]
        if self.approvals is not None and self.approvals.reviewer(user):
            batches.sort(key=lambda b: 0 if (self.approvals.approval(b) or {}).get('kind') == 'SUBMIT' else 1)
        rows = [self.summary(b) for b in batches[offset:offset + 20]]
        check(self.actor(token) == user, 'ACCOUNT_CHANGED')
        return {'items': rows, 'offset': offset, 'total': len(batches),
                'next_offset': offset + len(rows) if offset + len(rows) < len(batches) else None}

    def officer_rows(self, token, officer):
        """Verified uploaded rows for one in-scope officer, each with its retained acceptance outcome."""
        self.research.authorized(token, officer, charge=False)
        analysis = getattr(self.research, 'dataset_analysis', None)
        reports = analysis.reports(officer) if analysis is not None else []
        current = self.approvals.current(officer) if self.approvals is not None and reports else None
        outcomes = {(o['batch_id'], o['source_row']): o for o in (current or {}).get('row_outcomes', [])}
        items = []
        for r in reports:
            spec = dataset(r['dataset'])
            items.append({'batch_id': r['batch_id'], 'source_row': r['source_row'], 'raw_record_id': r['raw_record_id'],
                'dataset': spec.code, 'dataset_label': spec.label, 'filename': spec.filename, 'fields': r['fields'],
                'subject_role': r['subject_role'], 'source_system': r['source_system'], 'received_at': r['received_at'],
                'analysis_recorded_at': r['analysis_recorded_at'], 'publication': r['publication'],
                'outcome': outcomes.get((r['batch_id'], r['source_row']))})
        self.research.authorized(token, officer, charge=False)
        return {'items': items, 'current': current, 'authority': 'ROW_LEVEL_ASSESSMENT',
                'source_records_preserved': True, 'fresh_chain_reads': False}
