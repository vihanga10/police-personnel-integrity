"""Append-only availability joining dual-chain-verified uploads to officer analysis.

An activation is an application observation recorded at its actual time. It
never backdates evidence to upload or effective dates, and it is not an
assertion that a reported action was authorized or that a row is accepted.
"""
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from app.access.store import private
from app.access import research_policy as P
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.historical_source_claims import source_claims, HEADERS as CLAIM_HEADERS
from app.identity.reported_authority_actions import review_actions, ActionReview, ROUTES as AUTHORITY_ROUTES
from app.intake.promotion_pipeline.analysis import AvailabilityJournal
from .core import canonical, check, digest
from .registry import dataset
from .store import DatasetStore

POLICY = 'PUBLISHED_PERSONNEL_INTAKE_ANALYSIS_V1'


class DatasetAvailabilityJournal(AvailabilityJournal):
    POLICY = POLICY


def verified_batch(store, batch):
    """Recompute every binding from retained bytes before analysis may see a row."""
    ident = batch['batch_id']
    visible, receipt = store.phase(ident, 'VISIBLE'), store.phase(ident, 'CHAINS_VERIFIED')
    storage, prepared = store.phase(ident, 'STORAGE_VERIFIED'), store.phase(ident, 'DOCUMENTS_PREPARED')
    check(None not in (visible, receipt, storage, prepared), 'ANALYSIS_PROOF_MISSING')
    payload, manifest = store.publication(batch)
    check(receipt['status'] == 'BOTH_CHAINS_VERIFIED' and receipt['fabric']['status'] == 'FINAL' and
          receipt['public']['status'] == 'FINAL', 'ANALYSIS_BOTH_CHAINS_REQUIRED')
    check(receipt['fabric']['payload'] == payload, 'ANALYSIS_FABRIC_BINDING_DIFFERS')
    check(receipt['public']['payload'] == store.expected_public(payload, receipt), 'ANALYSIS_PUBLIC_BINDING_DIFFERS')
    check(visible == {'publication': payload, 'manifest_sha256': digest(manifest), 'receipt_sha256': digest(receipt),
                      'storage': storage}, 'ANALYSIS_VISIBILITY_BINDING_DIFFERS')
    ready = [r for r in batch['rows'] if r['status'] == 'READY']
    check(storage == {'documents_sha256': digest(prepared['documents']), 'row_count': len(ready)} and
          len(prepared['documents']) == len(ready), 'ANALYSIS_STORAGE_BINDING_DIFFERS')
    for row, document in zip(ready, prepared['documents'], strict=True):
        blob = base64.b64decode(document['ciphertext'], validate=True)
        check(hashlib.sha256(blob).hexdigest() == document['ciphertext_sha256'] and document['batch_id'] == ident and
              document['record_id'] == store.record_id(row) and
              store.open('DELIVERY', document['record_id'], blob) == store.delivery_value(batch, row),
              'ANALYSIS_SOURCE_DOCUMENT_DIFFERS')
    return {'receipt_sha256': digest(receipt), 'visible_sha256': digest(visible), 'manifest_sha256': digest(manifest),
            'dataset': payload['dataset'], 'publication_id': payload['publication_id'],
            'merkle_root': payload['merkle_root'], 'fabric_transaction_id': receipt['fabric']['transaction_id'],
            'public_transaction_id': receipt['public']['transaction_id'],
            'public_contract': receipt['public']['destination']['contract'],
            'verification_observed_at': receipt['verification_observed_at']}


class DatasetAnalysis:
    def __init__(self, workspace, config_file, *, create=False):
        self.workspace = workspace
        self.config_file = private(config_file, repo=workspace.repo)
        self.raw = self.config_file.read_bytes()
        self.config = json.loads(self.raw)
        check(set(self.config) == {'policy', 'intake_config', 'analysis_root'} and self.config['policy'] == POLICY,
              'ANALYSIS_CONFIG_DIFFERS')
        self.runtime_file = private(self.config['intake_config'], repo=workspace.repo)
        self.runtime_raw = self.runtime_file.read_bytes()
        self.runtime = json.loads(self.runtime_raw)
        check(self.runtime['policy'] == 'PERSONNEL_INTAKE_RUNTIME_V1' and
              self.runtime['analysis_config'] == str(self.config_file), 'ANALYSIS_RUNTIME_BINDING_DIFFERS')
        self.intake = DatasetStore(self.runtime['state_root'], self.runtime['key_file'],
                                   self.runtime['backup_key_file'], repo=workspace.repo)
        self.journal = DatasetAvailabilityJournal(self.config['analysis_root'], self.intake.key,
                                                  repo=workspace.repo, create=create)

    def guard(self):
        check(private(self.config_file).read_bytes() == self.raw and
              private(self.runtime_file).read_bytes() == self.runtime_raw, 'ANALYSIS_CONFIG_CHANGED')
        from .configuration import source_files
        check(set(self.runtime['source_pins']) == set(source_files(self.workspace.repo)), 'ANALYSIS_SOURCE_PIN_COVERAGE_DIFFERS')
        for relative, pin in self.runtime['source_pins'].items():
            file = Path(self.workspace.repo) / relative
            check(not file.is_symlink() and hashlib.sha256(file.read_bytes()).hexdigest() == pin, 'ANALYSIS_SOURCE_CHANGED')

    def now(self):
        return datetime.fromtimestamp(self.workspace.clock(), timezone.utc)

    def activate_visible(self, limit=20):
        """Record actual availability once both chains verified; never backdated."""
        self.guard()
        with self.intake.transaction() as c:
            identifiers = [r[0] for r in c.execute("SELECT batch FROM phases WHERE phase='VISIBLE' ORDER BY rowid")]
        check(len(identifiers) <= 1000, 'ANALYSIS_BATCH_LIMIT')
        existing, created = self.journal.identifiers(), []
        for ident in [v for v in identifiers if v not in existing][:limit]:
            batch = self.intake.get(ident)
            binding = verified_batch(self.intake, batch)
            check(P.instant(batch['received_at']) <= P.instant(binding['verification_observed_at']) <= self.now(),
                  'ANALYSIS_OBSERVATION_CLOCK_DIFFERS')
            self.guard()
            created.append(self.journal.append(ident, binding, self.now()))
        return created

    def reports(self, officer, known=None):
        """Verified uploaded rows concerning this officer, visible at the knowledge time."""
        self.guard()
        now = self.now()
        known = now if known is None else known
        check(known <= now, 'ANALYSIS_FUTURE_KNOWLEDGE_FORBIDDEN')
        reports = []
        for batch in self.intake.officer_batches(officer):
            activation = self.journal.get(batch['batch_id'])
            if activation is None or P.instant(activation['available_at']) > known:
                continue
            binding = verified_batch(self.intake, batch)
            check(activation['binding'] == binding, 'ANALYSIS_ACTIVATED_RECEIPT_CHANGED')
            spec = dataset(batch['dataset'])
            for row in batch['rows']:
                roles = [s['role'] for s in row['subjects'] if s['officer_uid'] == officer]
                if row['status'] != 'READY' or not roles:
                    continue
                reports.append({'officer_uid': officer, 'dataset': spec.code, 'filename': spec.filename,
                    'batch_id': batch['batch_id'], 'source_row': row['row'], 'raw_record_id': self.intake.record_id(row),
                    'subject_role': roles[0], 'subject_officer_uid': row['officer_uid'],
                    'subjects': deepcopy(row['subjects']), 'fields': deepcopy(row['source']),
                    'source_system': batch['source_system'], 'received_at': batch['received_at'],
                    'analysis_recorded_at': activation['available_at'],
                    'source_reference_sha256': digest(batch['source_reference']),
                    'publication': deepcopy(binding), 'activation_reference': digest(activation)})
        check(len(reports) <= 5000, 'ANALYSIS_OFFICER_ROW_LIMIT')
        return sorted(reports, key=lambda r: (r['analysis_recorded_at'], r['dataset'], r['raw_record_id']))

    @staticmethod
    def catalog(report, extra_links=()):
        """Catalog item in the same shape the original anchored corpus uses."""
        spec = dataset(report['dataset'])
        fields = report['fields']
        check(set(fields) == set(spec.columns), 'ANALYSIS_COLUMNS_DIFFER')
        # The derived demotion view is SRB-derived evidence, never an independent source.
        reported = 'SRB' if report['source_system'] == 'DERIVED_BAD_CONDUCT_VIEW' else report['source_system']
        provenance = {'reported_source': reported, 'represented_system': report['source_system'],
            'evidence_role': spec.evidence_role, 'source_custody': 'UPLOADER_REPORTED', 'batch_id': report['batch_id'],
            'source_row': report['source_row'], 'received_at': report['received_at'],
            'analysis_recorded_at': report['analysis_recorded_at'], 'activation_reference': report['activation_reference'],
            'publication': report['publication']}
        if spec.evidence_role == 'DERIVED_NON_INDEPENDENT':
            provenance['derived_from'] = 'bad_conduct_register.csv'
        links = [{'officer_uid': report['subject_officer_uid'], 'role': 'officer_nic_no', 'state': 'CANDIDATE_NOT_ACCEPTED'}] \
            if report['subject_officer_uid'] else []
        item = {'raw_record_id': report['raw_record_id'], 'filename': spec.filename, 'classification': 'UNASSESSED',
            'delivery': {'complete': True}, 'candidate_links': links + list(extra_links),
            'original': {'columns': list(spec.columns), 'values': [fields[k] for k in spec.columns]},
            'provenance': provenance, 'assertion': {'reported_row_sha256': digest(fields)}}
        return item, {'activation_reference': report['activation_reference'],
                      'receipt_sha256': report['publication']['receipt_sha256']}

    def extend_history(self, history, officer, reports):
        """Add state-bearing uploads to an officer's recording history at activation time."""
        versions = list(history.versions)
        relevant = [r for r in reports if r['filename'] in CLAIM_HEADERS and r['subject_officer_uid'] == officer]
        if not relevant:
            return history
        for report in relevant:
            item, binding = self.catalog(report)
            raw = report['raw_record_id']
            reference = canonical({'raw_record_id': raw, 'filename': report['filename'],
                'provenance': item['provenance'], 'assertion': item['assertion']}).decode()
            for claim in source_claims(officer, {raw: item}, {raw: [binding]}):
                claim = replace(claim, source_reference=reference)
                versions.append(EvidenceVersion(digest([POLICY, report['activation_reference'], claim.claim_id]),
                    claim, raw, P.instant(report['analysis_recorded_at']), report['activation_reference'],
                    report['publication']['receipt_sha256']))
        check(len(versions) <= 20000, 'ANALYSIS_VERSION_LIMIT')
        end = max(history.coverage_end, *(P.instant(r['analysis_recorded_at']) for r in relevant))
        return RecordingHistory(officer, history.coverage_start, end, POLICY,
            digest({'previous_coverage': history.coverage_digest,
                    'activations': sorted({r['activation_reference'] for r in relevant})}), tuple(versions))

    def actions(self, packet, directory, reports):
        """Reported authority actions of uploaded rows, with exact-NIC actor candidates only."""
        from app.access.operational_authority import action_reference
        candidates = {}
        for officer in directory['officers']:
            candidates.setdefault(officer['nic'].strip().casefold(), []).append(officer['officer_uid'])
        result = {}
        for report in reports:
            routes = AUTHORITY_ROUTES.get(report['filename'], ())
            if not routes:
                continue
            links = [{'officer_uid': u, 'role': column, 'state': 'CANDIDATE_NOT_ACCEPTED'}
                     for _, column, _ in routes if column
                     for u in candidates.get(report['fields'][column].strip().casefold(), [])]
            item, binding = self.catalog(report, links)
            raw = report['raw_record_id']
            actions = review_actions({raw: item}, {raw: [binding]})
            if not actions:
                actions = (ActionReview(routes[0][0], 'CANNOT_VERIFY',
                    ('ACTOR_CLAIM_MISSING', 'REPORTED_DATE_MISSING', 'GOVERNING_RULE_UNASSESSED', 'DELEGATION_EVIDENCE_UNASSESSED'),
                    raw, (), None, '', canonical({'filename': report['filename'], 'provenance': item['provenance'],
                    'assertion': item['assertion']}).decode(), digest(binding)),)
            for action in actions:
                result[action_reference(packet, action)] = action
        return result


def configured_analysis(workspace):
    file = getattr(workspace, 'personnel_intake_config', None)
    if not file:
        return None
    config = json.loads(private(file, repo=workspace.repo).read_bytes())
    return DatasetAnalysis(workspace, config['analysis_config']) if 'analysis_config' in config else None
