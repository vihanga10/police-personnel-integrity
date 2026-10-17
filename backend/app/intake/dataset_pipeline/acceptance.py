"""Independent dataset approval and append-only, evidence-derived row acceptance.

Batch approval authorizes processing of one exact upload. Each verified row is
then evaluated separately: ACCEPTED only when its dataset checks pass and any
reported authority is VALID, or when an independent IGP row review resolves a
non-blocking uncertainty. Accepted dated effects alter the displayed current
state only from their reported effective date. Source records never change.
"""
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo
import json
from uuid import UUID
from app.access import research_policy as P
from app.access.store import private
from app.identity.service_values import RANKS
from app.intake.promotion_pipeline.approvals import ApprovalEngine, DecisionJournal, ORDER, stamp
from .core import check, digest
from .registry import dataset

POLICY = 'PERSONNEL_INTAKE_APPROVAL_V1'
TRUE = {'TRUE', 'YES', 'Y', '1'}


def reported_day(text):
    try:
        return date.fromisoformat(text.strip()) if text.strip() else None
    except ValueError:
        return None


class DatasetApprovals(ApprovalEngine):
    # Evidence conflicts and broken sequences are never resolved by a reviewer.
    BLOCKING = frozenset({'IGP_PROCESSING_APPROVAL_REQUIRED', 'EFFECTIVE_DATE_REQUIRED', 'INTERVAL_ORDER_INVALID',
        'EARLIER_POSTING_CHANGE_REQUIRES_REVIEW', 'FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE',
        'MULTIPLE_UPLOADED_TRANSFERS_AT_SAME_EFFECTIVE_DATE', 'CONFLICTING_ORIGINAL_TRANSFER_AT_EFFECTIVE_DATE',
        'MULTIPLE_UPLOADED_NUMBERS_AT_SAME_EFFECTIVE_DATE', 'OVERLAPPING_ORIGINAL_NUMBER_INTERVAL',
        'OVERRIDDEN_RESTRICTION_NOT_FOUND', 'UPSTREAM_PUNISHMENT_NOT_FOUND', 'DEMOTION_RANK_EVIDENCE_UNRESOLVED',
        'DEMOTION_MUST_DECREASE_RANK'})

    def __init__(self, workspace, analysis, file, *, create=False):
        check(analysis is not None, 'DATASET_ANALYSIS_REQUIRED')
        self.workspace, self.analysis, self.intake = workspace, analysis, analysis.intake
        self.file = private(file, repo=workspace.repo)
        self.raw = self.file.read_bytes()
        self.config = json.loads(self.raw)
        check(set(self.config) == {'policy', 'decision_root', 'reviewer_ids', 'legacy_queued'} and
              self.config['policy'] == POLICY and self.config['legacy_queued'] == {}, 'APPROVAL_CONFIG_DIFFERS')
        check(type(self.config['reviewer_ids']) is list and 0 < len(self.config['reviewer_ids']) <= 5,
              'EXPLICIT_IGP_REVIEWERS_REQUIRED')
        for ident in self.config['reviewer_ids']:
            check(str(UUID(ident)) == ident, 'REVIEWER_ID_INVALID')
        self.journal = DecisionJournal(self.config['decision_root'], self.intake.key, repo=workspace.repo, create=create)

    def today(self):
        return datetime.fromtimestamp(self.workspace.clock(), timezone.utc).astimezone(ZoneInfo('Asia/Colombo')).date()

    def context(self, officer):
        from app.access.full_source_profiles import profile
        with self.workspace.access.transaction() as c:
            directory = self.workspace.access._directory(c)
        source = profile(self.workspace, officer, directory['source_public_sha256'])
        return directory, source

    def evaluate_officer(self, officer):
        """Deterministic evaluation of every verified uploaded row concerning one officer."""
        self.guard()
        reports = self.analysis.reports(officer)
        if not reports:
            return []
        packet = self.workspace.get_packet(officer)
        directory, source = self.context(officer)
        originals = source['full_records']
        service = [r for r in originals if r['dataset'] == 'officer_service_information.csv']
        baseline = service[0]['fields'] if len(service) == 1 else {}
        today = self.today()

        def original(name):
            return [r['fields'] for r in originals if r['dataset'] == name]
        own = [r for r in reports if r['subject_officer_uid'] == officer]
        uploaded = lambda name: [r['fields'] for r in own if r['filename'] == name]
        restriction_ids = {f['restriction_id'].strip() for f in original('officer_restrictions.csv') + uploaded('officer_restrictions.csv')}
        punishments = {f['punishment_id'].strip(): f.get('reduction_in_rank_enacted', '').strip().upper() in TRUE
                       for f in original('bad_conduct_register.csv') + uploaded('bad_conduct_register.csv')}
        same_day = {}
        for r in own:
            spec = dataset(r['dataset'])
            if spec.effect in ('POSTING', 'POLICE_NUMBER'):
                group = (spec.effect, r['fields'].get('number_type', '').strip(), r['fields'][spec.effective_column].strip())
                same_day[group] = same_day.get(group, 0) + 1
        station = baseline.get('current_station_code', '').strip() or None
        base_rank = RANKS.get(baseline.get('current_rank', '').strip())
        blocked, results = set(), []

        def order(r):
            spec = dataset(r['dataset'])
            when = r['fields'][spec.effective_column].strip() if spec.effective_column else ''
            return (spec.effect in ('RESTRICTION_OVERRIDE', 'RANK'), when, r['dataset'], r['raw_record_id'])
        for report in sorted(reports, key=order):
            spec = dataset(report['dataset'])
            batch = self.intake.get(report['batch_id'])
            decision = self.approval(batch)
            f, issues = report['fields'], []
            subject = report['subject_officer_uid'] == officer
            if decision is None or decision['kind'] != 'APPROVE':
                issues.append('IGP_PROCESSING_APPROVAL_REQUIRED')
            effective = reported_day(f[spec.effective_column]) if spec.effective_column else None
            if spec.effective_column and effective is None:
                issues.append('EFFECTIVE_DATE_REQUIRED')
            applies = spec.effect != 'RECORD'
            if spec.effect == 'POSTING':
                if 'POSTING' in blocked:
                    issues.append('EARLIER_POSTING_CHANGE_REQUIRES_REVIEW')
                if station is None or f['from_station_code'].strip() != station:
                    issues.append('FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE')
                if same_day.get(('POSTING', '', f['effective_date'].strip()), 0) > 1:
                    issues.append('MULTIPLE_UPLOADED_TRANSFERS_AT_SAME_EFFECTIVE_DATE')
                if any(o['effective_date'].strip() == f['effective_date'].strip() and
                       o['to_station_code'].strip() != f['to_station_code'].strip() for o in original('transfer_history.csv')):
                    issues.append('CONFLICTING_ORIGINAL_TRANSFER_AT_EFFECTIVE_DATE')
                if baseline.get('service_status') != 'Active':
                    issues.append('SERVICE_STATUS_REQUIRES_REVIEW')
                if f['is_cancelled'].strip().upper() in TRUE or f['cancellation_date'].strip() or f['cancellation_ref'].strip():
                    # A reported cancellation is accepted as a record without a posting effect.
                    applies = False
            elif spec.effect == 'POLICE_NUMBER':
                end = reported_day(f['valid_to'])
                if f['valid_to'].strip() and (end is None or (effective and end < effective)):
                    issues.append('INTERVAL_ORDER_INVALID')
                if same_day.get(('POLICE_NUMBER', f['number_type'].strip(), f['valid_from'].strip()), 0) > 1:
                    issues.append('MULTIPLE_UPLOADED_NUMBERS_AT_SAME_EFFECTIVE_DATE')
                for o in original('officer_police_numbers.csv'):
                    start, stop = reported_day(o['valid_from']), reported_day(o['valid_to'])
                    # An open earlier interval is superseded; a closed overlapping one conflicts.
                    if (o['number_type'].strip() == f['number_type'].strip() and o['police_no'].strip() != f['police_no'].strip()
                            and effective and start and stop and start <= effective <= stop):
                        issues.append('OVERLAPPING_ORIGINAL_NUMBER_INTERVAL')
            elif spec.effect == 'RESTRICTION':
                end = reported_day(f['restriction_removal_date'])
                if f['restriction_removal_date'].strip() and (end is None or (effective and end < effective)):
                    issues.append('INTERVAL_ORDER_INVALID')
            elif spec.effect == 'RESTRICTION_OVERRIDE':
                if f['restriction_id'].strip() not in restriction_ids:
                    issues.append('OVERRIDDEN_RESTRICTION_NOT_FOUND')
            elif spec.effect == 'SERVICE_SNAPSHOT':
                issues.append('SERVICE_SNAPSHOT_REPLACEMENT_REQUIRES_REVIEW')
            elif spec.effect == 'RANK':
                issues.append('DERIVED_NON_INDEPENDENT_SOURCE')
                if not punishments.get(f['punishment_id'].strip(), False):
                    issues.append('UPSTREAM_PUNISHMENT_NOT_FOUND')
                floor = RANKS.get(f['floor_rank'].strip())
                if floor is None or base_rank is None or floor not in ORDER or base_rank not in ORDER:
                    issues.append('DEMOTION_RANK_EVIDENCE_UNRESOLVED')
                elif ORDER.index(floor) <= ORDER.index(base_rank):
                    issues.append('DEMOTION_MUST_DECREASE_RANK')
            authority = {'status': 'NOT_APPLICABLE', 'actions': []}
            if spec.authority_actions and subject:
                authority = self.authority(packet, directory, report)
                if authority['status'] != 'VALID':
                    issues.extend(v for a in authority['actions'] for v in a['reasons'])
                    issues.append('AUTHORITY_' + authority['status'])
            elif spec.authority_actions:
                # A shared record's reported commander is not assessed per participant.
                issues.extend(('AUTHORITY_CANNOT_VERIFY', 'MULTI_SUBJECT_AUTHORITY_NOT_EVALUATED'))
            check(P.instant(report['analysis_recorded_at']) <= datetime.fromtimestamp(self.workspace.clock(), timezone.utc),
                  'ACCEPTANCE_CLOCK_DIFFERS')
            status = 'NOT_ACCEPTED' if authority['status'] == 'INVALID' else 'PENDING_REVIEW' if issues else 'ACCEPTED'
            # Shared rows bind only shared evidence so every participant sees one evaluation.
            evidence = {k: v for k, v in report.items() if k not in ('officer_uid', 'subject_role')}
            binding = digest(dict(report=evidence, decision=decision, **(dict(source_profile=P.fingerprint(source),
                packet=P.fingerprint(packet), baseline=baseline) if subject else {})))
            status, review = self.reviewed(report['batch_id'], report['source_row'], status, issues, binding)
            if spec.effect in ('POSTING', 'RANK'):
                if status != 'ACCEPTED':
                    blocked.add(spec.effect)
                elif spec.effect == 'POSTING' and applies:
                    station = f['to_station_code'].strip()
            results.append(dict(batch_id=report['batch_id'], source_row=report['source_row'], raw_record_id=report['raw_record_id'],
                dataset=spec.code, officer_uid=report['subject_officer_uid'], status=status, reasons=sorted(set(issues)),
                authority=authority, effect=spec.effect if applies else 'NONE',
                effective_on=effective.isoformat() if effective else None,
                effective_now=bool(applies and (effective is None or effective <= today)),
                binding=binding, igp_decision_reference=digest(decision) if decision else None,
                publication=report['publication'], **review))
        check(self.analysis.reports(officer) == reports, 'DATASET_REPORTS_CHANGED_DURING_ACCEPTANCE')
        check(self.context(officer) == (directory, source) and self.workspace.get_packet(officer) == packet,
              'SOURCE_CHANGED_DURING_ACCEPTANCE')
        for result in results:
            decision = self.approval(self.intake.get(result['batch_id']))
            check((digest(decision) if decision else None) == result['igp_decision_reference'], 'IGP_DECISION_CHANGED_DURING_ACCEPTANCE')
        return results

    def synchronize(self, limit=20):
        """Retain changed evaluations; shared rows are evaluated once per participant officer."""
        self.guard()
        for batch in self.intake.batches(limit=1000):
            decision = self.approval(batch)
            if decision and decision['kind'] == 'APPROVE' and self.intake.phase(batch['batch_id'], 'QUEUED') is None:
                self.queue(batch)
        officers = set()
        for ident in sorted(self.analysis.journal.identifiers()):
            batch = self.intake.get(ident)
            if self.approval(batch):
                officers.update(o for r in batch['rows'] if r['status'] == 'READY' for o in self.intake.row_officers(r))
        ordered = sorted(officers)
        start = getattr(self, 'cursor', 0) % max(1, len(ordered))
        selected = (ordered[start:] + ordered[:start])[:limit]
        self.cursor = start + len(selected)
        for officer in selected:
            for result in self.evaluate_officer(officer):
                subject = 'ROW:' + result['batch_id'] + ':' + str(result['source_row'])
                previous = self.journal.head(subject)
                stable = {k: v for k, v in result.items() if k != 'effective_now'}
                if previous and previous['result'] == stable:
                    continue
                decision = self.approval(self.intake.get(result['batch_id']))
                if result['status'] == 'ACCEPTED' and (not previous or previous['result']['status'] != 'ACCEPTED'):
                    self.live_reviewer(decision)
                self.journal.append(subject, 'evaluation:' + subject + ':' + str(previous['version'] + 1 if previous else 1) + ':' + digest(stable),
                    previous['version'] if previous else 0, dict(kind='DATASET_ROW_ACCEPTANCE', batch_id=result['batch_id'],
                    actor=decision['actor'] if decision else {}, recorded_at=stamp(self.workspace),
                    reason='Evidence-derived dataset row acceptance evaluation', result=stable))
        self.audit_outbox()

    def affected_officers(self):
        """Subjects of retained evaluations whose accepted state may change a displayed field."""
        return {o for o in super().affected_officers() if o is not None}

    def current(self, officer):
        """Accepted, retained and currently effective evidence; scheduled effects stay separate."""
        results = self.evaluate_officer(officer)
        reports = {(r['batch_id'], r['source_row']): r for r in self.analysis.reports(officer)} if results else {}
        outcomes, accepted, scheduled, pending = [], [], [], 0
        for result in results:
            head = self.journal.head('ROW:' + result['batch_id'] + ':' + str(result['source_row']))
            stable = {k: v for k, v in result.items() if k != 'effective_now'}
            retained = head is not None and head['result'] == stable
            report = reports[(result['batch_id'], result['source_row'])]
            outcome = dict(batch_id=result['batch_id'], source_row=result['source_row'], dataset=result['dataset'],
                status=result['status'] if retained else 'EVALUATION_NOT_YET_RETAINED', reasons=result['reasons'],
                effect=result['effect'], effective_on=result['effective_on'], effective_now=result['effective_now'],
                acceptance_basis=result.get('acceptance_basis', 'EVIDENCE_CHECKS' if result['status'] == 'ACCEPTED' else None),
                decision_reference=digest(head) if retained else None, decision_version=head['version'] if head else 0,
                subject_role=report['subject_role'], decision_retained=retained)
            outcomes.append(outcome)
            if not retained or result['status'] != 'ACCEPTED':
                pending += result['status'] != 'NOT_ACCEPTED' or not retained
                continue
            item = dict(dataset=result['dataset'], effective_on=result['effective_on'], fields=report['fields'],
                        acceptance_reference=digest(head), accepted_at=head['recorded_at'], effect=result['effect'],
                        officer_uid=result['officer_uid'])
            if result['effect'] != 'NONE' and not result['effective_now']:
                scheduled.append({k: item[k] for k in ('dataset', 'effective_on', 'acceptance_reference', 'effect')})
            elif result['officer_uid'] == officer:
                accepted.append(item)
        return {'policy': POLICY, 'projection': self.project(accepted), 'scheduled_effects': scheduled,
                'pending_rows': pending, 'row_outcomes': outcomes, 'source_records_preserved': True}

    def project(self, accepted):
        """Latest effective accepted value per state dimension; never edits source rows."""
        def latest(effect, key=None):
            items = [a for a in accepted if a['effect'] == effect]
            if key:
                groups = {}
                for a in items:
                    groups.setdefault(key(a), []).append(a)
                return [max(v, key=lambda a: (a['effective_on'] or '', a['accepted_at'])) for _, v in sorted(groups.items())]
            return max(items, key=lambda a: (a['effective_on'] or '', a['accepted_at'])) if items else None
        posting = latest('POSTING')
        demotion = latest('RANK')
        snapshot = max((a for a in accepted if a['effect'] == 'SERVICE_SNAPSHOT'), key=lambda a: a['accepted_at'], default=None)
        overridden = {a['fields']['restriction_id'].strip() for a in accepted if a['effect'] == 'RESTRICTION_OVERRIDE'}
        today = self.today().isoformat()
        restrictions = [a for a in accepted if a['effect'] == 'RESTRICTION' and a['fields']['restriction_id'].strip() not in overridden
                        and not (a['fields']['restriction_removal_date'].strip() and a['fields']['restriction_removal_date'].strip() <= today)]
        ref = lambda a: {'effective_on': a['effective_on'], 'acceptance_reference': a['acceptance_reference'], 'accepted_at': a['accepted_at']}
        return {
            'posting': None if posting is None else dict(ref(posting), **{k: posting['fields'][k].strip() for k in
                ('to_station_code', 'to_station_name', 'to_unit_type', 'to_unit_name', 'to_division', 'to_province')}),
            'police_numbers': [dict(ref(a), number_type=a['fields']['number_type'].strip(), police_no=a['fields']['police_no'].strip())
                               for a in latest('POLICE_NUMBER', key=lambda a: a['fields']['number_type'].strip())],
            'demotion': None if demotion is None else dict(ref(demotion), floor_rank=demotion['fields']['floor_rank'].strip(),
                rank_code=RANKS.get(demotion['fields']['floor_rank'].strip())),
            'service_snapshot': None if snapshot is None else dict(ref(snapshot), fields=snapshot['fields']),
            'active_restrictions': [dict(ref(a), restriction_id=a['fields']['restriction_id'].strip(),
                category=a['fields']['restriction_category'].strip(), effect=a['fields']['restriction_effect'].strip())
                for a in restrictions],
        }

    def audit_outbox(self):
        logs = getattr(self.workspace, 'accountability', None)
        if logs is None:
            return
        from app.access.accountability import ACTIONS
        ACTIONS.add('PERSONNEL_INTAKE_DECISION_RETAINED')
        for seq, value in self.journal.pending_audit():
            a = value['actor']
            logseq = logs.append(dict(action='PERSONNEL_INTAKE_DECISION_RETAINED', phase='ADMINISTRATION', method='WORKER',
                status=None, outcome='ALLOWED', actor=dict(user_id=a.get('user_id'), username=a.get('username'),
                role=a.get('role'), scope_type=a.get('scope_type'), scope_id=a.get('scope_id'), account_version=a.get('version'),
                authenticated=False, authentication_state='RETAINED_DECISION_OUTBOX'), request_id=None,
                operation_id=value.get('operation_id'), finding_id=None,
                requested_officer_uid=value.get('result', {}).get('officer_uid'), session_reference=None, peer_reference=None,
                reason=value['kind'], intake_batch_id=value['batch_id'], intake_decision_reference=digest(value),
                intake_decision_version=value['version'], intake_decision_recorded_at=value['recorded_at'],
                intake_decision_status=value.get('result', {}).get('status'), intake_decision_reason=value['reason']))
            self.journal.ack(seq, logseq)


def configured_approvals(workspace, analysis):
    if analysis is None:
        return None
    file = analysis.runtime.get('approval_config')
    return DatasetApprovals(workspace, analysis, file) if file else None
