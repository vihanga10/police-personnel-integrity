"""Bounded CSV validation and opaque dataset-bound batch commitments.

Validation establishes a supported, linkable source report for one registered
dataset. It never establishes authority, accepted state or source truth. Exact
source text survives parsing. No networking or storage access happens here.
"""
import csv
import io
from datetime import date
from uuid import UUID
from app.identity.reported_authority_actions import ROUTES as AUTHORITY_ROUTES
from app.intake.promotion_pipeline.core import IntakeError, check, canonical, digest, opaque, merkle
from .registry import dataset, source_key, subject_nics, planner_issues

POLICY = 'PERSONNEL_INTAKE_V1'
FABRIC_POLICY = 'PERSONNEL_INTAKE_FABRIC_ANCHOR_V1'
PUBLIC_POLICY = 'PERSONNEL_INTAKE_PUBLIC_ANCHOR_V1'
NAMESPACE = 'personnel-intake-anchor-v1'
MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 1000
MAX_FIELD = 4000
MAX_SUBJECTS = 50


def parse(data, spec):
    """Strict UTF-8 CSV with the exact registered header and no control bytes."""
    check(type(data) is bytes and 0 < len(data) <= MAX_BYTES, 'CSV_SIZE_LIMIT')
    try:
        content = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise IntakeError('CSV_UTF8_REQUIRED') from None
    check('\x00' not in content, 'CSV_NUL_FORBIDDEN')
    reader = csv.reader(io.StringIO(content, newline=''), strict=True)
    try:
        header = next(reader)
        check(tuple(header) == spec.columns, 'CSV_HEADER_DIFFERS')
        rows = []
        for values in reader:
            check(len(rows) < MAX_ROWS, 'CSV_ROW_LIMIT')
            check(len(values) == len(spec.columns), 'CSV_COLUMN_COUNT_DIFFERS')
            check(all(len(v) <= MAX_FIELD for v in values), 'CSV_FIELD_LIMIT')
            check(all(not any(ord(c) < 32 and c not in '\r\n\t' for c in v) for v in values), 'CSV_CONTROL_CHARACTER')
            rows.append(dict(zip(spec.columns, values)))
        check(rows, 'CSV_EMPTY')
        return rows
    except (csv.Error, StopIteration):
        raise IntakeError('CSV_MALFORMED') from None


def _future_action_dates(spec, row, today):
    """A reported signing/recording date after intake cannot already be an issued act."""
    issues = []
    for _, _, column in AUTHORITY_ROUTES.get(spec.filename, ()):
        text = row.get(column, '').strip() if column else ''
        try:
            if text and date.fromisoformat(text) > today:
                issues.append(column + ':FUTURE_ACTION_DATE')
        except ValueError:
            pass  # the planner reports unusable dates
    return issues


def validate_rows(spec, rows, *, resolve, existing, stations, references, now):
    """Callbacks use the signed directory and provisioned indexes; no client UID.

    A single row needing review blocks the batch. Exact duplicates of retained
    or original rows are reported, not delivered again. A changed row under an
    existing source identity is a conflict and needs a corrected file.
    """
    output, seen = [], set()
    for number, row in enumerate(rows, 1):
        result = {'row': number, 'status': 'READY', 'issues': [], 'officer_uid': None,
                  'subjects': [], 'source_key': None, 'source': row}
        key = source_key(spec, row)
        if key is None:
            result['issues'].append('SOURCE_ID_REQUIRED')
        else:
            key = spec.code + '\x1e' + key
            if key in seen:
                result['issues'].append('DUPLICATE_ID_IN_FILE')
            seen.add(key)
            result['source_key'] = key
        nics, issues = subject_nics(spec, row)
        result['issues'].extend(issues)
        check(len(nics) <= MAX_SUBJECTS, 'SUBJECT_LIMIT')
        subjects = {}
        for nic, role in nics:
            found = resolve(nic)
            if len(found) != 1:
                result['issues'].append(role + (':OFFICER_NOT_FOUND' if not found else ':OFFICER_AMBIGUOUS'))
                continue
            check(str(UUID(found[0])) == found[0], 'RESOLVER_ID_INVALID')
            subjects.setdefault(found[0], role)
        result['subjects'] = [{'officer_uid': u, 'role': r} for u, r in sorted(subjects.items())]
        if not spec.multi_subject and len(subjects) == 1:
            result['officer_uid'] = next(iter(subjects))
        complete = not result['issues'] and (spec.multi_subject or result['officer_uid'] is not None)
        if complete:
            # Actor NICs become candidates only on one exact directory match.
            actors = {}
            for column in spec.actor_columns:
                text = row[column].strip().upper()
                found = resolve(text) if text else []
                if len(found) == 1:
                    actors[column] = UUID(found[0])
            try:
                result['issues'].extend(planner_issues(spec, row, result['officer_uid'], stations=stations,
                    actors=actors, references=references(row) if references else None))
            except ValueError:
                result['issues'].append('SOURCE_ROW_SHAPE_UNSUPPORTED')
            result['issues'].extend(_future_action_dates(spec, row, now.date()))
            if key is not None:
                prior = existing(key, result['officer_uid'], row)
                check(prior in {'ABSENT', 'IDENTICAL', 'CONFLICT'}, 'DUPLICATE_CHECK_INVALID')
                if prior == 'CONFLICT':
                    result['issues'].append('SOURCE_ID_CONFLICT')
                elif prior == 'IDENTICAL' and not result['issues']:
                    result['status'] = 'DUPLICATE'
        if result['issues']:
            result['status'] = 'NEEDS_REVIEW'
        result['issues'] = sorted(set(result['issues']))
        output.append(result)
    return output


def leaf(key, batch, row):
    return opaque(key, 'ROW', {'dataset': batch['dataset'], 'subjects': row['subjects'], 'source': row['source'],
        'row': row['row'], 'file_sha256': batch['file_sha256'], 'received_at': batch['received_at']})


def publication(key, batch):
    """Dataset-coded Fabric payload; all other values are keyed opaque digests."""
    spec = dataset(batch['dataset'])
    ready = [r for r in batch['rows'] if r['status'] == 'READY']
    check(ready and not any(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']), 'BATCH_NOT_PUBLISHABLE')
    leaves = [leaf(key, batch, r) for r in ready]
    manifest = {'policy': POLICY, 'dataset': spec.code, 'filename': spec.filename, 'batch_id': batch['batch_id'],
        'file_sha256': batch['file_sha256'], 'received_at': batch['received_at'], 'actor': batch['actor'],
        'source_reference': batch['source_reference'], 'source_system': batch['source_system'],
        'evidence_role': spec.evidence_role, 'rows': leaves, 'row_count': len(leaves),
        'duplicate_count': sum(r['status'] == 'DUPLICATE' for r in batch['rows']),
        'authority': 'NOT_ASSESSED', 'source_custody': 'UPLOADER_REPORTED'}
    return {'policy': FABRIC_POLICY, 'namespace': NAMESPACE, 'dataset': spec.code,
        'publication_id': opaque(key, 'BATCH', batch['batch_id']),
        'public_sha256': opaque(key, 'MANIFEST', manifest), 'merkle_root': merkle(leaves),
        'publication_commitment': opaque(key, 'PUBLICATION', manifest)}, manifest


def expected_public(payload, result):
    """Exact Sepolia payload: binds the verified Fabric receipt and destination."""
    return {'policy': PUBLIC_POLICY, 'namespace': NAMESPACE, 'dataset': payload['dataset'],
        'publication_id': payload['publication_id'], 'public_sha256': payload['public_sha256'],
        'merkle_root': payload['merkle_root'], 'fabric_destination_sha256': digest(result['fabric']['destination']),
        'fabric_transaction_id': result['fabric']['transaction_id'], 'fabric_receipt_sha256': digest(result['fabric'])}


__all__ = ['POLICY', 'FABRIC_POLICY', 'PUBLIC_POLICY', 'NAMESPACE', 'MAX_BYTES', 'MAX_ROWS', 'IntakeError', 'check',
           'canonical', 'digest', 'opaque', 'parse', 'validate_rows', 'publication', 'expected_public', 'leaf']
