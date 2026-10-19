"""Bounded promotion CSV validation and opaque batch commitments.

Validation establishes a supported source report, never promotion authority or
accepted current rank. Exact source text survives parsing. No networking here.
"""
import csv
import hashlib
import hmac
import io
import json
import re
from datetime import date
from uuid import UUID
from app.identity.inspect_history_sources import HEADERS
from app.identity.history_plan import plan_history
from app.identity.service_values import RANKS

POLICY = 'PROMOTION_INTAKE_V1'
COLUMNS = HEADERS['promotion_history.csv']
MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 1000
MAX_FIELD = 4000

class IntakeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def check(value, code):
    if not value:
        raise IntakeError(code)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def opaque(key, domain, value):
    check(type(key) is bytes and len(key) == 32, 'COMMITMENT_KEY_REQUIRED')
    return hmac.new(key, canonical([POLICY, domain, value]), hashlib.sha256).hexdigest()

def parse(data):
    check(type(data) is bytes and 0 < len(data) <= MAX_BYTES, 'CSV_SIZE_LIMIT')
    try:
        content = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise IntakeError('CSV_UTF8_REQUIRED') from None
    check('\x00' not in content, 'CSV_NUL_FORBIDDEN')
    reader = csv.reader(io.StringIO(content, newline=''), strict=True)
    try:
        header = next(reader)
        check(tuple(header) == COLUMNS, 'CSV_HEADER_DIFFERS')
        rows = []
        for values in reader:
            check(len(rows) < MAX_ROWS, 'CSV_ROW_LIMIT')
            check(len(values) == len(COLUMNS), 'CSV_COLUMN_COUNT_DIFFERS')
            check(all(len(v) <= MAX_FIELD for v in values), 'CSV_FIELD_LIMIT')
            check(all(not any(ord(c) < 32 and c not in '\r\n\t' for c in v) for v in values), 'CSV_CONTROL_CHARACTER')
            rows.append(dict(zip(COLUMNS, values)))
        check(rows, 'CSV_EMPTY')
        return rows
    except (csv.Error, StopIteration):
        raise IntakeError('CSV_MALFORMED') from None

def validate_rows(rows, resolve, existing, *, now):
    """Callbacks use authenticated connected records; no user-supplied UID.

    A single bad row blocks the batch. Exact duplicates are reported, not
    delivered again. Changed values under an existing source ID need review.
    """
    output = []
    seen = set()
    for number, row in enumerate(rows, 1):
        result = {'row': number, 'status': 'READY', 'issues': [], 'officer_uid': None,
                  'source': row}
        source_id = row['promotion_id'].strip()
        if not source_id or len(source_id) > 128:
            result['issues'].append('PROMOTION_ID_REQUIRED')
        elif source_id in seen:
            result['issues'].append('DUPLICATE_ID_IN_FILE')
        seen.add(source_id)
        nic = row['officer_nic_no'].strip()
        if not re.fullmatch(r'(?:[0-9]{9}[VX]|[0-9]{12})', nic):
            result['issues'].append('NIC_FORMAT_UNSUPPORTED')
            candidates = []
        else:
            candidates = resolve(nic)
        if len(candidates) != 1:
            result['issues'].append('OFFICER_NOT_FOUND' if not candidates else 'OFFICER_AMBIGUOUS')
        else:
            officer = candidates[0]
            check(str(UUID(officer)) == officer, 'RESOLVER_ID_INVALID')
            result['officer_uid'] = officer
            plan = plan_history('promotion_history.csv', row, officer_uid=UUID(officer))
            result['issues'].extend(plan.review_issues)
            for field in plan.fields:
                if field.status == 'REVIEW_REQUIRED':
                    result['issues'].extend(field.source_column + ':' + v for v in field.issues)
            order=('IGP','SDIG','DIG','SSP','SP','ASP','CIP','IP','SI','PS_C1','PS_C2','PC_C1','PC_C2','PC_C3','PC_C4','PC')
            old,new=RANKS.get(row['from_rank'].strip()),RANKS.get(row['to_rank'].strip())
            if old in order and new in order and order.index(new)>order.index(old):result['issues'].append('REPORTED_PROMOTION_RANK_ORDER_REQUIRES_REVIEW')
            if row['from_rank'].strip() == row['to_rank'].strip():
                result['issues'].append('RANK_CHANGE_REQUIRED')
            # A future reported order can be retained only through later review;
            # unattended intake must not make it look like an already issued order.
            for field in ('promotion_order_date', 'promotion_authority_signed_date'):
                try:
                    if row[field].strip() and date.fromisoformat(row[field].strip()) > now.date():
                        result['issues'].append(field + ':FUTURE_ORDER_DATE')
                except ValueError:
                    pass  # parser already reports the invalid date
            prior = existing(source_id, officer, row)
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

def merkle(leaves):
    check(bool(leaves) and all(re.fullmatch('[0-9a-f]{64}', v) for v in leaves), 'MERKLE_LEAVES_INVALID')
    level = [hashlib.sha256(b'\x00' + bytes.fromhex(v)).digest() for v in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b'\x01' + level[i] + level[i+1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()

def publication(key, batch):
    accepted = [r for r in batch['rows'] if r['status'] == 'READY']
    check(accepted and not any(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']), 'BATCH_NOT_PUBLISHABLE')
    leaves = [opaque(key, 'ROW', {'officer_uid': r['officer_uid'], 'source': r['source'],
        'row': r['row'], 'file_sha256': batch['file_sha256'], 'received_at': batch['received_at']}) for r in accepted]
    manifest = {'policy': POLICY, 'batch_id': batch['batch_id'], 'file_sha256': batch['file_sha256'],
        'received_at': batch['received_at'], 'actor': batch['actor'], 'source_reference': batch['source_reference'],
        'source_system': 'PF_REGISTRY', 'rows': leaves, 'row_count': len(leaves),
        'duplicate_count': sum(r['status'] == 'DUPLICATE' for r in batch['rows']),
        'authority': 'NOT_ASSESSED', 'source_custody': 'UPLOADER_REPORTED'}
    return {'policy': 'PROMOTIONS_FABRIC_ANCHOR_V1', 'namespace': 'promotions-anchor-v1',
        'publication_id': opaque(key, 'BATCH', batch['batch_id']),
        'public_sha256': opaque(key, 'MANIFEST', manifest), 'merkle_root': merkle(leaves),
        'publication_commitment': opaque(key, 'PUBLICATION', manifest)}, manifest
