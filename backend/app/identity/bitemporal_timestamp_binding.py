"""Verify database-reported timestamps against captured full-row commitments.

Trusted callers supply catalog and destination bindings from the existing
all-officer commitment replay. This does not authenticate those inputs itself,
prove a commit/visibility instant, establish history coverage or issue permits.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
import re
from uuid import UUID

from app.identity.destination_binding import row_binding, verify_binding
from app.identity.evidence_bundle_v2 import open_artifact, seal_artifact
from app.identity.historical_reconstruction import instant, require
from app.identity.protected_commitment import digest

POLICY = 'BOUND_DATABASE_RECORDING_TIMESTAMP_V1'
TABLE = 'identity.source_assertion'


@dataclass(frozen=True)
class BoundRecordingTimestamp:
    officer_uid: str = field(repr=False)
    raw_record_id: str = field(repr=False)
    source_assertion_id: str = field(repr=False)
    transaction_start: datetime = field(repr=False)
    transaction_end: datetime | None = field(repr=False)
    assertion_state: str
    row_sha256: str = field(repr=False)
    policy: str = POLICY
    timestamp_semantics: str = 'DATABASE_REPORTED_TRANSACTION_START'
    visibility_time_established: bool = False
    complete_history_established: bool = False


def verify_recording_timestamp(row, catalog_row, destination_bindings):
    """Require the exact previously committed row, not an unbound timestamp.

    A PostgreSQL transaction-start default can precede commit and visibility.
    Return that distinction explicitly. It must not be silently substituted for
    a missing authenticated intake/version receipt timestamp.
    """
    raw = catalog_row['raw_record_id']
    assertion = catalog_row['assertion']
    delivery = catalog_row['delivery']
    require(delivery['complete'] is True and
        str(row['source_assertion_id']) == assertion['source_assertion_id'] == delivery['assertion_id'] and
        row['raw_record_id'] == raw == assertion['raw_record_id'],
        'Recording source identity differs.')
    require(str(UUID(str(row['officer_uid']))) == str(row['officer_uid']), 'Officer UUID differs.')
    subject = [link for link in catalog_row['candidate_links']
        if link['role'] == 'officer_nic_no' and link['officer_uid'] == str(row['officer_uid'])]
    require(len(subject) == 1 and subject[0]['state'] == 'CANDIDATE_NOT_ACCEPTED',
        'Recording subject membership differs.')
    for name in ('source_file_name', 'source_file_sha256', 'source_row_number',
        'intake_batch_id', 'assertion_type'):
        require(row[name] == assertion[name], 'Recording provenance differs.')
    for name in ('source_system_id', 'import_file_id'):
        require(str(row[name]) == assertion[name], 'Recording provenance differs.')
    require(row['source_file_name'] == catalog_row['filename'], 'Recording filename differs.')
    actual = row_binding(TABLE, ('source_assertion_id',), row)
    expected = [item for item in destination_bindings[raw]
        if item.get('table') == TABLE and item['primary_key'] == actual['primary_key']]
    require(len(expected) == 1, 'Exact assertion destination binding required.')
    verify_binding(expected[0], actual)
    start = instant(row['transaction_start'])
    end = None if row['transaction_end'] is None else instant(row['transaction_end'])
    require(end is None or end > start, 'Recording transaction interval differs.')
    require(row['assertion_state'] in {'ACTIVE', 'SUPERSEDED', 'WITHDRAWN', 'DISPUTED'},
        'Recording assertion state differs.')
    return BoundRecordingTimestamp(str(row['officer_uid']), raw, str(row['source_assertion_id']),
        start, end, row['assertion_state'], actual['row_sha256'])


def payload(record):
    require(type(record) is BoundRecordingTimestamp, 'Typed recording timestamp required.')
    value = asdict(record)
    for name in ('transaction_start', 'transaction_end'):
        if value[name] is not None:
            value[name] = instant(value[name]).isoformat()
    require(value['policy'] == POLICY and
        value['timestamp_semantics'] == 'DATABASE_REPORTED_TRANSACTION_START' and
        value['visibility_time_established'] is False and value['complete_history_established'] is False,
        'Recording timestamp assurance differs.')
    return value


def receipt_binding(record, source_context):
    require(set(source_context) == {'code_revision', 'bundle_attempt_id', 'binding_attempt_id',
        'commitment_attempt_id', 'binding_artifact_sha256'} and
        all(isinstance(v, str) and v for v in source_context.values()),
        'Recording receipt context differs.')
    require(re.fullmatch('[0-9a-f]{40}', source_context['code_revision']) is not None and
        re.fullmatch('[0-9a-f]{64}', source_context['binding_artifact_sha256']) is not None,
        'Recording receipt version differs.')
    return dict(artifact='BOUND_RECORDING_TIMESTAMP', policy=POLICY,
        source_context=dict(source_context), record_sha256=digest(payload(record)))


def seal_recording_receipt(record, crypto, backup, source_context):
    """Seal metadata only; the trusted caller rechecks its permit before saving."""
    return seal_artifact(crypto, backup, payload(record), receipt_binding(record, source_context))


def open_recording_receipt(envelope, crypto, backup, expected_record, source_context):
    """Expected metadata comes from replayed row bindings, never envelope hints."""
    binding = receipt_binding(expected_record, source_context)
    primary = open_artifact(crypto, envelope, binding)
    recovered = open_artifact(backup, envelope, binding)
    require(primary == recovered == payload(expected_record), 'Recording receipt recovery differs.')
    return expected_record
