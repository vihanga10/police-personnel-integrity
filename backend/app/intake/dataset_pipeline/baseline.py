"""Index the original batch archive so uploads cannot silently re-assert or rewrite it.

Reads only the checksum-verified original archive and the signed directory.
Each original row's dataset-scoped source identity maps to a keyed fingerprint;
reused identities with different content are recorded as ambiguous so any
upload under them is a conflict. Station names and cross-row references are
captured for the reviewed planners. Nothing is decrypted, sent or changed.
"""
import csv
import hashlib
import io
import zipfile
from app.identity.station_reference import build_station_index
from .core import check, digest, opaque, raw_record_id
from .registry import DATASETS, source_key, dataset
from .store import REFERENCES

POLICY = 'PERSONNEL_INTAKE_BASELINE_V1'
AMBIGUOUS = 'AMBIGUOUS_ORIGINAL_SOURCE_IDENTITY'


def members(archive, receipt):
    """Exact archive and per-file digests from the original registration receipt."""
    data = archive.read_bytes()
    check(hashlib.sha256(data).hexdigest() == receipt['archive']['sha256'] and
          len(data) == receipt['archive']['size_bytes'], 'ORIGINAL_ARCHIVE_DIGEST_DIFFERS')
    files = {f['filename']: f for f in receipt['files']}
    check(len(files) == len(receipt['files']) == 19, 'ORIGINAL_RECEIPT_FILES_DIFFER')
    out = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name, item in files.items():
            raw = z.read(item['archive_path'])
            check(hashlib.sha256(raw).hexdigest() == item['sha256'] and len(raw) == item['size_bytes'], 'ORIGINAL_FILE_DIGEST_DIFFERS')
            out[name] = raw
    return data, out


def rows(raw):
    reader = csv.reader(io.StringIO(raw.decode('utf-8-sig'), newline=''), strict=True)
    header = next(reader)
    return header, [dict(zip(header, values)) for values in reader]


def build(store, archive, receipt, directory):
    """Return (value, entries, references) for DatasetStore.install_baseline."""
    data, files = members(archive, receipt)
    by_nic = {}
    for officer in directory['officers']:
        by_nic.setdefault(officer['nic'].strip().upper(), []).append(officer['officer_uid'])
    entries, references, counts = {}, {}, {}
    for spec in DATASETS.values():
        header, original = rows(files[spec.filename])
        check(tuple(header) == spec.columns, 'ORIGINAL_HEADER_DIFFERS')
        counts[spec.code] = len(original)
        for number, row in enumerate(original, 1):
            key = source_key(spec, row)
            if key is None:
                continue  # unidentified original rows cannot collide with a keyed upload
            officers = by_nic.get(row['officer_nic_no'].strip().upper(), []) if not spec.multi_subject else []
            officer = officers[0] if len(officers) == 1 else None
            ident = opaque(store.key, 'SOURCE_ID', spec.code + '\x1e' + key)
            fingerprint = opaque(store.key, 'SOURCE_ROW', [officer, row])
            if ident in entries and entries[ident] != fingerprint:
                fingerprint = AMBIGUOUS
            entries[ident] = fingerprint
            column = next((k for k, v in REFERENCES.items() if v == spec.filename), None)
            if column and row[column].strip() and officer:
                references.setdefault(store.reference_id(column, row[column]), []).append(
                    {'filename': spec.filename, 'raw_record_id': opaque(store.key, 'RAW', [spec.filename, number]),
                     'officer_uid': officer, 'batch_id': None})
    _, stations = rows(files['station_master.csv'])
    index = build_station_index([(str(n), r) for n, r in enumerate(stations, 1)])
    value = {'source_set_sha256': digest({'policy': POLICY, 'archive_sha256': receipt['archive']['sha256'],
                                          'source_public_sha256': directory['source_public_sha256']}),
             'rows': len(entries), 'index_sha256': digest(entries),
             'stations': {name: list(codes) for name, codes in sorted(index.candidates.items())},
             'references': digest(references),
             'station_master': [[raw_record_id(dataset('STATION_REFERENCE'), r), r] for r in stations]}
    return value, entries, references, {'original_rows': counts, 'archive_sha256': hashlib.sha256(data).hexdigest(),
                                        'ambiguous_identities': sum(v == AMBIGUOUS for v in entries.values())}
