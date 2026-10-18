"""Dedicated encrypted intake journal for registered officer datasets.

Reuses the append-only promotion intake mechanics (immutable phases, exact
operation replay, worker audit outbox) under a separate file, key domain and
dataset-scoped source identities. Original research stores are never edited.
"""
import sqlite3
from .core import check, digest, opaque, publication, expected_public
from .registry import dataset
from app.intake.promotion_pipeline.store import IntakeStore

REFERENCE_SCHEMA = '''CREATE TABLE IF NOT EXISTS ref_index(id TEXT NOT NULL, seq INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY(id,seq));
CREATE TRIGGER IF NOT EXISTS no_ref_index_update BEFORE UPDATE ON ref_index BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;
CREATE TRIGGER IF NOT EXISTS no_ref_index_delete BEFORE DELETE ON ref_index BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;'''
# Reported cross-row references the reviewed SRB planner resolves for overrides.
ORIGINAL_SCHEMA = '''CREATE TABLE IF NOT EXISTS original_commitments(id TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS original_commitment_meta(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS no_original_commitments_update BEFORE UPDATE ON original_commitments BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;
CREATE TRIGGER IF NOT EXISTS no_original_commitments_delete BEFORE DELETE ON original_commitments BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;
CREATE TRIGGER IF NOT EXISTS no_original_commitment_meta_update BEFORE UPDATE ON original_commitment_meta BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;
CREATE TRIGGER IF NOT EXISTS no_original_commitment_meta_delete BEFORE DELETE ON original_commitment_meta BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;'''
RECEIPT_SCHEMA = '''CREATE TABLE IF NOT EXISTS original_receipts(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS no_original_receipts_update BEFORE UPDATE ON original_receipts BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;
CREATE TRIGGER IF NOT EXISTS no_original_receipts_delete BEFORE DELETE ON original_receipts BEGIN SELECT RAISE(ABORT,'immutable intake evidence'); END;'''
REFERENCES = {'restriction_id': 'officer_restrictions.csv', 'transfer_id': 'transfer_history.csv'}


class DatasetStore(IntakeStore):
    FILENAME = 'personnel-intake.sqlite3'
    DOMAIN = 'PERSONNEL_INTAKE_STORE_V1'

    def __init__(self, root, key_file, backup_file, *, repo, create=False):
        super().__init__(root, key_file, backup_file, repo=repo, create=create)
        if create:
            with sqlite3.connect(self.path) as c:
                c.executescript(REFERENCE_SCHEMA)
        with self.transaction() as c:
            check(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ref_index'").fetchone(),
                  'INTAKE_SCHEMA_DIFFERS')

    # Original anchored batch: one pseudonymous commitment and Merkle proof per officer (installed once).
    def install_original_commitments(self, meta, entries):
        """entries: {officer_uid: {...}}. Atomic and one-time; keyed by a keyed opaque index, never by UID."""
        check(set(meta) >= {'merkle_root', 'batch_publication_id', 'officers'} and meta['officers'] == len(entries), 'ORIGINAL_COMMITMENT_META_DIFFERS')
        with sqlite3.connect(self.path) as c:
            c.executescript(ORIGINAL_SCHEMA)
        with self.transaction() as c:
            check(c.execute('SELECT COUNT(*) FROM original_commitments').fetchone()[0] == 0 and
                  c.execute('SELECT COUNT(*) FROM original_commitment_meta').fetchone()[0] == 0, 'ORIGINAL_COMMITMENTS_ALREADY_INSTALLED')
            for officer, entry in sorted(entries.items()):
                ident = opaque(self.key, 'ORIGINAL_COMMITMENT', officer)
                c.execute('INSERT INTO original_commitments VALUES(?,?)', (ident, self.seal('ORIGINAL_COMMITMENT', ident, entry)))
            c.execute('INSERT INTO original_commitment_meta VALUES(1,?)', (self.seal('ORIGINAL_COMMITMENT_META', 1, meta),))

    def original_commitment(self, officer):
        """(entry, meta) for one officer, or None when the index was never installed or lacks the officer."""
        ident = opaque(self.key, 'ORIGINAL_COMMITMENT', officer)
        with self.transaction() as c:
            if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='original_commitments'").fetchone():
                return None
            row = c.execute('SELECT value FROM original_commitments WHERE id=?', (ident,)).fetchone()
            meta = c.execute('SELECT value FROM original_commitment_meta WHERE id=1').fetchone()
        if row is None or meta is None:
            return None
        return self.open('ORIGINAL_COMMITMENT', ident, row[0]), self.open('ORIGINAL_COMMITMENT_META', 1, meta[0])

    def install_original_receipts(self, receipts):
        """The stored Fabric and Sepolia receipts of the original batch's 68 transactions each. Installed once."""
        with sqlite3.connect(self.path) as c:
            c.executescript(RECEIPT_SCHEMA)
        with self.transaction() as c:
            check(c.execute('SELECT COUNT(*) FROM original_receipts').fetchone()[0] == 0, 'ORIGINAL_RECEIPTS_ALREADY_INSTALLED')
            c.execute('INSERT INTO original_receipts VALUES(1,?)', (self.seal('ORIGINAL_RECEIPTS', 1, receipts),))

    def original_receipts(self):
        with self.transaction() as c:
            if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='original_receipts'").fetchone():
                return None
            row = c.execute('SELECT value FROM original_receipts WHERE id=1').fetchone()
        return None if row is None else self.open('ORIGINAL_RECEIPTS', 1, row[0])

    # Dataset hooks used by the shared delivery/publication worker.
    def source_key(self, row):
        check(type(row.get('source_key')) is str and '\x1e' in row['source_key'], 'SOURCE_KEY_REQUIRED')
        return row['source_key']

    def row_officers(self, row):
        return {s['officer_uid'] for s in row['subjects']}

    def delivery_value(self, batch, row):
        spec = dataset(batch['dataset'])
        return {'policy': 'PERSONNEL_SOURCE_ROW_V1', 'dataset': spec.code, 'filename': spec.filename,
            'officer_uid': row['officer_uid'], 'subjects': row['subjects'], 'batch_id': batch['batch_id'],
            'file_sha256': batch['file_sha256'], 'source_row': row['row'], 'source': row['source'],
            'received_at': batch['received_at'], 'source_reference': batch['source_reference'],
            'source_system': batch['source_system'], 'evidence_role': spec.evidence_role,
            'source_custody': 'UPLOADER_REPORTED', 'authority': 'NOT_ASSESSED'}

    def publication(self, batch):
        return publication(self.key, batch)

    def expected_public(self, payload, result):
        return expected_public(payload, result)

    # Original-corpus baseline (built once by the operator from the verified archive).
    def install_baseline(self, value, entries, references):
        """Atomic one-time install. Entries map opaque source IDs to row fingerprints."""
        check(set(value) == {'source_set_sha256', 'rows', 'index_sha256', 'stations', 'references', 'station_master'},
              'BASELINE_FIELDS_DIFFER')
        check(value['rows'] == len(entries) and value['index_sha256'] == digest(entries), 'BASELINE_INDEX_DIFFERS')
        check(value['references'] == digest(references), 'BASELINE_REFERENCES_DIFFER')
        with self.transaction() as c:
            check(c.execute('SELECT COUNT(*) FROM baseline').fetchone()[0] == 0 and
                  c.execute('SELECT COUNT(*) FROM baseline_meta').fetchone()[0] == 0, 'PARTIAL_BASELINE_REFUSED')
            c.executemany('INSERT INTO baseline VALUES(?,?)', sorted(entries.items()))
            for ident, items in sorted(references.items()):
                for seq, item in enumerate(items):
                    c.execute('INSERT INTO ref_index VALUES(?,?,?)', (ident, seq, self.seal('REFERENCE', [ident, seq], item)))
            c.execute('INSERT INTO baseline_meta VALUES(1,?)', (self.seal('BASELINE', 1, value),))
        return self.verify_baseline(value['source_set_sha256'])

    def verify_baseline(self, expected_pin):
        with self.transaction() as c:
            meta = c.execute('SELECT value FROM baseline_meta WHERE id=1').fetchone()
            check(meta is not None, 'BASELINE_INDEX_REQUIRED')
            value = self.open('BASELINE', 1, meta[0])
            rows = dict(c.execute('SELECT id,fingerprint FROM baseline'))
            check(value['source_set_sha256'] == expected_pin and value['rows'] == len(rows) and
                  value['index_sha256'] == digest(rows), 'BASELINE_INDEX_CHANGED')
        return value

    def stations(self):
        with self.transaction() as c:
            meta = c.execute('SELECT value FROM baseline_meta WHERE id=1').fetchone()
        check(meta is not None, 'BASELINE_INDEX_REQUIRED')
        value = self.open('BASELINE', 1, meta[0])
        return {name: tuple(codes) for name, codes in value['stations'].items()}

    def station_master_rows(self):
        """Original station master rows with opaque references, for the reviewed station planner."""
        with self.transaction() as c:
            meta = c.execute('SELECT value FROM baseline_meta WHERE id=1').fetchone()
        check(meta is not None, 'BASELINE_INDEX_REQUIRED')
        return [(rid, row) for rid, row in self.open('BASELINE', 1, meta[0])['station_master']]

    def reference_id(self, column, value):
        return opaque(self.key, 'REFERENCE', [column, value.strip()])

    def references(self, column, value):
        """Original and queued-upload source rows reported under this identifier."""
        check(column in REFERENCES, 'REFERENCE_COLUMN_UNSUPPORTED')
        ident = self.reference_id(column, value)
        with self.transaction() as c:
            rows = c.execute('SELECT seq,value FROM ref_index WHERE id=? ORDER BY seq', (ident,)).fetchall()
        return [self.open('REFERENCE', [ident, seq], blob) for seq, blob in rows]

    def queue(self, ident, approved):
        """Reserve source identities and publish uploaded reference targets in one transaction."""
        with self.transaction() as c:
            batch = self._batch(c, ident)
            prior = c.execute('SELECT value FROM phases WHERE batch=? AND phase=?', (ident, 'QUEUED')).fetchone()
            if prior:
                check(self.open('PHASE', [ident, 'QUEUED'], prior[0]) == approved, 'COMMIT_CONFLICT')
                return
            check(not any(r['status'] == 'NEEDS_REVIEW' for r in batch['rows']), 'ROWS_REQUIRE_REVIEW')
            rows = [r for r in batch['rows'] if r['status'] == 'READY']
            check(rows, 'NO_NEW_ROWS')
            spec = dataset(batch['dataset'])
            column = next((k for k, v in REFERENCES.items() if v == spec.filename), None)
            for r in rows:
                key = opaque(self.key, 'SOURCE_ID', self.source_key(r))
                check(c.execute('SELECT 1 FROM reserved_sources WHERE id=?', (key,)).fetchone() is None and
                      c.execute('SELECT 1 FROM baseline WHERE id=?', (key,)).fetchone() is None,
                      'SOURCE_RESERVED_AFTER_PREVIEW_REVIEW_REQUIRED')
                c.execute('INSERT INTO reserved_sources VALUES(?,?,?)', (key, ident,
                          opaque(self.key, 'SOURCE_ROW', [r['officer_uid'], r['source']])))
                if column is not None:
                    target = self.reference_id(column, r['source'][column])
                    seq = c.execute('SELECT COUNT(*) FROM ref_index WHERE id=?', (target,)).fetchone()[0]
                    c.execute('INSERT INTO ref_index VALUES(?,?,?)', (target, seq, self.seal('REFERENCE', [target, seq],
                        {'filename': spec.filename, 'raw_record_id': self.record_id(r), 'officer_uid': r['officer_uid'], 'batch_id': ident})))
            for officer in sorted({o for r in rows for o in self.row_officers(r)}):
                c.execute('INSERT INTO officer_batches VALUES(?,?)', (opaque(self.key, 'OFFICER_INDEX', officer), ident))
            c.execute('INSERT INTO phases VALUES(?,?,?)', (ident, 'QUEUED', self.seal('PHASE', [ident, 'QUEUED'], approved)))
