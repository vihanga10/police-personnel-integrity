# Committed evidence outbox and capture bridge V1

This step adds a concrete encrypted SQL evidence-version store and a trusted
backend bridge to the existing signed observation journal and independent
witness. It does not install a schema or hook itself into the existing intake
pipelines. There is no CLI or public HTTP endpoint. Existing CSVs, PostgreSQL and
Mongo destination records, baseline evidence and chain anchors are untouched by
the installer and tests.

## Meaning of a committed version

The signed receipt establishes that an exact encrypted version was read through
a new connection checkout after its outbox transaction committed. It does NOT
establish that this version was committed to all existing HR/PF/SRB/NPC
destination tables or Mongo documents, independently captured, true, accepted,
or anchored on either chain. The explicit storage semantics are
`NEW_ENCRYPTED_OUTBOX_EVIDENCE_VERSION`.

The outbox stores the complete supplied source row inside authenticated
encryption. A temporal claim is derived using the existing source parser and
bound to the stored row, outbox operation UUID and outbox table. Caller-supplied
destination fingerprints are not accepted as proof of other database writes.
Source classification and candidate subject identity remain unassessed.

The trusted intake caller must authenticate/validate its delivery and subject
association before calling these APIs. Arbitrary request dictionaries must not
be treated as trusted intake. Automatic intake hooks, validated correction
submission workflows and complete source-change capture remain pending.

## Backend API

Module: `app.identity.committed_evidence_capture`.

- `commit_evidence_version(args, repo, revision, engine, adapter, **submission)`
  verifies configured PostgreSQL/mTLS and loads the original fully replayed
  snapshot with its fresh readiness permit, then commits a new outbox row.
- `capture_evidence_version(args, repo, revision, engine, adapter, *, operation_id,
  authority_signer, authority_key_id, recorder_signer, recorder_key_id)` loads that
  same protected snapshot, reads the committed row, signs its receipt with the
  pinned independent evidence authority, appends the observation and checkpoint,
  advances the registry/witness and verifies the resulting history.
- `commit_loaded_version` and `capture_loaded_version` are INTERNAL APIs for
  already fully replayed snapshots and trusted backend configuration. Tests use
  these with file-backed SQLite and an in-process witness. Public entries refuse
  SQLite and in-process transport. A permit alone is not snapshot authentication.

`engine` must be a trusted SQLAlchemy Engine, not a caller-held Connection or
transaction. Its database URL must identify the configured primary; no request
may select credentials, endpoints, keys, journal roots or operation scope.
The PostgreSQL guards check mutation privileges (including column UPDATE),
`fsync=on` and primary status. Inserts force transaction-local
`synchronous_commit=on`. Both encryption key copies must recover the same body.

Submission fields:

| Field | Meaning |
| --- | --- |
| `operation_id` | Caller-retained canonical UUID for retries; not a timestamp |
| `source_row` | Validated single source catalog row with original columns/cells, provenance, candidate subject and complete delivery metadata |
| `source_claim_id` | Exact claim ID extracted from that row by the existing parser |
| `supersedes` | Latest journal version ID for a correction; `None` for a new independent claim |
| `withdrawn` | Explicit boolean, default `False` |
| `withdrawal_reason` | Required nonempty explanation for withdrawal; otherwise `None` |

For withdrawal, `source_row` and `source_claim_id` must be `None`. The stored claim
retains its predecessor unchanged. The explanation is encrypted in the outbox;
the journal authorization commits to that outbox epoch. Corrections preserve the
stable logical claim ID and the same source, dimension and field slot while
retaining the new source-row provenance. Independently reported claims remain
separate. A source row producing multiple temporal claims requires a separately
identified submission for each claim; this step does not promise atomic capture
of every claim from a row or an entire intake batch.

Console summaries contain policy/status/operation UUID and explicit incomplete
source-change coverage, without source values or officer identifiers.

## Time and retry rules

Database defaults and source CSV dates are not used as observation/commit times.
`database_reported_created_at` is metadata only and can precede commit. Receipt
issuance uses the authority's current clock after committed readback; the journal
assigns its current recorder observation time. These clocks must advance beyond
existing coverage. They are observation times, not a recovered exact historical
database commit instant. A delayed capture becomes visible at capture time.

The operation UUID binds one immutable intent. Reuse with different evidence is
refused, as is a duplicate intent under a different operation UUID. Unique SQL
constraints protect concurrent insert races. A retry after lost database
readback can discover the already committed row. A completed capture is found by
its exact outbox epoch in authenticated journal history and returned without a
new receipt or observation, even after its original authorization expires.

The SQL commit, journal publication, registry update and independent witness CAS
are separate durable operations. This is not a distributed transaction. A
committed-but-uncaptured row does not extend query coverage. If an event or
checkpoint is published without registry/witness acknowledgment, ordinary use
blocks; use the existing separately authorized recovery/reconciliation APIs.
Never automatically discard uncertain files or reset witness state. Lost replies
after a witness commit are recovered by a fresh head read and idempotent capture
retry. Retain the outbox operation UUID and do not substitute a new ID for an
uncertain operation.

## PostgreSQL provisioning — deferred, not part of installation

The new metadata is separate from the existing model registry and original
anchored table-count replay. An administrator must create the outbox in the
selected research database under a separate owner and configure the runtime
role. This package does not execute the following DDL; review and provision it
only as a later controlled database step with fresh readiness.

```sql
CREATE TABLE identity.recording_evidence_outbox (
    operation_id VARCHAR(36) NOT NULL PRIMARY KEY,
    journal_anchor VARCHAR(64) NOT NULL,
    intent_sha256 VARCHAR(64) NOT NULL,
    envelope_sha256 VARCHAR(64) NOT NULL,
    envelope_json TEXT NOT NULL,
    database_reported_created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT uq_recording_evidence_intent UNIQUE (journal_anchor, intent_sha256)
);
```

Grant only SELECT/INSERT on this table to the designated runtime role and USAGE
on its schema. Remove PUBLIC access. The role must not own the table, be a
superuser, inherit an owning/admin role, have table or column UPDATE, DELETE,
TRUNCATE or TRIGGER rights, or be able to assume such a role. PostgreSQL runtime
privilege checks reject directly effective mutation rights, but do not audit
every possible privilege-escalation path. Restrict administrative credentials and
schema-management permissions separately. Configure durable storage, backups
and independently protected witness infrastructure. These are operational
requirements, not guarantees supplied by unit tests.

Official references: [PostgreSQL 16 WAL settings](https://www.postgresql.org/docs/16/runtime-config-wal.html),
[PostgreSQL 16 privileges](https://www.postgresql.org/docs/16/ddl-priv.html),
[PostgreSQL 16 GRANT](https://www.postgresql.org/docs/16/sql-grant.html).

## Installation and verification

The installer requires clean `feat/identity-resolution` with commit `3f013da`,
validates exact prerequisite sources, and adds only this module, tests and doc.
It does not create a table, grant privileges, deploy a witness or create keys.
Run `--check` before installation.

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest \
  tests/test_committed_evidence_capture.py \
  tests/test_protected_bitemporal_runner.py \
  tests/test_witness_secure_transport.py \
  tests/test_recording_tip_witness.py \
  tests/test_recording_checkpoint_registry.py \
  tests/test_observed_recording_journal.py \
  tests/test_authenticated_recording_history.py \
  tests/test_protected_recording_review.py \
  tests/test_bitemporal_timestamp_binding.py \
  tests/test_bitemporal_reconstruction.py -q
```

Tests exercise real file-backed SQL transactions, commit visibility and rollback,
AEAD, Ed25519 signatures, durable journal files, idempotence, delayed capture,
correction/withdrawal lineage, conflict/tamper rejection and interrupted witness
publication. PostgreSQL DDL compilation and simulated privilege/durability guard
responses are also checked. They do NOT run an actual PostgreSQL server or prove
its privileges/WAL behavior; a fresh PostgreSQL integration check is required
before operational use. Existing secure-transport tests exercise disposable TLS.

Scope remains `JOURNAL_OBSERVATIONS_ONLY`; full intake/source-change completeness
is false. Outbox processing must be integrated and evaluated before this scope
can grow. Original-batch readiness does not anchor these new evidence versions.
Findings commitments, dual-chain anchoring, scoped UI and actual independent
service deployment remain separate work. RPC 1 stays deferred; no live research
execution is authorized or performed by this development package.
