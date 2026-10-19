# Controlled staging recording hook V1

This step provides opt-in trusted backend functions. It does not enable an intake hook, install schemas, deploy a witness, create production keys, call a chain, or execute research. RPC 1 remains deferred. Existing registration/staging code and original evidence stay unchanged.

## Explicit backend workflow

After the existing archive verification, source registration and `stage_file` transaction return successfully, an authorized backend may select one committed staging row and one exact temporal claim. It supplies a pinned `StageScope` (batch, archive and registration-receipt fingerprints, file UUID/name/hash, expected row count, reported source code). `issue_registered_route` loads the full replayed snapshot and current readiness, verifies the independent witnessed baseline, decrypts the staging row with primary and recovery keys, and signs a 600-second routing decision. `process_registered_route` repeats those checks, independently reads committed staging, commits an encrypted evidence outbox intent, then captures and witnesses it through the existing bridge. Both public functions require PostgreSQL and the existing configured mutual-TLS witness transport. Do not expose loaded-snapshot functions or scope/signing inputs to request callers.

Routing means authorized candidate membership. It does not authenticate the source agency, establish NIC identity, create an accepted personnel fact, or prove changes to existing HR/PF/SRB destination tables. `source_system_code` is a pinned backend-reported label retained in encrypted provenance. A registration-receipt fingerprint is compared with trusted backend expectations, not independently treated as a signed source-authentication credential.

The stage reader must have SELECT only on the three staging tables. INSERT (including column grants), UPDATE (including column grants), DELETE, TRUNCATE and TRIGGER grants are rejected. The outbox role retains its existing SELECT/INSERT-only restriction. All three staging records are read in a repeatable-read read-only transaction. File row counts and contiguous distinct row ordinals must match. Metadata, exact ordered parsed strings and AEAD bindings are checked; selected row/batch/file fingerprints bind the signed decision. This verifies committed selection at the read instant, not that no administrator can ever change the source afterward.

## Corrections and interruption

A correction explicitly names the latest prior version of the same logical source claim; unrelated or stale predecessors are rejected by the existing capture layer. New intake uses `supersedes=None`. Originals are preserved. One row may have several temporal claims: each needs a separate authorized selector. Unselected rows/claims do not acquire coverage. This step handles intake and corrections; automatic withdrawal hooks and comprehensive intake scheduling remain pending.

Operation IDs derive from the journal, officer, pinned scope, committed staging fingerprint, exact claim selector and predecessor. Route refresh changes authorization time without changing the immutable outbox intent. Expired routes are rejected; an authorized backend can issue a fresh route for an idempotent retry. The outbox transaction and journal/registry/witness advancement are not a distributed atomic transaction. A failed capture may leave a committed pending outbox row. A normal retry completes a lost readback; uncertain journal/checkpoint/witness advancement follows the existing authenticated recovery procedure and must not be bypassed or silently marked successful. There is no guarantee of automatic retries or complete capture of every intake until orchestration is separately enabled and evaluated.

CSV dates remain effective dates. Database staging/registration timestamps remain provenance. Protected history uses the newly verified recording observation time, never an invented historical commit date. Successful status is returned only by the capture bridge after the witnessed checkpoint is confirmed. The result explicitly states `JOURNAL_OBSERVATIONS_ONLY` and does not establish source-change completeness.

## Isolated validation

The installer adds the module, unit tests, PostgreSQL tests and this document, and replaces only the exact previously installed isolated launcher. Its default recording suite remains 23 tests. New allowlisted `--suite intake-hook` runs 12 staging-to-history tests in a new Docker PostgreSQL 16 container, creates staging and outbox schemas only there, grants a separate restricted test role, and removes the container. No arbitrary database URL or existing container override is accepted. Without its private attested launcher configuration, PostgreSQL tests skip explicitly.

Run from backend:

```bash
uv run python -m pytest tests/test_controlled_recording_hook.py tests/test_controlled_recording_hook_postgres.py tests/test_isolated_recording_postgres_launcher.py -q
uv run python scripts/run_isolated_recording_postgres.py --suite intake-hook
```

The second command is required to validate real PostgreSQL behavior. SQLite fixtures establish neither PostgreSQL permission behavior nor deployment readiness. Production schema provisioning, intake orchestration, independent witness deployment, fresh RPC readiness and integrated research evaluation are still pending.
