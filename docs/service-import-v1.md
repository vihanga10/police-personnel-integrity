# Guarded service batch import v1

This local development CLI is pinned to the reviewed BATCH-RAW-001 source,
archive/confirmation fingerprints and 6,596 service rows. It is not an
authenticated HQ Admin API. No officer disclosure is enabled.

## Before running the importer

Run focused tests and `scripts/check_service_delivery.py` using the private
Mongo credential directory. That checker uses the real PostgreSQL/Mongo drivers,
ephemeral encryption keys, a new synthetic SQL source/officer fixture and a
separate random Mongo database with equivalent validation/indexes/append-only
application permissions. Five interruption cases cover preparation, Mongo
insertion and completion receipt acknowledgment. Retry must reuse exact
ciphertext and create one Mongo record/SQL receipt; reconciliation must verify
both. SQL fixtures remain inside rollback-only transactions. Only the isolated
synthetic Mongo database/users/roles are removed. Research counts/revision remain
unchanged, and no production personnel values/keys are read or displayed.

The checker exercises actual SQL bodies and Mongo persistence but its SQL
savepoints are not independent durable commits. The importer uses the real
application SQL account, commits preparation before Mongo and recovers it via
a fresh connection. It likewise independently recovers each completion receipt.
Stop on failed checks; never import to discover whether recovery works.

## Modes and validation

`python -m app.identity.import_services` defaults to validation with no database
writes. `--write` explicitly enables coordinated delivery. `--reconcile` is
read-only and requires every selected record to have exact prepared SQL evidence,
matching Mongo evidence and its committed completion receipt. It cannot repair
missing records. Write and reconciliation are mutually exclusive.

Every mode requires clean committed source, private primary/backup keys,
authenticated research database targets and complete source confirmation.
Preflight validates archive/file registration, exact 32-column service contract,
row sequence/count, primary/backup recovery, one distinct officer candidate,
usable exact encrypted NIC evidence, station-source references and every source
field. Repeated service identifiers or officers stop the batch. Original source
values, missing fields and uncertainties are preserved. No source snapshot or
state-effective dates are inferred. Extra/orphan service documents are refused.

Preflight holds keyed source-plan fingerprints in memory. Before each write,
the CLI replans/rechecks the row and requires its identity/evidence fingerprint
to match preflight. The SQL adapter then checks originals and NIC linkage inside
the preparation transaction. Pending source assertions/outbox rows are evidence
of preparation, not completed service imports. Completion is appended only after
exact Mongo readback. Interrupted attempts must be retried with the original
committed preparation; no records are deleted or overwritten to compensate.

## Private attempt evidence

The required attempt root is outside Git, without symlinks and owner-only.
Each run creates a private directory of exclusive, atomically published receipts.
They record mode, batch/policy/code revision and source fingerprints, aggregate
warnings/outcomes, and opaque source-row progress. They contain no officer names,
NICs, service values or encryption keys. If a post-commit journal write fails,
the row remains uncertain until database evidence is verified on retry. This
development journal is not the final authenticated human access/audit log.

## Expected first-import results

Before writing: 6,596 `PLANNED` rows; SQL preparations/completions and Mongo
service documents are zero. After a complete first import: 6,596 SQL preparations,
6,596 completion receipts, 6,596 Mongo service documents and 6,596 added
`HR_SERVICE_EVIDENCE` assertions. Total source assertions become 37,158, and
registered source systems become two (PF_REGISTRY and POLICE_HR_IS). Existing
officer/identifier/profile counts must remain unchanged. Reconciliation must
return 6,596 `VERIFIED_EXISTING` outcomes with no database writes.

Do not run `--write` until source tests, driver recovery checks, the committed-code
validation run and its aggregate results have passed review. Classification and
historical NIC eligibility remain UNASSESSED; source independence and snapshot
applicability remain unknown. This import does not establish source truth,
verified current state or user authorization. Stage 2 remains in progress after
service import: remaining source transformations/classification still need their
own verified workflows. Human RBAC/ABAC, audits, algorithms and anchoring are
separate remaining implementation stages.
