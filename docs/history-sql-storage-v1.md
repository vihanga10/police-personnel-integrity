# Append-only historical SQL delivery storage v1

## Scope

Baseline: clean feat/identity-resolution at 42d5781. PostgreSQL applied revision
is f73a0c94de21. Service/profile imports remain reconciled; historical Mongo
collections are empty. This package installs historical preparation/receipt
models, a migration and a rollback-only checker. It does not install an actual
historical delivery adapter or importer, apply a migration, connect to Mongo,
classify evidence, approve historical linkage or grant human access.

## Preparation and completion

staging.history_delivery_preparation retains the exact sealed Mongo BSON bytes
and their SHA-256 digest. Metadata binds the preparation to the source raw row,
source assertion, officer UUID, supporting NIC version, confirmation hash and
code revision. The source filename, destination collection and writer policy
must form one of the two permitted transfer/promotion combinations. Unique
source-row/policy and source-assertion constraints prevent duplicate delivery.

A field review count and review state preserve visibility of outstanding field
review without exposing original personnel values in SQL metadata. They do not
constitute authority verification, historical validity, source truth or import
readiness. Original values and detailed review reasons remain in ciphertext.
The 30 negative duration claims remain REVIEW_REQUIRED with no normalized numeric
value. Retaining such evidence is distinct from using it in duration calculations.

staging.history_delivery_completion references the exact preparation event and
digest together. A completion may not predate its preparation. Both tables are
append-only: application SELECT/INSERT permissions only, plus UPDATE/DELETE and
TRUNCATE rejection triggers. Automatic destructive downgrade is intentionally
unavailable. Existing service delivery tables and evidence remain unchanged.

## Provenance and security boundaries

The preparation trigger verifies a corresponding active PF_REGISTRY source
assertion, raw row/file/batch/hash/row number, registered officer and active
matching NIC evidence. Historical identifier eligibility remains UNASSESSED.
Unknown valid periods stay NULL; reported event dates remain inside ciphertext.
Authority and classification are not approved by this storage operation.

SQL verifies the byte digest and relational provenance. It cannot decrypt or
interpret arbitrary BSON. The future writer must validate full source-plan
coverage, exact row/identifier support, review state and primary/backup recovery,
and commit assertion plus preparation atomically before Mongo insertion. It must
reuse committed bytes on retry and append a receipt only after exact Mongo
readback. A SQL receipt by itself cannot prove Mongo delivery; driver checks and
reconciliation remain required before import.

All personal payloads stay encrypted. The policy-v2 former-service summary
exception concerns controlled application disclosure only, never plaintext
storage or unrestricted access to full transfer/promotion records.

## Rollback-only verification

check_history_storage.py uses the existing migration account, a dedicated SQL
transaction and ephemeral test keys. It temporarily applies the proposed DDL,
compares model/schema metadata and checks application privileges. Synthetic
transfer and promotion fixtures test provenance, digest, routing and review
constraints; encrypted recovery; failure rollback after assertion insertion;
receipt matching and order; duplicates; UPDATE/DELETE/TRUNCATE denials.

All DDL, functions and fixture rows are rolled back. Fresh-connection checks
verify unchanged baseline counts and revision and absence of the proposed tables
and functions. No Mongo connection or production encryption keys are used.
The initial checker must run before migration b84d2f06ac39 is applied. Review its
output before committing/applying the migration. Stage 2 remains in progress.
