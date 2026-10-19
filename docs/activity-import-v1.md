# Guarded SRB activity import v1

## Reviewed batch and modes

Built on committed checkpoint `68c1f30`, applied SQL revision `d06f4b28ce51`,
and the verified activity delivery adapter with twenty real-driver interruption
cases. Import sources: officer_duty_periods.csv (3,138),
officer_firearms_expertise.csv (30,348), good_conduct_register.csv (2,779),
bad_conduct_register.csv (370); total 36,635 rows.

`python -m app.identity.import_activities` is a local development intake command,
not a user-facing API. Human HQ Admin authentication/authorization remains pending.
This first importer is pinned to reviewed BATCH-RAW-001, its original registered
archive SHA-256 and confirmation SHA-256; it is not yet a general daily CSV UI.
Default mode is read-only validation. `--write` explicitly enables delivery;
`--reconcile` is read-only and refuses incomplete records. These two flags are
mutually exclusive. Commit reviewed source before any workflow so receipts retain
a clean, exact code revision. No migration or credential changes are introduced.

## Preflight before any database write

Use the pinned PostgreSQL application account and dedicated activity Mongo
account. Verify registered batch membership, source confirmation, file headers,
row counts/order, complete source-scoped station index, primary/backup row
recovery, exact subject NIC evidence, nonempty actor candidate support, unique
nonmissing source IDs, routing and the rebuilt preserved plan. Repeated officer
rows are legitimate history, not duplicate source records. Semantic unknowns
remain explicit; structural review prevents delivery.

Verify all expected activity preparation/document/receipt states and stop on
mismatch, orphan documents/assertions, evidence outside the reviewed batch, or a
completed receipt with a missing Mongo record. Complete-batch checks run before
any write. Preserve the reviewed observations: H2 missing 1,614 and present
28,734; matching reported totals 1,614/28,734; missing H1/H2/annual signatures
1,232/2,744/1,227; missing punishment dates 81 and delegation references 370.
None establishes authenticity, competency, authority or legal effect.

## Write and retry

Keep keyed preflight fingerprints and opaque source references in memory. For
each row, re-recover its staged cells and compare the keyed fingerprint and
subject linkage before proposing delivery. Subject/actor caches avoid redundant
preflight lookups; the SQL adapter independently re-verifies each preparation's
source, actor, station and NIC evidence before commit. It then uses the verified
SQL -> Mongo readback -> SQL receipt protocol and fresh-connection SQL commit
recovery. Interrupted writes may retain durable evidence: retry verifies and
reuses exact committed bytes, never deletes or overwrites them.

The source assertion count grows by 36,635 after a complete first import,
from 110,692 to 147,327. Activity preparations and completions each become
36,635. Mongo activity destinations become 3,138/30,348/2,779/370; previously
imported sources and profile destinations remain unchanged. SourceSystem stays
three because SRB is already registered. Classification history stays zero.

## Private attempt evidence and disclosure

Create owner-only attempt directories outside Git. Append receipts containing
code revision, policy versions, source hashes, aggregate warnings/statuses and
opaque raw IDs, without original personnel cells or encryption keys. Stop events
record uncertain progress. Default/reconcile modes write only this private local
journal, never either database; no plaintext plan is saved.

All personal activity payloads remain encrypted. Record classification is
UNASSESSED, authority_result is null, authority_assessment is NOT_RUN, valid
periods/reconstructed state remain null, and source independence is UNVERIFIED.
The importer grants no user disclosure and no verified-current-state claim.
Existing CID/CCIB and ordinary scoped disclosure policy remains applicable.

## Run order

Install and run focused tests; commit and push reviewed source. Run default
read-only validation and inspect aggregate results. Then run the same command
with `--write`. After completion, rerun with `--reconcile` and verify PostgreSQL
and Mongo counts separately. Actual imports exercise durable production commit
paths; local in-memory tests do not replace real-driver/import reconciliation.
Stage 2 remains in progress.
