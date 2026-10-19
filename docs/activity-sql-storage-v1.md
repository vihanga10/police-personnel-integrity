# SRB activity SQL delivery storage v1

## Scope and checkpoint

Built on committed checkpoint `40560db`, with applied PostgreSQL revision
`c95e3a17bd40`. New revision `d06f4b28ce51` adds only two staging tables:
`activity_delivery_preparation` and `activity_delivery_completion`.
This step installs storage, not a delivery adapter, importer or human permission.
The four Mongo activity collections remain empty.

## Evidence routes

| Source | Mongo collection | Writer policy | Fields |
| --- | --- | --- | ---: |
| officer_duty_periods.csv | duty_periods | SRB_DUTY_EVIDENCE_V1 | 17 |
| officer_firearms_expertise.csv | firearms_assessments | SRB_FIREARMS_EVIDENCE_V1 | 41 |
| good_conduct_register.csv | good_conduct_records | SRB_GOOD_CONDUCT_EVIDENCE_V1 | 33 |
| bad_conduct_register.csv | bad_conduct_records | SRB_BAD_CONDUCT_EVIDENCE_V1 | 31 |

Each preparation stores the exact sealed BSON envelope, SHA-256, opaque source
and officer references, source-confirmation hash, code revision, field/row review
counts and writer policy. Field bounds match each source's coverage. Unique
source/policy and assertion constraints prevent duplicate preparations. Completion
receipts bind a preparation ID and its exact digest, with a non-earlier timestamp.
They record delivery bookkeeping; the future adapter must verify Mongo contents
before inserting a receipt. SQL alone does not prove successful Mongo delivery.

## Preservation and provenance

Foreign keys restrict deletion. Insert guards require a registered officer,
usable NIC evidence and a matching ACTIVE SRB source assertion with the staged
batch/file/hash/row provenance. Historical identifier eligibility remains
UNASSESSED; this relational guard does not decrypt or authenticate a NIC match.
The future adapter must verify encrypted NIC evidence independently.
Assertions preserve unknown valid times and UNVERIFIED source independence.

Only SELECT and INSERT are granted to the existing application database account.
UPDATE, DELETE and TRUNCATE are also blocked by triggers. No automatic destructive
downgrade is supplied. These protections cannot prevent a database administrator
from deliberately disabling enforcement; blockchain commitments are a later step.
No database account is elevated and no existing evidence schema is altered.

## Encryption and interpretation

All activity details remain inside authenticated encrypted payloads. Ordinary
scoped viewing and special CID/CCIB viewing follow the agreed disclosure policy,
which is not implemented by these storage tables. Classification stays UNASSESSED.
Unknown H2 values remain missing, TRUE/FALSE claims stay booleans, and original
text and review issues remain preserved. Storage is not an authority, competency,
legal-effect, accepted-period or verified-current-state determination.

## Verification before applying the migration

Run the focused tests and `python scripts/check_activity_storage.py` using the
existing migration configuration. The checker pins the previously reconciled
counts and revision, acquires the existing registration advisory lock, installs
the migration inside one transaction, compares ORM/schema metadata, exercises
four unrelated synthetic fixtures with ephemeral primary/backup keys, checks
constraints/ACLs and attempts prohibited mutations inside savepoints.

It always rolls back its transaction, then uses a fresh connection to verify
that research counts (including prior profile destinations), revision, tables
and functions returned to their original state. It never connects to MongoDB,
uses production keys or displays personnel values. Run it only before applying
`d06f4b28ce51`; a changed checkpoint causes it to stop.

After a successful checker, commit the reviewed sources and apply the migration
as a separate step, then run Alembic current/check and post-migration counts.
Recovery adapters and the guarded activity importer follow. Stage 2 remains in
progress.
