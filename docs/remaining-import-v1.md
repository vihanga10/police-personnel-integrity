# Guarded remaining HR/PF import v1

## Scope and modes

This local development CLI handles five reviewed sources, totaling 36,694 rows:
education 6,596, operations 19,554, courts 9,538, complaints 998 and demotions 8.
Family details are excluded; their encryption migration and SQL writer remain
pending. This tool is not an authenticated application endpoint. HQ Admin-only
human intake and the full disclosure rules still require application enforcement.

The default mode performs no database writes. --write explicitly enables the
verified delivery adapter. --reconcile requires every existing delivery to be
complete and performs no repairs. The two flags cannot be combined. Source must
be committed and the working tree clean before any workflow run.

## Complete preflight before writes

The CLI pins BATCH-RAW-001, its reviewed archive and confirmation SHA-256 values,
all registered archive members, supplying source codes, headers, row sequences
and the five expected counts. Both private key copies must recover each original
staged row and each newly encrypted plan exactly. Field-routing coverage is
validated against the committed contract. Keys must use different paths.

Single-subject education, complaints and demotions require one exact registered
NIC candidate and independently recovered encrypted identifier/assertion proof.
Education has no event key; one row per exact subject is enforced without using
an exam index as an officer or event identity. Other files require nonempty unique
reported event keys. Repeated officers in event history are not duplicates.

Operations and courts retain a null primary officer and identifier version.
All participant text and unresolved references stay in the encrypted plan;
source references do not establish accepted participant relationships. Missing
and unresolved scalar actor/NIC observations are included explicitly and
independently rediscovered by the delivery adapter. The reviewed 240 complaint
rows with unresolved alternate NIC evidence remain flagged. Changed review
counts stop preflight; delivery does not turn those observations into accepted
identities or legal effects. Raw values and review issues are preserved.

Saved preparations, encrypted Mongo documents and SQL completion digests are
checked. Orphan Mongo documents, unexpected preparations outside this batch,
orphan assertions, conflicting documents and completed deliveries with missing
Mongo evidence stop the workflow. No overwrite or deletion repairs are offered.

## Execution and recovery

Preflight retains only keyed HMAC fingerprints and opaque row/identity bindings,
not full plaintext plans. Before each write, staging is recovered again and its
plan compared with the preflight fingerprint. The delivery adapter independently
checks source/NIC/candidate evidence before committing assertion and exact BSON
preparation. It verifies durable SQL visibility using fresh connections, Mongo
readback and the completion receipt. A retry uses the existing winning encrypted
preparation rather than replacing its IDs, timestamp or ciphertext.

Each row may commit independently. An interrupted import can leave completed
rows and partially delivered evidence. Retry validates all existing states and
finishes valid pending deliveries; --reconcile never finishes pending work.
An import failure does not mean committed evidence was rolled back.

Private attempt journals are outside the repository with owner-only permissions.
They contain code revision, fingerprints, opaque row references and aggregate
outcomes/issues, not personnel values. Uncertain delivery is recorded with an
opaque pending row ID. No raw exception messages or personnel-level output are
printed. Source IDs used for duplicate checks stay in memory.

## Run order

1. Install at clean feat/identity-resolution commit 64134a7 and run focused tests.
2. Commit the importer, tests and document; push the commit.
3. Run the CLI without --write or --reconcile; inspect aggregate validation.
4. After validation passes, explicitly run --write.
5. Run --reconcile and verify all SQL/Mongo counts, including previously imported
   evidence and classification counts.

The CLI arguments are --batch-id, --expected-archive-sha256, --confirmation,
--expected-confirmation-sha256, --expected-education-rows 6596,
--expected-operation-rows 19554, --expected-court-rows 9538,
--expected-complaint-rows 998, --expected-demotion-rows 8, --key-file,
--backup-key-file, --remaining-credential-directory and --attempt-root.

The existing identity.source_assertion count remains 147,327. These five imports
append 36,694 identity.remaining_source_assertion rows and matching preparations
and completion receipts, separately from the existing assertion table. Mongo
counts must be 6596/19554/9538/998/8. These are expected post-import totals, not
claims that an import has already run.

Classification remains UNASSESSED, source independence UNVERIFIED, historical
eligibility/reference linkage UNASSESSED and authority assessment NOT_RUN.
Reported outcomes are unapplied and valid periods unknown. No user disclosure,
verified current-state claim or independent NPC source is created by this import.
Family encryption and remaining Stage 2 work are still pending.

## Tests

Unit tests cover mutually exclusive modes, exact batch fingerprints/counts,
read-only progress states, missing completed evidence, orphan documents, changed
review coverage, dual-key source/plan recovery, null multi-person subjects,
preserved unresolved alternate NICs, identity-proof caching and full five-source
orchestration with inert database boundaries. They verify that a later invalid
subject prevents all import writes during complete preflight and that private
journals omit source NIC text. The real delivery checker has separately passed
25 interruption cases on the research development machine. Unit tests here do
not claim an actual import or durable production commits.
