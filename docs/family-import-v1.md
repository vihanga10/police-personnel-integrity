# Atomic encrypted HR family import v1

## Verified starting point

Commit 51d8c08 added encrypted family destinations. The user applied
f28b6d40ea73, Alembic found no schema differences, and post-migration counts
matched the completed remaining import checkpoint. Existing PF family relations
remain 6,596; civil events, next-of-kin and attestations are empty. The family
storage rollback checker passed 74 checks. It inspected application privileges
and exercised fixtures as migrator; it did not impersonate the application login.

## This package

The package adds family_transform_receipt, migration a39c7e51fb84, family routing,
the atomic writer, guarded import_families CLI, tests and a rollback-only checker.
Install source and run focused tests, then check_family_writer.py at f28b6d40ea73.
Do not apply the receipt migration or run the importer before that check passes.
The checker compares migration/models, inspects app find/insert-equivalent SQL
privileges, stages only unrelated synthetic family/NIC fixtures with ephemeral
keys, exercises actual SQL writes, injects failure after every INSERT boundary,
checks savepoint rollback, verifies read-only/write replay and encrypted recovery,
and rejects receipt mutation and altered reference metadata. It always rolls back
new tables, functions and fixtures and verifies original counts/revision afterward.
There is no Mongo connection. Application-login writes and fresh-connection commit
recovery are tested during the subsequent actual guarded importer workflow.

## Preservation and routing

Every original cell, normalized claim, missing value, issue and uncertainty is in
an authenticated encrypted source assertion. No new family evidence replaces a
PF father claim or accepts a family person's identity. Source assertions use
HR_FAMILY_EVIDENCE under POLICE_HR_IS, independence UNVERIFIED, unknown valid
periods, and unknown source_recorded_at; the reported entry date stays encrypted.
No security classification rows or current-state determinations are written.

Spouse fields produce a source-scoped SPOUSE claim. Reported marriage/divorce dates
or certificates also produce such a claim if a spouse name is missing, because
civil-event FKs require a relationship anchor. The envelope explicitly states
person identity UNASSESSED. Separate civil-event payloads preserve the original
MARRIAGE/DIVORCE claims, without accepting legal effect or effective dates.

Child names/ages produce at most one CHILD aggregate list claim per source row.
Neither equal lengths nor reported child counts authorize positional matching,
individual child identities, or birth-date derivation. All count and list claims
stay preserved even if a structural review is required. Count-only/zero/missing
claims remain assertion-only. Death fields and certificates remain assertion-only
because the deceased person's identity is not established by this file.

Next-of-kin details remain encrypted with no invented link to the spouse/children.
Attestations use RECORDED_BY routing metadata, actor_officer_uid null and
resolution_status UNRESOLVED. Candidate NIC evidence remains encrypted in the
source plan. Certified_signed_date is preserved as a separately named source
claim, not attributed to a fabricated certifier or accepted certification.
All dates, names, addresses, asserted rank and signatures remain encrypted.

## Atomicity and recovery

Each row independently rechecks staged headers/original cells, batch fingerprints,
source confirmation references, exact encrypted subject NIC, current subject
candidate ambiguity and recorder candidate evidence. It replans the original
and compares the entire normalized envelope before any writes. All 6,596 rows
receive a complete read-only preflight before the first write. Snapshot HMACs
bind source and linkage between preflight and execution. Exactly one family row
per discovered officer is enforced for this first reviewed batch.

A per-source advisory transaction lock and raw-record receipt primary key protect
cooperating retries. The assertion, zero or more destinations and one receipt
are written in a single SQL transaction. Ciphertext is authenticated to the
policy, purpose, raw row, officer, assertion, record, table, chain and relationship
IDs. Primary and backup keys must recover identical payloads. The encrypted
receipt binds the original code revision, exact NIC reference, policy and every
destination. Retry verifies provenance, state, routing, coverage and encrypted
contents; no new rows or ciphertext replacements occur for existing receipts.

After commit, a fresh application connection verifies the saved receipt and all
destinations. A lost commit acknowledgement is resolved with a fresh read-only
connection. If no verified receipt exists, execution stops and a later retry can
resume. No partial row is declared complete. Per-row commits mean earlier complete
rows remain if a later row fails; this is not one transaction for the whole batch.

Orphan family assertions, orphan receipts, unexpected batch receipts, missing
or additional destination rows, changed normalized claims and altered bindings
stop the workflow. Receipt insertion also has a DB provenance guard. Receipts
reject update/delete/truncate, and the app account receives SELECT/INSERT only.
Existing family payload protections and technical version guards remain in place.
No production family rows are deleted, closed or superseded by this importer.

## CLI and sequence

1. Install, focused tests, rollback-only check_family_writer.py.
2. Commit/push reviewed source; apply a39c7e51fb84; alembic current/check and counts.
3. Run import_families without write flags for read-only validation of 6,596 rows.
4. Inspect aggregate destinations, structural reviews and uncertainties.
5. Explicit --write imports; --reconcile verifies without writes. Modes exclude
   one another. The CLI requires clean committed source, the reviewed fingerprints,
   separate private key files and owner-only attempt journals outside Git.
6. Reconcile and verify post-import counts before closing the family checkpoint.

Required flags are --batch-id, --expected-archive-sha256, --confirmation,
--expected-confirmation-sha256, --expected-rows 6596, --key-file,
--backup-key-file and --attempt-root. There is no Mongo credential flag. Aggregate
journals contain opaque row IDs, counts, fingerprints and error types, no personal
values or decrypted plans. Errors print types; checker diagnostics use code
locations only. Final human authentication, scoped disclosure and temporal
reconstruction remain pending. Classification stays UNASSESSED; Stage 2 remains
in progress. Import is evidence preservation, not source-truth verification.
