# Recoverable SRB evidence delivery

This package adds the delivery protocol, real SQL adapter and a real-driver recovery
checker. It adds no migration or human-facing import API and imports no officer records.

## Delivery sequence

1. Validate the complete SRB plan and rebuild its parsed fields from preserved text.
2. Recover the exact staged subject row and its primary/backup encrypted NIC proof.
3. Independently check supplied actor identities, station rows and source-qualified
   restriction/transfer references. Referenced subjects and source keys must agree.
4. In one SQL transaction, register/reuse the active SRB source and append its
   source assertion plus exact encrypted Mongo BSON preparation.
5. Recover that committed preparation through a fresh SQL connection.
6. Append the prepared document to its exact SRB Mongo destination and verify readback.
7. Append a completion receipt and verify the committed receipt through a fresh connection.

The expected filename/collection/policy tuple is enforced before any SQL or Mongo
mutation. The Mongo document and source assertion use the same authenticated
ciphertext. Every original field and source/evidence reference is preserved inside
the encrypted payload. Source classification stays UNASSESSED; authority NOT_RUN;
accepted valid boundaries and reconstructed state stay null. Source verifiable
flags and rank labels do not approve a restriction or override.

## Recovery and preservation

Uniqueness and per-source transaction locks resolve competing preparations. A retry
returns the first committed encrypted document, preserving original IDs, timestamp,
nonce and ciphertext. Lost acknowledgments are unknown outcomes, not instructions
to delete evidence or generate a replacement version.

A duplicate Mongo insertion is successful only when readback proves exact equality
with the SQL preparation. Conflicting Mongo content or receipt digests stop delivery.
Missing Mongo evidence after a completion receipt is an integrity issue and is not
silently repaired. Read-only reconciliation never inserts a missing document or receipt.
No protocol operation updates or deletes evidence.

## Source and importer boundaries

The SQL adapter verifies active exact NIC evidence without claiming historical
eligibility. Actor UUIDs are independently resolved from encrypted NIC evidence;
the reported rank remains separate. Referenced restriction and transfer raw rows
must have the correct source filename/header, batch, key and subject. A cancelled
transfer claim can remain a referenced source claim; its effect is not accepted.
Station source provenance and encrypted code/name support are independently checked.

The future importer must additionally verify the complete source-confirmation and
archive contracts, full-snapshot source-key uniqueness, station-name uniqueness,
override-recorded flag consistency and batch coverage before executing deliveries.
The preceding planner already assesses these supplied-source consistency claims;
the delivery adapter does not replace full-batch preflight or human authorization.
Structural review rows are refused by this writer version; semantic uncertainties
are preserved rather than converted into source truth or accepted state.

## Verification scope

Unit tests exercise uncertain outcomes, exact replay, read-only reconciliation,
missing/tampered evidence, conflicting receipts, unsupported plan promotions and
privileged SQL account rejection. They do not establish actual database permissions.

The real-driver checker uses five interruption points for each of the three source
types: after SQL preparation, before Mongo insert, after Mongo insert, before receipt,
and after receipt. It uses real PostgreSQL transaction bodies/savepoints and a
separate synthetic Mongo database with the same SRB contract and restricted role.
Fixtures exercise actor lookup, encrypted station support and recovered cross-file
restriction/transfer references, including a preserved cancelled-transfer claim.

SQL fixtures and temporary SRB source registration are rolled back; only the isolated
Mongo fixtures/users/roles are removed. Existing research counts and applied revision
c95e3a17bd40 must remain unchanged. Production encryption keys are not used.

Savepoint checks do not prove independent durable commits. SqlSrbLedger uses fresh
connections to verify commits, and the forthcoming guarded importer must exercise
and reconcile those production commit paths before declaring the import complete.
Human RBAC/ABAC, classification, authority verification and state reconstruction remain
pending. Stage 2 remains in progress.
