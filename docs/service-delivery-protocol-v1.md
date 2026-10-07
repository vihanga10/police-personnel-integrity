# Service delivery recovery protocol v1

This step implements the recovery core. It does not add SQL tables, connect to
either database or enable a personnel import command. The concrete PostgreSQL
adapter, migration, source-link acceptance and batch importer are next.

## Required order

1. Validate the exact service plan and its established source/officer references.
2. Seal a Mongo envelope and recover it with primary and backup encryption keys.
3. Commit the source assertion and exact prepared BSON envelope together in SQL.
   Unique source-row/writer-policy constraints choose one committed winner when
   multiple workers prepare the same source. The preparation contains the event
   ID, recorded timestamp and encrypted content, including its nonce/key version.
4. Read Mongo by source-row/writer-policy. Insert only when absent. If another
   worker wins insertion, require exact readback equality; do not trust a duplicate
   error alone. Existing conflicting evidence stops the workflow.
5. Verify the saved Mongo document matches the committed preparation.
6. Append one immutable SQL completion receipt for that preparation digest.

PostgreSQL and MongoDB are not one atomic transaction. A prepared row without a
completion receipt is pending delivery, not a completed service import. SQL
adapter methods must return only after commit and validate SQL evidence linkage.
They must never update existing evidence or delete records to compensate for a
failure. A timeout can mean an operation committed despite a lost acknowledgment.
Retry must load the original committed preparation, never reseal it or silently
replace its event ID, timestamp or ciphertext.

A completion receipt is evidence of successful delivery at its recorded time.
Every retry still checks Mongo. If completed evidence is now missing or differs,
stop for an integrity investigation; do not silently recreate it.

Read-only reconciliation requires both exact Mongo evidence and its matching SQL
receipt. It does not insert records, append receipts or fix discrepancies.

## Encryption and temporal rules

The envelope preserves all 32 planned source fields, their original text,
parsed/missing status, issues, reference evidence and uncertainties. Primary and
backup keys must recover an identical payload equal to the supplied source plan.
No personnel values are placed in envelope routing metadata. Event, officer,
assertion, raw-row, policy, key version and recorded timestamp are authenticated.
Recorded timestamps use UTC millisecond precision to match BSON storage.

Classification remains `UNASSESSED`; no user disclosure is enabled. Snapshot
date, valid-from and valid-to remain unknown. A transaction recording timestamp
does not establish a source snapshot date or a service-state effective date.

## What the tests establish

Failure-injection tests cover interruption after SQL preparation, before/after
Mongo insertion and before/after SQL completion; replay must preserve one exact
event and one receipt. Tests also cover conflicting evidence, changed source
plans, corrupted receipts, missing completed evidence, insertion races and
read-only reconciliation. Their in-memory adapters model commit boundaries;
they do not establish production SQL transaction, constraint or permission
correctness. Real adapter integration and rollback/permission checks are still
required before any officer service import.

Stage 2 remains in progress. This protocol is one necessary part of coordinated
service import, not completion of the service-import stage or human RBAC/ABAC.
