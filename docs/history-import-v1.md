# Guarded PF historical import v1

## Preconditions and scope

Baseline: clean feat/identity-resolution at 4537d42. SQL revision b84d2f06ac39
is applied and verified; historical preparations/receipts and Mongo history
collections are empty. Ten isolated real-driver interruption cases passed.
This package adds the guarded importer and tests, not a migration or user API.
HQ Admin human authentication/authorization remains pending; this local development
workflow must not be exposed as an unrestricted upload endpoint.

## Modes and source contract

Default mode validates without database writes. --write performs recoverable
append-only delivery. --reconcile is read-only and requires every row to have a
verified Mongo document and SQL receipt. Write and reconcile are mutually exclusive.

The first workflow is pinned to BATCH-RAW-001, the reviewed archive and confirmation
fingerprints, 33,316 transfer rows and 13,974 promotion rows. It requires clean,
committed source, separate primary/backup key paths, the SQL application account,
and the dedicated Mongo history account. It rejects changed headers/membership,
row gaps, source IDs duplicated within a file, unresolved linkage and unsupported
structural review. Repeated officer rows are allowed as legitimate history.

Both files are fully preflighted before the first write. Exact encrypted NIC
evidence, preserved original values, canonical plans and complete station snapshot
are checked. Historical identifier eligibility, authority, source independence,
station applicability and valid periods remain unassessed/unknown.

The archive-pinned checkpoint requires 30 transfer rows retaining negative duration
review, no promotion structural review and 118 cancelled transfer observations.
The negative values stay encrypted, REVIEW_REQUIRED and unnormalized; they are not
accepted durations. Cancelled transfers are retained without deciding cancellation
effect. Any changed anomaly/chronology count stops before writing.

## Delivery and retry

Each row is replanned before delivery and compared to its preflight keyed HMAC.
A linkage/source change stops the run. The adapter commits assertion and exact
Mongo BSON preparation atomically, independently recovers committed SQL bytes,
performs Mongo insert/readback, and appends/recovers a matching completion receipt.
Retries reuse the original committed ciphertext/IDs/timestamp. Evidence is never
overwritten/deleted to resolve disagreement or an uncertain acknowledgment.

Preflight checks existing SQL preparations, full Mongo document recovery and
receipt digests. Unexpected/orphan documents or source assertions fail validation.
Already verified rows are recognized; unfinished rows may resume only in write
mode. A completed receipt with missing Mongo evidence requires integrity review.

A private owner-only attempt directory outside Git records ordered local-session
progress and source-row references without personnel values, keys or plaintext
plans. SQL/Mongo evidence supplies the durable recovery facts. These local journals
are not substitutes for the later human access-log and approval implementation.

## Expected final reconciliation

After a successful complete import, expect:

| Storage | Count |
|---|---:|
| identity.source_assertion | 84,448 |
| staging.history_delivery_preparation | 47,290 |
| staging.history_delivery_completion | 47,290 |
| police_operations.transfer_events | 33,316 |
| police_operations.promotion_events | 13,974 |

Officer, identifier, profile and service evidence counts remain unchanged;
source systems remain two and classification decisions remain zero. Default
validation before the first write instead reports all 47,290 rows as PLANNED.
Run read-only reconciliation and independent aggregate count checks after writing.

Classification remains UNASSESSED and no human disclosure is enabled. Stored
reported events are not verified current state or accepted reconstructed periods.
Encryption remains applied to all personal payloads, including future authorized
former-service summaries. This import checkpoint does not complete Stage 2 or 3.
