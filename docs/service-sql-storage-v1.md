# Service SQL delivery storage v1

This step adds a migration and PostgreSQL adapter, not an officer-import command.
No Mongo collection/schema changes are included. Stage 2 remains in progress.

## Preparation and completion

`staging.service_delivery_preparation` stores one initial delivery per source
row/writer policy, with an opaque event ID, officer/source assertion/NIC evidence
references, confirmation hash, code revision, recorded timestamp and exact BSON
document containing an encrypted service payload. Mongo retries reuse these
bytes, including the original timestamp, event ID and ciphertext nonce.

`staging.service_delivery_completion` appends one receipt for the preparation's
exact SHA-256 digest. A composite foreign key binds the receipt to that event
and digest. A receipt cannot predate its preparation. Neither table contains
plaintext personnel values. PostgreSQL SHA-256 checks the stored BSON digest
without requiring an extension: https://www.postgresql.org/docs/16/functions-binarystring.html .

The preparation and `HR_SERVICE_EVIDENCE` source assertion are committed together.
The assertion reuses the authenticated encrypted service envelope; its context
is reconstructed from the prepared Mongo metadata. The adapter checks originals
against encrypted staging, primary/backup recovery, exact encrypted NIC and HMAC
evidence, officer identity and the planned evidence references. The supplying
source is registered as `POLICE_HR_IS` inside the same transaction if absent;
its independence remains unverified. NIC matching does not establish historical
identifier eligibility, source truth or a verified current officer state.

Database triggers guard source/officer/identifier linkage and reject evidence
UPDATE, DELETE and TRUNCATE. Application grants on the new tables are limited
to SELECT and INSERT. Existing permissions on other tables are not widened.
The app role is a technical account; human HQ Admin/IGP/SDIG authorization is
still a separate pending implementation.

## Commit and recovery boundaries

`SqlDeliveryLedger` uses the existing PostgreSQL application engine. Its
preparation and completion methods return only after their SQL transaction
commits. A stable per-source advisory lock serializes cooperating preparations;
unique constraints remain the final concurrency protection. Completion may be
called only by the delivery protocol after exact Mongo readback. PostgreSQL
cannot independently query Mongo to prove that readback; this is an application
workflow gate, not a distributed SQL constraint.

The transaction-body helpers are used by the rollback checker. They do not
commit on their own and must never be used to write Mongo before the surrounding
SQL transaction commits. The real batch CLI must still verify archive/source
confirmation, candidate uniqueness, complete planning/routing and station-source
evidence before calling this adapter. It must keep pending delivery separate
from completion, support retries/reconciliation and preserve its private attempt
journal. Those CLI and cross-database integration checks are the next step.

Classification remains `UNASSESSED`. No disclosure path is enabled. Source
snapshot, valid-from, valid-to and historical NIC eligibility stay unknown.

## Verification procedure

First run the focused unit tests. Then run `scripts/check_service_storage.py`
before upgrading from `e62c9a01bd47`. It applies the proposed migration inside a
transaction, compares both schemas against model metadata, checks the app's
effective permissions and creates an isolated synthetic staging/officer/NIC
fixture with ephemeral keys. It exercises the real adapter transaction bodies,
including an injected failure after assertion insertion: rollback must retain
neither assertion nor preparation. It also checks exact replay, malformed
provenance/digests, duplicate rejection, completion linkage/order and mutation
guards. Its final rollback removes the proposed schema and all fixtures and
verifies original research counts and the applied revision are unchanged.

The checker reads real data counts and non-personnel source metadata only; it
does not decrypt existing personnel records, load production keys, connect to
Mongo or make a commit. It does not replace later real application-account and
SQL/Mongo recovery integration checks. Stop on any failure; do not apply the
migration or start personnel imports until the failing check is resolved.

Migration `f73a0c94de21` adds only the new tables/functions/triggers/grants. It
does not transform existing profile/identifier evidence. There is no automatic
destructive downgrade; any later recovery migration needs explicit review.
