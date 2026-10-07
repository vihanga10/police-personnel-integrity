# Recoverable historical delivery v1

## Scope

Baseline: clean feat/identity-resolution at 2d09429. Applied SQL revision is
b84d2f06ac39; historical SQL preparations/receipts and Mongo history collections
are empty. This package adds the protocol, real SQL adapter and isolated real-driver
checker. It contains no officer importer, schema migration or human access endpoint.
Stage 2 remains in progress.

## Delivery and recovery

1. Recover the staged original and verify exact NIC support and provenance.
2. Validate the exact versioned plan, including every preserved source field.
3. Atomically commit the source assertion and exact encrypted Mongo BSON preparation.
4. Recover that preparation through a fresh SQL connection after commit.
5. Insert/read back the identical document in the designated Mongo collection.
6. Append the SQL receipt matching the committed preparation digest, then recover it.

Retry always loads the original committed preparation, retaining the original ID,
recording timestamp, nonce and ciphertext. A timeout means an uncertain outcome;
it never authorizes deletion, overwrite or regenerated replacement evidence.
Conflicting Mongo content or receipt digests stop delivery. A completed receipt
with missing Mongo evidence is an integrity incident, not an automatic repair.
Read-only reconciliation does not fill missing documents or receipts.

Per-source advisory locking and SQL uniqueness serialize cooperating writers.
The production adapter accepts only the police_identity_app target and verifies
committed facts with fresh connections. Bootstrap/migrator accounts are not
production evidence writers. Actual independent commit paths are exercised during
the future importer workflow; the synthetic driver checker retains SQL inside an
outer rollback transaction and does not claim independent durable commit testing.

## Evidence preservation and uncertainty

The inspected negative-integer days_in_previous_posting exception is explicitly
allowed as retained evidence only. Original negative text and REVIEW_REQUIRED
status remain; the normalized duration stays NULL. It must not become an accepted
input to period reconstruction or duration arithmetic. Other structural failures
still block delivery. Cancelled transfers stay preserved without determining the
cancellation's historical effect. No authority decision or known valid period is
created. Record classification stays UNASSESSED and human disclosure remains off.

Plans are regenerated from original strings before delivery to prevent replacing
parsed values, erasing review flags, changing policy, inventing applicability or
promoting authority results. SQL independently verifies referenced encrypted
station rows and their code/name/provenance. The upcoming batch import preflight
must also validate the complete station snapshot and name uniqueness; a station
reference is source-scoped with historical applicability UNKNOWN.

All stored personal payloads remain encrypted. The former-service-period summary
exception applies only to a future authorized projection, never full-document
access or plaintext database storage.

## Validation boundaries

Unit recovery tests cover both event types and five interruption points, duplicate
races, missing/conflicting evidence, read-only reconciliation, review preservation,
wrong destinations and privileged SQL-account rejection. They do not establish
actual database permissions or independent durable SQL commits.

check_history_delivery.py uses real PostgreSQL and Mongo drivers with ephemeral
keys and synthetic transfer/promotion fixtures. Transfer fixtures include an
independently staged station reference, a cancelled-order claim and a negative
reported duration. Five interruptions per source type give ten cases. It verifies
exact encrypted replay and SQL/Mongo reconciliation, rolls back all SQL fixtures,
removes only its unique disposable Mongo test namespace, and checks unchanged
research counts and applied revision. No personnel payloads, production keys or
research Mongo writes are used. Guarded real import remains the next step.
