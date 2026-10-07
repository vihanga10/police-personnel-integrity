# Recoverable station reference evidence delivery v1

This step adds an internal delivery protocol, PostgreSQL adapter and isolated driver checker. It is not the guarded importer. No station reference rows, human access grants, accepted mappings or historical station states are created by installation.

## Delivery protocol

1. Validate the reference plan and its source/master provenance envelope. Recover the original staged row with both key copies, recover every master row and rebuild the candidate index independently. Require exact equality of original cells, candidate membership, reported hierarchy context and review metadata.
2. Atomically insert the encrypted reference assertion and preparation in PostgreSQL. A per-source transaction advisory lock serializes cooperating retries; unique constraints remain the final concurrency protection.
3. Commit SQL. The production application adapter reads the saved preparation on a fresh connection and verifies exact BSON, digest, encrypted recovery, provenance and assertion metadata before allowing any Mongo insertion.
4. Insert the saved document into the appropriate reference collection and verify exact document equality through readback.
5. Append a digest-bound SQL completion receipt and verify its committed readback.

A retry generates a new proposal but must recover the original committed winner. Event ID, assertion ID, timestamp, nonce, ciphertext, BSON bytes and digest stay unchanged. A changed source/master snapshot, warning, candidate or payload stops delivery. The original preparation's code revision is retained on a retry; later code cannot relabel it.

A duplicate Mongo response is accepted only if readback proves the identical prepared document. Conflicting evidence is never overwritten. A completion receipt with missing Mongo evidence is an integrity incident and is not silently repaired. Read-only reconciliation requires both the exact Mongo document and matching SQL receipt; it does not finish pending delivery.

## Scope and preserved uncertainty

The two destinations are station_reference_records and station_sinhala_reference_records. The encrypted payload uses the reference planner's plan/evidence shape, preserving all source fields, source file and registered master snapshot provenance. SQL and Mongo metadata contain no officer identifier or accepted station identifier.

Candidate mappings remain candidates. Repeated labels, the two unresolved bracket structures, coordinate review and reported hierarchy text remain preserved. Classification, historical eligibility and linkage remain UNASSESSED. Valid periods, accepted station identity and authority result remain unknown. Production intake authorization and pinned archive/confirmation verification belong to the forthcoming importer; this adapter supports separately staged synthetic batches for isolated checks.

## Verification

Run tests/test_reference_delivery.py with the reference SQL, planner and Mongo contract tests. The tests exercise interruption retries, exact replay, mismatch/missing-evidence refusal, reconciliation without writes, candidate/source reconstruction, stored metadata checks and privileged-account rejection. In-memory fixtures do not verify database permissions.

Run scripts/check_reference_delivery.py only after b40d8f62ac95 is applied and the three SQL reference tables and two Mongo reference collections are still empty. Supply all six private Mongo credential directories using the bootstrap/history/SRB/activity/remaining/reference options used by the reference storage setup.

The checker authenticates existing accounts and verifies research counts/contracts. It stages unrelated encrypted source fixtures using ephemeral keys inside an outer SQL transaction and creates a short random Mongo database with strictly validated reference collections and a find/insert test account. It injects five interruptions for each destination: after SQL preparation, before Mongo insertion, after Mongo insertion, before SQL receipt, and after SQL receipt. Each case verifies reconciliation states, unchanged winner bytes, replay and duplicate-free evidence.

SQL savepoints exercise the transaction bodies and recovery protocol; they do not demonstrate separate durable SQL commits or actual transport outages. SQL fixtures use the migrator. The production adapter restricts itself to police_identity_app and uses fresh-connection commit recovery; that production path remains to be exercised by the guarded importer. No role impersonation or research database permission changes are made by the checker.

The outer SQL transaction is rolled back, the isolated synthetic Mongo database/users/role are removed, and original research counts and revision are verified. Research Mongo payloads and production encryption keys are not used. No personnel or station values are printed. There is no schema migration in this step. Stage 2 remains in progress.
