# Remaining HR/PF evidence delivery v1

## Scope

This step adds a recoverable PostgreSQL/MongoDB delivery adapter for 36,694
planned source rows. It does not import research records or change the schema.

| Source file | Mongo collection | Expected rows |
| --- | --- | ---: |
| officer_education.csv | education_records | 6,596 |
| operations.csv | operation_records | 19,554 |
| court_details.csv | court_records | 9,538 |
| public_complaints.csv | complaint_records | 998 |
| _demotions_enacted.csv | demotion_events | 8 |

Family details are excluded. Family encryption migration and the SQL writer
remain required before importing that source.

## Source and identity binding

Before preparation, both key copies recover the staged original. Every source
cell, registered header, file fingerprint, row position and batch fingerprint
must agree with the plan. Identity candidate observations are independently
rediscovered. Single-subject rows also require existing encrypted NIC assertion
and identifier-version evidence. Exact matches do not establish historical
identifier eligibility, authority or source truth.

Operations and courts retain a null single-subject officer and identifier.
Nested participant text is preserved without inventing a primary officer or
accepting participant relationships. Unresolved complaint alternate NICs,
malformed claims and review issues remain encrypted and flagged. The adapter
rebuilds the planner output and rejects altered parsed values, erased issues or
unsupported determinations. Delivering evidence does not resolve its issues.

## Recoverable delivery

1. Commit the new remaining-source assertion and exact BSON preparation together
   in PostgreSQL. A source/policy lock and unique constraints select one winner.
2. Recover the committed preparation using a fresh SQL connection.
3. Insert the exact winning encrypted document into its Mongo collection, or
   verify an identical existing document. Read it back and compare exact bytes.
4. Append the SQL completion receipt and verify it through a fresh connection.

Retries reuse winning IDs, ciphertext, key version and timestamp. A conflicting
Mongo document stops delivery; it is never overwritten. A completed receipt
whose Mongo document is missing stops reconciliation as an integrity incident.
The coordinated protocol, rather than a standalone SQL receipt method, is
responsible for checking Mongo readback before completion.

There is no distributed atomic transaction. An interrupted delivery can leave a
committed preparation or Mongo document awaiting the remaining step. Recovery
preserves and verifies that evidence. Reconciliation performs no writes.

Assertions use identity.remaining_source_assertion; existing
identity.source_assertion records remain unchanged. The adapter reuses existing
PF/HR source registrations and does not grant human import or viewing access.
Classification stays UNASSESSED, independence UNVERIFIED, valid periods unknown,
reported effects unapplied, and authority assessment NOT_RUN.

## Verification

Unit tests exercise five routes, interruption/retry behavior, duplicate races,
conflicting documents, exact encrypted replay, key recovery, metadata binding,
review preservation and independent staged-source verification. These local
tests do not claim a connection to the research databases.

scripts/check_remaining_delivery.py runs 25 interruption cases using real SQL
and Mongo drivers: after SQL preparation, before Mongo insertion, after Mongo
insertion, before the SQL receipt and after the SQL receipt, for all five routes.
It uses ephemeral synthetic keys, rollback-only SQL transactions/savepoints and
an isolated synthetic Mongo database with a restricted technical account.
Research counts and applied revision e17a5c39df62 must remain unchanged. Both new
SQL delivery tables, the remaining assertion table and all five research Mongo
collections must be empty before this check.

The checker verifies transaction bodies and SQL/Mongo recovery. Its SQL changes
are rolled back; independent durable SQL commits through the production adapter
still require fresh-connection verification during the forthcoming importer.
No personnel values or production encryption keys are used by this checker.
Synthetic cleanup is limited to the generated test namespace. Research evidence
is never deleted. Human authorization and guarded import remain subsequent work.
