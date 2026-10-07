# Append-only SQL SRB delivery storage

Migration: c95e3a17bd40, following b84d2f06ac39.

This foundation adds staging.srb_delivery_preparation and
staging.srb_delivery_completion. It imports no personnel evidence, creates no
production SRB source-system row and makes no Mongo connection.

## Preparation and receipt

A preparation binds a delivery UUID to the raw-row digest, subject officer UUID,
source assertion UUID and exact NIC identifier-evidence version. It stores the
confirmation digest, code revision, filename/collection/policy tuple, field review
count, row review count, review state, linkage method, historical eligibility,
exact sealed BSON bytes, BSON SHA-256 digest and recorded time.

Every filename maps to exactly one destination and writer policy:

| Source file | Mongo destination | Writer policy |
| --- | --- | --- |
| officer_police_numbers.csv | police_number_intervals | SRB_POLICE_NUMBER_EVIDENCE_V1 |
| officer_restrictions.csv | restriction_records | SRB_RESTRICTION_EVIDENCE_V1 |
| restriction_overrides.csv | restriction_overrides | SRB_OVERRIDE_EVIDENCE_V1 |

Field review counts are bounded by each source's column count. Row-level issues
remain separate, with a coherent NO_STRUCTURAL_REVIEW or STRUCTURAL_REVIEW_REQUIRED
state. Neither state means source truth, valid authority or approved legal effect.
Historical identifier eligibility remains UNASSESSED.

Unique raw-row/policy and assertion constraints prevent competing preparations.
Foreign keys use RESTRICT rather than cascade deletion. The SQL digest must match
the exact stored BSON. A preparation-insert trigger requires matching active SRB
assertion provenance, registered officer and usable NIC evidence. The assertion
retains unknown valid boundaries and source-recording times, and UNVERIFIED source
independence; reported source dates remain encrypted field claims.

A completion receipt binds both delivery UUID and document digest and cannot
precede the preparation. This proves a consistent SQL receipt relationship; the
later coordinator must verify Mongo delivery before appending a completion.
SQL cannot decrypt BSON or independently prove that Mongo contains it.

## Preservation and permissions

Application permissions are SELECT and INSERT on the two new tables. UPDATE,
DELETE, TRUNCATE, REFERENCES and TRIGGER privileges are withheld. Mutation triggers
also reject accidental UPDATE/DELETE/TRUNCATE by privileged maintenance code.
No automatic destructive downgrade is provided. Existing service/history/profile
storage and application permissions are not altered.

## Rollback-only checker

Run backend/scripts/check_srb_storage.py before applying the migration. It requires
the reconciled research baseline at b84d2f06ac39, temporarily applies the DDL inside
one outer transaction, compares schema/model metadata and checks application ACLs.
Synthetic officer, NIC, assertion and SRB source fixtures use ephemeral keys.
They exercise all three routing contracts, leading-zero and invalid-date preservation,
review metadata, source assertion/preparation atomic rollback, exact BSON recovery,
source binding, digest and receipt constraints, and mutation denial.

The outer transaction always rolls back. A fresh connection verifies original
counts/revision and absence of the new tables/functions. The temporary SRB source
registration is also rolled back; existing source-system count remains two.
The checker does not connect to Mongo or use production encryption keys.

Passing unit tests alone does not establish real PostgreSQL enforcement. Apply
this migration only after the rollback-only driver checks pass, then verify the
applied revision, schema comparison and unchanged research counts separately.
Do not rerun this pre-upgrade checker after the migration has been applied.

## Pending work

The SRB SQL/Mongo delivery adapter, recovery exercise, guarded importer and
reconciliation remain pending. Classification stays UNASSESSED; human RBAC/ABAC,
authority verification and reconstructed restriction/number state remain pending.
All original personal payloads stay encrypted. Stage 2 remains in progress.
