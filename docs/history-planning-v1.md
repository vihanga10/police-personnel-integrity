# Transfer and promotion planning v1

## Scope and checkpoint

Baseline: clean `feat/identity-resolution` at `94c3944`.
The PF profiles and HR service evidence have been imported and reconciled.
Historical inspection identified 33,316 transfer rows and 13,974 promotion rows.
This step prepares plans and exercises authenticated encryption in memory. It does
not import historical records, create Mongo collections, grant access, or append
classification decisions. Stage 2 remains in progress.

## Source preservation and interpretation

Every source column is preserved with its original string inside the encrypted
plan: 35 transfer columns and 21 promotion columns. Target fields follow the
existing field-routing contract. Strict ISO dates are calendar-parsed but remain
reported claims. Effective date interpretation and authority verification are
separate pending tasks. `valid_from` and `valid_to` remain unknown.

Known rank and unit labels use the versioned service dictionary. Unknown labels
require review; there is no fuzzy mapping. Category labels remain reported text
with an unknown category code. Unit names and authority identities remain
unresolved. Boolean text accepts the inspected TRUE/FALSE vocabulary only.
Reported durations are nonnegative numeric claims, not reconstructed periods.
Missing previous-posting fields are never filled from current service details.

Station code/name pairs require a single exact match in the staged station source.
Even a matched reference has unknown historical applicability. Missing pairs are
preserved; incomplete, ambiguous or conflicting pairs require review.

Cancelled transfers are retained in full. Missing cancellation evidence or a
FALSE flag accompanied by cancellation evidence requires review. Cancellation
effect remains unassessed. Chronology observations preserve both reported dates;
they do not automatically declare an order invalid or forbid retrospective effect.

## Identity, encryption and disclosure

The read-only checker verifies exact encrypted NIC candidate evidence using
primary and backup keys. Candidate linkage is not an accepted historical identity
decision: identifier eligibility at the event date remains unassessed.
Source confirmation, archive membership, headers, row counts, sequence and source
bindings are checked before reporting aggregate results.

Authenticated encryption binds each plan to its source filename, raw row ID,
officer UUID and policy versions. Plans contain source and identifier evidence
references. Primary and backup recovery must agree. No personnel values or
plaintext plans are written to reports. Ciphertexts are exercised in memory only.
Authority assessment is NOT_RUN with no result; record classification remains
UNASSESSED. This step enables no human disclosure or authorization.

CID/CCIB event mentions must not be treated as verified service periods, current
assignments or permission grants. Historical protection must survive a transfer.
Promotion rows lack explicit unit-type columns, so their absence cannot establish
that a promotion is ordinary. Unknown classification remains protected pending
classification and application authorization.

## Validation and next boundary

Synthetic unit checks cover exact field preservation, missing evidence,
cancellation conflicts, station references, calendar dates, chronology,
identifier formatting, policy guards, encrypted recovery and tamper rejection.
The CLI uses a PostgreSQL REPEATABLE READ, READ ONLY transaction and no Mongo
connection. Planning PASSED means coverage and encryption recovery succeeded;
review counts and uncertainty counts remain separate and must be reviewed.

After reviewing the real planning output, implement and test append-only encrypted
historical destinations and recoverable delivery adapters. Verify rollback-only
schema checks and isolated driver recovery before migrations and imports. Real
historical imports require reconciliation before proceeding to classification,
RBAC/ABAC, approval workflows and access logging. Neither Stage 2 nor Stage 3 is
claimed complete by this package.
