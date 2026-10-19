# SRB number, restriction and override import checkpoint

## Verified operator results — 7 October 2026

Reviewed code: dbdba51 (bounded-period grouping correction), following importer
e973cfc and delivery ddda777. Applied schema: c95e3a17bd40.
Focused tests: 142 passed on the operator's Mac. SRB delivery prerequisite:
15 real-driver interruption/recovery cases passed, with test changes rolled back.

Read-only preflight attempt: 6c8b3a97-32c2-4eaa-aba2-85f5aaea9c4a.
Write output reported all source rows COMPLETED; its attempt UUID was not supplied.
Read-only reconciliation attempt: 4a1873f2-8253-4171-a971-8621b5d9e642.
All 26,244 rows reconciled as VERIFIED_EXISTING; no reconciliation writes.

| Evidence | Rows / Mongo documents |
| --- | ---: |
| officer_police_numbers.csv / police_number_intervals | 15,123 |
| officer_restrictions.csv / restriction_records | 10,971 |
| restriction_overrides.csv / restriction_overrides | 150 |

Post-import aggregate checks passed: officer=6,596; identifiers=23,966;
source_assertion=110,692; source_system=3; source_assertion_classification=0;
profile receipts=6,596; service preparations/completions=6,596 each;
history preparations/completions=47,290 each; SRB preparations/completions=26,244 each.
The three SRB assertion types matched 15,123 / 10,971 / 150.
Existing Mongo service/transfer/promotion counts remained 6,596 / 33,316 / 13,974.
All prior profile destination counts remained unchanged.

## Preserved uncertainty and disclosure boundaries

Zero structural review rows. Missing number ends=10,774; missing restriction
removals=10,137; preserved unapplied override claims=150. These counts do not
establish open validity intervals, active restrictions or authorized overrides.
Category vocabulary, temporal eligibility, date semantics, actor authority,
delegation, legal effect and source independence remain unassessed/unverified.
All stored personal detail payloads remain encrypted. Classification remains
UNASSESSED and no human user disclosure is enabled by this workflow.
No personnel evidence was deleted or corrected by reconciliation/count checks.
Stage 2 remains in progress: remaining source transformations and classification
still require implementation and verification.
