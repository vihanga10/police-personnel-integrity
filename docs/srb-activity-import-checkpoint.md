# Verified SRB activity import checkpoint

## Source and database evidence

Importer commit: `486e1a0` on feat/identity-resolution.
Applied PostgreSQL revision: `d06f4b28ce51`.
Batch: BATCH-RAW-001. Registered archive SHA-256:
`32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2`.
Source confirmation SHA-256:
`b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481`.

210 focused tests and twenty real-driver interruption cases passed. The real
import completed and read-only reconciliation returned VERIFIED_EXISTING for
all 36,635 activity rows. Separate post-import PostgreSQL/Mongo count checks
passed on 2026-10-07; no personnel values were displayed.

| Source | Assertion type | Mongo collection | Verified count |
| --- | --- | --- | ---: |
| officer_duty_periods.csv | SRB_DUTY_EVIDENCE | duty_periods | 3,138 |
| officer_firearms_expertise.csv | SRB_FIREARMS_EVIDENCE | firearms_assessments | 30,348 |
| good_conduct_register.csv | SRB_GOOD_CONDUCT_EVIDENCE | good_conduct_records | 2,779 |
| bad_conduct_register.csv | SRB_BAD_CONDUCT_EVIDENCE | bad_conduct_records | 370 |

Activity preparations and completion receipts each total 36,635.
Source assertions total 147,327; source systems remain three. Officers remain
6,596 and identifier versions 23,966. Previously imported profile destinations,
service (6,596), transfer (33,316), promotion (13,974), SRB police-number (15,123),
restriction (10,971) and override (150) counts remain unchanged.

## Preserved interpretation limits

All detail payloads remain encrypted. Source assertion classification history
remains empty; record classification is UNASSESSED and no user disclosure is
enabled. Source independence remains UNVERIFIED. Imported dates, roles, scores,
signatures and conduct outcomes remain source claims, not accepted valid periods,
authority, competency, legal effects or verified current state.

The 1,614 missing H2 blocks remain missing. Missing H1/H2/annual signatures
(1,232/2,744/1,227), punishment dates (81) and delegation references (370) are
preserved. Unknown original firearms status text is not mapped to an accepted
status. Previous evidence is not overwritten or deleted.

This completes the SRB activity evidence import checkpoint, not Stage 2.
Remaining HR/PF source planning/imports, master-data applicability and later
classification/authorization, temporal reconstruction, authority verification,
contradiction findings, blockchain commitments and user-facing workflows still
require their own implementation and verification.
