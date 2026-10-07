# PF historical import and reconciliation checkpoint

Verified from the project owner's execution outputs on 2026-10-07 (Asia/Colombo).

- Source commit: `e262d1f` on `feat/identity-resolution`.
- SQL revision: `b84d2f06ac39`; preceding Alembic check found no schema differences.
- Focused tests: 123 passed and 25 subtests passed.
- Earlier real-driver recovery exercise: ten interruption cases passed using
  rolled-back SQL transactions and isolated synthetic Mongo fixtures.
- Read-only validation: promotion 13,974 and transfer 33,316 planned deliveries.
- Controlled import: all 47,290 deliveries completed.
- Read-only reconciliation: all 47,290 returned VERIFIED_EXISTING, with no database writes.
- Independent SQL counts: 47,290 historical preparations and completions each;
  84,448 source assertions; two source systems; zero assertion classifications.
- Independent Mongo counts: promotion_events 13,974; transfer_events 33,316;
  service_status_events unchanged at 6,596.
- Officer count remained 6,596; identifier versions 23,966; profile receipts 6,596;
  service preparations and completions 6,596 each. All checked profile counts
  remained unchanged (contacts 13,192; previous employment 1,187; other imported
  profile destinations 6,596 each).
- Thirty transfer rows retain field-review flags for negative reported durations.
  No replacement duration was inferred or written.
- 118 source-reported cancelled transfers remain preserved. Cancellation effect
  has not been accepted as a verified change of historical state.

Private attempt identifiers:

- Validation: e7cecf9f-96ca-4a2f-92ef-ec432ed3dd63
- Import: 992c2c0a-9a34-4059-8b69-8d22b270d41d
- Reconciliation: 89b390a1-c133-42c0-b58c-028817f4dc91

Payloads remain encrypted for all officers. Ordinary scoped disclosure and
restricted CID/CCIB disclosure require the agreed application authorization,
which is not implemented by these importers. Classification remains UNASSESSED.
Historical NIC eligibility, authority, source independence, cancellation effect
and valid service periods remain unassessed. This checkpoint establishes delivery
and recovery, not source truth or verified current state. Stage 2 remains in progress.

Next: inspect SRB police-number, restriction and override evidence before planning.
