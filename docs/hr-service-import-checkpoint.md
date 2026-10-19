# HR service import and reconciliation checkpoint

User execution outputs verified on 2026-10-07, Asia/Colombo.

- Importer source committed and pushed as `66f1082` on feat/identity-resolution.
- SQL revision `f73a0c94de21`; Alembic check reports no schema differences.
- 91 focused unit tests passed; five real-driver interruption cases passed using
  rollback-only SQL and an isolated synthetic Mongo database.
- Initial read-only validation: 6,596 PLANNED service rows, no database writes.
- Controlled import: 6,596 COMPLETED deliveries. Preparation commits and completion
  commits were independently recovered through fresh SQL connections; Mongo
  documents were verified against their original encrypted preparations.
- Read-only reconciliation: 6,596 VERIFIED_EXISTING outcomes; no database writes.
- Post-import counts matched: officers 6,596; identifiers 23,966; source assertions
  37,158, including 6,596 HR_SERVICE_EVIDENCE assertions; source systems two;
  service preparations 6,596; service completion receipts 6,596; Mongo
  police_operations.service_status_events 6,596; source classifications zero.
- PF profile receipt count remained 6,596. Name/address/demographic/family/physical/
  restricted profiles remained 6,596 each, contacts 13,192 and previous employment
  1,187. Existing evidence was preserved.

Private attempt directory identifiers:

- Validation: 09dc6790-7091-498b-87cb-bf3590a83328
- Write: d421225b-6cfa-4d42-bad0-903829ca1b41
- Reconciliation: 827dcfc2-6ad3-4259-a3bd-335b5cf21147

Directories remain in the user's protected ResearchEvidence service-import-attempts
root. This checkpoint includes no personnel values, passwords or keys.

Classification and historical NIC eligibility remain UNASSESSED. Source
independence, snapshot applicability and effective-time semantics remain unknown.
No user disclosure or verified-current-state claim is enabled. The service import
checkpoint is complete; Stage 2 as a whole remains in progress. Remaining source
transformations, classification, human RBAC/ABAC, algorithms, audit and blockchain
anchoring still require implementation and their own verification.

Next: read-only transfer/promotion source inspection before historical planning.
