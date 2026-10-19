# Development Evidence Log

## 5 October 2026 — Identity evidence protection

Branch: `fix/identity-evidence-protection`
Database revision: `8757cc30d835`

### Implemented

- Replaced plaintext source-assertion payload storage with ciphertext
  and an encryption-key version reference.
- Implemented AES-GCM encryption and keyed identifier lookup.
- Separated encryption keys from lookup keys.
- Excluded local secret keys from Git.
- Restricted evidence updates to one-time version closure.
- Added version-link checks for officer ownership, chain identity,
  consecutive version numbers and predecessor closure.
- Added unique predecessor indexes to prevent multiple direct replacements.

### Verification results

| Verification | Result |
|---|---|
| Python metadata and encryption tests | 21 passed |
| Saved evidence-update checks | 5 passed |
| Saved officer/version-link checks | 5 passed |
| Saved family-chain checks | 2 passed |
| Alembic schema comparison | No new upgrade operations detected |

All database test scripts ran as `police_identity_app`.
Each script ended with `ROLLBACK`, leaving no test records.

### Report connections

- Chapter 4: implementation and rationale for evidence protection,
  encryption and correction-version controls.
- Chapter 5: functional verification evidence.
- These checks are not research accuracy results or baseline comparisons.

### Limits of current verification

- Encryption is not yet integrated with intake or API workflows.
- Database behavior checks cover source assertions, names and family
  relationships; they do not exercise every protected table.
- Concurrent replacement attempts have not been tested.
- Correction authorization and supporting review evidence are not yet enforced.
- End-user authentication and organizational access scopes are not implemented.
- Secret-key recovery and backup procedures remain to be documented.
- Original CSV data has not yet been imported.

### Remaining implementation

- Complete field-routing and temporal contracts.
- Define evaluation cases, baselines and success criteria.
- Build protected intake, staging and validation.
- Implement identity resolution and SQL/MongoDB transformations.
- Implement authentication, scoped access control and access logging.
- Implement historical reconstruction and reproducible snapshots.
- Implement commitments and individual officer-root publication on both chains.
- Implement authority and contradiction algorithms.
- Implement findings, authorized review and evidence-backed corrections.
- Build APIs and frontend workflows.
- Run research evaluations and document measured limitations.

## Controlled intake and protected staging — 2026-10-05

Batch: `BATCH-RAW-001`

### Verified results

- Archive integrity and CSV structure checks passed for 19 files.
- All 443 registered fields have draft routing instructions.
- 167,865 source records were committed to encrypted PostgreSQL staging.
- Database file metadata, per-file counts and row numbering matched the manifest.
- The full-batch attempt contained 40 events with matching file outcomes.
- Attempt ID: `313d7d4e-10a0-48ba-8973-ecb0fe5ce067`.
- Reimporting the eight-row demotion file returned VERIFIED_EXISTING.
- Backup keys successfully decrypted the eight committed demotion rows.
- The latest reported automated suite passed 63 tests, including
  PostgreSQL integration tests.

### Scope and remaining work

These results establish the tested intake, staging and recovery behaviours.
They do not establish source authenticity, personnel-claim accuracy,
authority validity or full research-system completion.

Remaining work includes:
- Whole-batch repeat-import and concurrent-import verification.
- Recovery using storage separate from the laptop.
- Resolution of ambiguous source-field semantics.
- Identity resolution and normalized identity/operational imports.
- Historical reconstruction, authority checks, contradiction detection,
  blockchain publication and end-user workflows.

## PF identity registration pilot — 2026-10-06

- Backend revision: `ccf5266be03c2b9cf025dbce9e83d305886c8a53`.
- Batch: `BATCH-RAW-001`.
- Input: first data row of `officer_personal_information.csv`.
- Reported supplying source: `PF_REGISTRY`.
- Attempt: `6c8585d7-5685-4ed5-8114-d6914890b4f0`.
- First registration outcome: `CREATED`.
- Reason: `PF_PROFILE_WITH_NO_EXISTING_CANDIDATE`.
- Committed pilot records: 1 officer, 4 source assertions,
  4 identifiers and 1 registration decision.
- Retry using protected backup keys: `VERIFIED_EXISTING`.
- Retry duplicate check: passed.
- Protected attempt evidence is retained outside the repository.
- Personnel values were not displayed.

Before the pilot, all 146 tests passed, including 14 registration-service
integration tests. These service tests require an empty identity registry;
subsequent runs need an isolated test database.

Remaining verification includes successful concurrent commits in an isolated
test database. Lock contention and transaction rollback have been tested.
Full-batch identity registration has not yet run. Source independence and
source truth remain unverified.

## Full PF identity registration — 2026-10-06

- Batch: BATCH-RAW-001.
- Registration command and tests committed through abc6d60.
- Attempt: a771d6ac-ae2d-4ac7-81f6-7e53781f7136.
- Staged-profile validation and backup-key recovery passed for 6,596 rows.
- Attempt outcomes: 6,595 CREATED, 1 VERIFIED_EXISTING,
  0 MATCHED and 0 REVIEW_REQUIRED.
- Database totals: 6,596 officers, 23,966 identifier versions,
  23,966 source assertions and 6,596 registration decisions.
- Journal/database reconciliation passed for 13,194 events
  and 6,596 decisions.
- Protected report: decision-reconciliation.json in the attempt directory.
- No personnel values were displayed in verification output.

These results demonstrate registration consistency under the current PF
policy. They do not establish source truth or source independence.

Remaining work includes profile and family transformations, MongoDB
operational transformations, historical reconstruction, authority checks,
contradiction detection, blockchain commitments and user workflows.
