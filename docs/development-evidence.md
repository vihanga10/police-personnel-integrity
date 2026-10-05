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