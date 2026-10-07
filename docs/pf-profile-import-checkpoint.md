# PF personal-profile import checkpoint

Verified from execution output supplied on 2026-10-07.
Code commit: `899d6ba`. Applied schema revision: `e62c9a01bd47`.

- Implementation tests: 114 passed, 38 subtests passed.
- Rollback-only migration/writer check: 41 checks passed; original schema restored.
- Permanent migration applied; Alembic check found no new upgrade operations.
- Real-source validation: 6596 plans before writes.
- Initial import: 6596 CREATED outcomes.
- Read-only reconciliation: 6596 VERIFIED_EXISTING outcomes, no missing receipts.
- All post-import table counts matched.

| Table | Verified rows |
|---|---:|
| identity.officer | 6596 |
| identity.officer_identifier_version | 23966 |
| identity.source_assertion | 30562 |
| staging.profile_transform_receipt | 6596 |
| identity.officer_name_version | 6596 |
| identity.officer_address_version | 6596 |
| identity.officer_demographic_version | 6596 |
| identity.officer_family_relation | 6596 |
| identity.officer_physical_profile_version | 6596 |
| identity.officer_previous_employment_version | 1187 |
| identity.officer_restricted_profile_version | 6596 |
| identity.officer_contact_version | 13192 |
| identity.source_assertion_classification | 0 |

Normalized PF destination versions total 53955. This is not an officer count.
Unknown snapshot/measurement/effective dates remain unknown. Age comparison and
measurement plausibility remain unassessed. All original values remain protected
in encrypted staging and source assertions. Security classification is UNASSESSED;
no user disclosure, RBAC/ABAC or blockchain completion is claimed.

Retained development attempt directories (outside Git):
- Validation: 740f0550-f1c8-4dd0-b44d-c9e01dbf3d10
- Import: e93a6e6b-e879-4255-a949-c3413944dac6
- Reconciliation: b9fb7aee-ea0c-493a-b8b5-099660e6e835

This completes the PF personal-profile import substep. Stage 2 remains in
progress: remaining source transformations, protected MongoDB records and
classification evidence are still pending. Stage 3 is not complete.
