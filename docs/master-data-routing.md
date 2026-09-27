# Master Data Routing Contract

## 1. Purpose

This contract defines how registered research fields are routed into:

1. The isolated PostgreSQL identity/master-data service.
2. MongoDB operational and historical collections.
3. Protected staging and provenance storage.
4. Integrity commitments and blockchain checkpoints.

This contract does not claim that an accepted value is factually correct.
It records what a source asserted, where it was stored and how it can be traced.

## 2. Architecture boundary

### PostgreSQL identity service

PostgreSQL stores protected identity and slowly changing personal information:

- Stable internal officer identity
- Source-specific identifiers
- Names
- Demographic information
- Addresses
- Contact information
- Physical and restricted descriptive information
- Family and next-of-kin information
- Previous-employment information
- Source assertions and correction lineage

### MongoDB operational service

MongoDB stores operational and historical information:

- Promotions
- Demotions
- Transfers
- Service-status history
- Police-number history
- Postings and unit history
- Duty periods
- Restrictions
- Restriction overrides
- Education
- Firearms expertise
- Good-conduct records
- Bad-conduct records
- Complaints
- Operations
- Court records

### Cross-service reference

PostgreSQL creates the immutable `officer_uid`.

Every officer-related MongoDB document must contain:

- `officer_uid`
- `category_code`
- `schema_version`
- `record_version`
- Source/provenance reference
- Valid-time fields
- Transaction-time fields
- Identity-resolution status

MongoDB must not use an NIC, name, police number or regimental number as the
permanent officer reference.

PostgreSQL does not store lists of MongoDB document IDs.

## 3. Core identifier rule

`officer_uid` is a randomly generated UUID that does not contain personal
meaning.

Example:

```text
8a4fe720-806f-4dca-a410-29cf469b92c1

## 4. Personal-information field routing

Source file: `officer_personal_information.csv`

| Source field | Destination | Treatment |
|---|---|---|
| `officer_nic_no` | PostgreSQL | Identifier version, type `NIC` |
| `police_id` | PostgreSQL | Identifier version, type `POLICE_ID` |
| `regimental_no` | PostgreSQL | Identifier version, type `REGIMENTAL_NUMBER` |
| `full_name` | PostgreSQL | `officer_name_version.full_name` |
| `name_with_initials` | PostgreSQL | `officer_name_version.name_with_initials` |
| `father_name` | PostgreSQL | Family relation, type `FATHER` |
| `gender` | PostgreSQL | Demographic version |
| `date_of_birth` | PostgreSQL | Demographic version |
| `age` | Calculated | Calculate from DOB and requested date |
| `place_of_birth` | PostgreSQL | Demographic version |
| `nationality` | PostgreSQL | Demographic version |
| `religion` | PostgreSQL | Demographic version |
| `present_address` | PostgreSQL | Address version |
| `present_address_local_police_station_name` | PostgreSQL reference | Resolve to station reference |
| `height_cm` | PostgreSQL | Physical-profile version |
| `chest_cm` | PostgreSQL | Physical-profile version |
| `blood_group` | PostgreSQL | Restricted-profile version |
| `identifying_marks` | PostgreSQL | Restricted-profile version |
| `mo_remark` | PostgreSQL | Restricted assessment field |
| `marital_status` | PostgreSQL | Demographic version |
| `prev_employment_dept` | PostgreSQL | Previous-employment record |
| `officer_email` | PostgreSQL | Contact version, type `EMAIL` |
| `officer_mobile_number` | PostgreSQL | Contact version, type `MOBILE` |
| `officer_tin_number` | PostgreSQL | Identifier version, type `TIN` |

`age` must not be stored as permanent truth because it changes over time.

## 5. Family-information field routing

Source file: `officer_family_details.csv`

| Source field | Destination | Treatment |
|---|---|---|
| `officer_nic_no` | Identity resolution | Resolve to `officer_uid` |
| `spouse_name` | PostgreSQL | Family relation, type `SPOUSE` |
| `spouse_sex` | PostgreSQL | Related-person gender |
| `spouse_date_of_birth` | PostgreSQL | Related-person DOB |
| `spouse_place_of_birth` | PostgreSQL | Related-person birthplace |
| `date_of_marriage` | PostgreSQL | Civil event, type `MARRIAGE` |
| `reference_Marriage_certificate` | Provenance | Marriage evidence reference |
| `date_of_divorce` | PostgreSQL | Civil event, type `DIVORCE` |
| `reference_divorce_certificate` | Provenance | Divorce evidence reference |
| `date_of_death` | PostgreSQL | Civil event, type `DEATH` |
| `reference_death_certificate` | Provenance | Death evidence reference |
| `children_no` | Source assertion | Preserve declared child count |
| `childern_fullname` | PostgreSQL | One `CHILD` relation per parsed person |
| `children_age` | Source assertion | Preserve reported age; do not treat as permanent age |
| `next_of_near_relative_name` | PostgreSQL | Next-of-kin version |
| `next_of_relative_relationship` | PostgreSQL | Next-of-kin relationship |
| `next_of_relative_address` | PostgreSQL | Next-of-kin address |
| `datails_entry_date` | Provenance | Source entry date |
| `recorded_by_signature` | Protected provenance | Attestation reference |
| `recorded_by_officer_name` | Identity resolution | Resolve recording officer when possible |
| `recorded_by_officer_nic` | Protected identity resolution | Resolve recording officer UID |
| `Certified_signed_date` | Provenance | Certification date |
| `recorded_by_officer_rank` | Provenance assertion | Asserted rank at recording |

Multi-value child fields must use documented parsing rules. If names and ages
cannot be matched reliably, preserve the raw values and create a validation issue.

## 6. Operational dataset routing

| Registered file | Storage | Collection |
|---|---|---|
| `promotion_history.csv` | MongoDB | `promotion_events` |
| `demotion_history.csv` | MongoDB | `demotion_events` |
| `transfer_history.csv` | MongoDB | `transfer_events` |
| `officer_service_information.csv` | MongoDB | `service_status_events` |
| `officer_police_numbers.csv` | MongoDB | `police_number_intervals` |
| `officer_duty_periods.csv` | MongoDB | `duty_periods` |
| `officer_restrictions.csv` | MongoDB | `restriction_intervals` |
| `restriction_overrides.csv` | MongoDB | `restriction_override_events` |
| `officer_education.csv` | MongoDB | `education_records` |
| `officer_firearms_expertise.csv` | MongoDB | `firearms_expertise_records` |
| `good_conduct_register.csv` | MongoDB | `good_conduct_events` |
| `bad_conduct_register.csv` | MongoDB | `bad_conduct_events` |
| `public_complaints.csv` | MongoDB | `complaint_records` |
| `operations.csv` | MongoDB | `operation_records` |
| `court_details.csv` | MongoDB | `court_records` |

A complaint record is not automatically evidence of misconduct, guilt or a
restriction.

## 7. Reference dataset routing

| Registered file | Treatment |
|---|---|
| `station_master.csv` | Station reference collection or service |
| `sri_lanka_police_stations_sinhala.csv` | Sinhala station-name reference |

Identity records store a stable station reference instead of duplicating all
station information.

## 8. MongoDB reference example

```json
{
  "_id": "PROM-0001-V1",
  "officer_uid": "8a4fe720-806f-4dca-a410-29cf469b92c1",
  "category_code": "PROMOTION",
  "schema_version": "1.0",
  "record_version": 1,
  "effective_date": "2024-05-10",
  "transaction_start": "2026-09-26T10:00:00Z",
  "source_assertion_id": "SOURCE-ASSERTION-UUID",
  "identity_resolution_status": "RESOLVED"
}
```

An action involving another officer may contain:

```json
{
  "subject_officer_uid": "SUBJECT-OFFICER-UUID",
  "authority_officer_uid": "AUTHORITY-OFFICER-UUID"
}
```

## 9. Unresolved identity rule

When a source identifier cannot be linked safely:

1. Preserve the received staging row.
2. Do not invent an `officer_uid`.
3. Set the resolution state to `UNRESOLVED`.
4. Record the reason and candidate matches separately.
5. Require an authorized review before linkage.
6. Preserve the original and reviewed resolution history.

Similar names alone are not enough to establish that two records belong to the
same officer.

## 10. Temporal rule

Every versioned fact distinguishes:

- `valid_from` and `valid_to`: when the fact applied.
- `source_recorded_at`: when the represented source recorded it.
- `captured_at`: when the evidence was received or extracted.
- `transaction_start` and `transaction_end`: when the prototype knew it.

Unknown dates remain unknown. Import time must not be presented as the original
source-recording time.

## 11. Provenance rule

Every normalized record must trace to:

- Intake batch
- Source file
- Source-file SHA-256
- Source row number
- Raw staging record
- Represented source system
- Source record or document identifier when supplied
- Transformation version
- Identity-resolution decision

Naming HR, Personal File or SRB as the represented source does not automatically
prove source independence or factual correctness.

## 12. Correction rule

Corrections are append-only:

1. Keep the original assertion.
2. Create a new record version.
3. Link the new version using `supersedes`.
4. Record the correction evidence and review decision.
5. Close the previous transaction-time period when appropriate.
6. Never silently overwrite or delete original evidence.

## 13. Blockchain rule

PostgreSQL and MongoDB store protected records.

The blockchain stores only protected commitments, roots, versions and checkpoint
metadata.

The public blockchain must not receive:

- NIC
- Name
- Address
- Contact information
- Family information
- Raw `officer_uid`
- Narrative records
- Secret cryptographic keys

The published officer commitment must be derived separately from the internal
`officer_uid`.

## 14. Completion gate

The routing contract is complete when:

- Every registered CSV field has an explicit treatment.
- Every operational MongoDB document uses `officer_uid`.
- No personal identifier is used as the permanent cross-service key.
- Unknown, missing and conflicting evidence remain visible.
- SQL master data and MongoDB operational data are not duplicated without a
  documented reason.
- Personal information is excluded from blockchain payloads.