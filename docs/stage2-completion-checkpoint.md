# Stage 2 completion checkpoint — received batch v1

Status: COMPLETE for the received BATCH-RAW-001 storage checkpoint.
Recorded: 2026-10-08 (Asia/Colombo), from the operator-supplied successful final review output.

This checkpoint records completion of controlled intake, encrypted staging, protected transformations and destination reconciliation for this received batch. It does not establish source truth, historical identity, authority, independent corroboration or permission for human disclosure. Classification remains UNASSESSED.

## Evidence of completion

The final read-only runner `app.identity.review_stage2` reported:

> Stage 2 received-batch storage review: PASSED

Exact SQL row coverage, encrypted destination reconciliation and final PostgreSQL/MongoDB counts passed. All eight reconciliation workflows returned VERIFIED_EXISTING for their complete expected source sets. The review reported no database writes or plaintext exports.

The private aggregate attempt ID is `36e07bf0-b02e-4802-9854-c1d6339e4db2`, retained outside Git under the operator's `ResearchEvidence/police-personnel-integrity/stage2-review-attempts` directory. Child journals preserve the concrete review context. This document does not export those journals, credentials or source values. The exact review source commit is not transcribed here because it was not supplied in the posted final output; retain it with the private attempt evidence rather than guessing a revision.

Registered archive SHA-256: `32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2`.
Source-confirmation SHA-256: `b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481`.
Applied reference-storage migration previously verified: `b40d8f62ac95`.

## Received source coverage

Source codes below follow the pinned intake confirmation. They describe reported supplying sources, not independently verified provenance. NPC mentions in PF complaints do not constitute a separately received NPC dataset.

| File | Supplying source | Rows |
| --- | --- | ---: |
| officer_personal_information.csv | PF_REGISTRY | 6,596 |
| officer_service_information.csv | POLICE_HR_IS | 6,596 |
| transfer_history.csv | PF_REGISTRY | 33,316 |
| promotion_history.csv | PF_REGISTRY | 13,974 |
| officer_police_numbers.csv | SRB | 15,123 |
| officer_restrictions.csv | SRB | 10,971 |
| restriction_overrides.csv | SRB | 150 |
| officer_duty_periods.csv | SRB | 3,138 |
| officer_firearms_expertise.csv | SRB | 30,348 |
| good_conduct_register.csv | SRB | 2,779 |
| bad_conduct_register.csv | SRB | 370 |
| officer_education.csv | POLICE_HR_IS | 6,596 |
| officer_family_details.csv | POLICE_HR_IS | 6,596 |
| operations.csv | PF_REGISTRY | 19,554 |
| court_details.csv | PF_REGISTRY | 9,538 |
| public_complaints.csv | PF_REGISTRY | 998 |
| _demotions_enacted.csv | PF_REGISTRY | 8 |
| station_master.csv | POLICE_HR_IS | 607 |
| sri_lanka_police_stations_sinhala.csv | POLICE_HR_IS | 607 |

Seventeen personnel files contain 166,651 rows; two reference files contain 1,214 rows. Total: 19 files and 167,865 rows. These are source rows, not distinct officers. The research identity universe contains 6,596 officers; this checkpoint does not establish a verified current-unit cohort.

## Reconciled destination checkpoint

| PostgreSQL destination or receipt group | Count |
| --- | ---: |
| identity.officer | 6,596 |
| identity.officer_identifier_version | 23,966 |
| identity.source_assertion | 153,923 |
| identity.remaining_source_assertion | 36,694 |
| identity.reference_source_assertion | 1,214 |
| identity.source_system | 3 |
| identity.source_assertion_classification | 0 |
| Profile transform receipts | 6,596 |
| Service preparations / completions (each) | 6,596 |
| History preparations / completions (each) | 47,290 |
| SRB preparations / completions (each) | 26,244 |
| Activity preparations / completions (each) | 36,635 |
| Remaining preparations / completions (each) | 36,694 |
| Family transform receipts | 6,596 |
| Reference preparations / completions (each) | 1,214 |
| Family relationships, PF and HR combined | 15,585 |
| Preserved PF father claims | 6,596 |
| HR family relationship claims | 8,989 |
| Family civil-event claims | 5,245 |
| Next-of-kin claims | 6,596 |
| Unresolved source attestations | 6,596 |

Previously imported profile destinations remain reconciled: names, addresses, demographics, physical profiles and restricted profiles each contain 6,596 versions; previous employment contains 1,187; contacts contain 13,192. Remaining and reference assertions outside UNASSESSED: zero.

| MongoDB collection in police_operations | Count |
| --- | ---: |
| service_status_events | 6,596 |
| transfer_events | 33,316 |
| promotion_events | 13,974 |
| police_number_intervals | 15,123 |
| restriction_records | 10,971 |
| restriction_overrides | 150 |
| duty_periods | 3,138 |
| firearms_assessments | 30,348 |
| good_conduct_records | 2,779 |
| bad_conduct_records | 370 |
| education_records | 6,596 |
| operation_records | 19,554 |
| court_records | 9,538 |
| complaint_records | 998 |
| demotion_events | 8 |
| station_reference_records | 607 |
| station_sinhala_reference_records | 607 |

## Preserved unresolved observations

These observations remain research inputs. Counts can overlap; they are not a combined error total. Successful parsing, candidate matching, source flags and signatures do not establish truth or authority.

| Observation | Retained count / meaning |
| --- | --- |
| Transfer duration field review | 30 rows with invalid reported nonnegative integers |
| Reported cancelled transfers | 118; cancellation effect remains unassessed |
| Police-number missing end dates | 10,774; not explicitly open valid periods |
| Restrictions missing removal dates | 10,137; not proof of active restrictions |
| Override claims | 150 preserved; none automatically applied |
| Firearms missing second-half core blocks | 1,614; not proof of completion or competency |
| Complaint alternate subject NICs without candidates | 240; retained structural review |
| Complaint linked_case_no without provisional operation-key match | 343; reference meaning unassessed |
| Complaint linked_court_case_no without reported key match | 6; unresolved |
| Multi-person remaining assertions without a primary officer | 29,092; no invented sole subject |
| Station bilingual joint candidates | 605 under each of three comparison modes; these are the same rows, not 1,815 mappings |
| Sinhala station structural review | 2 unresolved labels |
| Master repeated Sinhala-label review | 2 rows; may overlap reference observations |

NPC and HRC mentions lack independently received target catalogs. Transfers, punishments and other reference domains require their own linkage assessments. Full Sinhala-label comparisons and bilingual component comparisons use different rules; neither establishes accepted station identity. Station coordinate reference systems, accuracy, code stability, hierarchy and historical validity remain unassessed.

Family participant structures, reported ages, civil dates, certificates and attestations remain claims. HR family evidence has not replaced the preserved PF father claims. Historical identity eligibility, source independence, reported date semantics, authority/delegation, restrictions, override effects and other source-reported outcomes remain unassessed throughout.

## Completion boundary and next stage

Stage 2 is closed for this received batch. Later batches or altered source/route policies require their own controlled intake and reconciliation. This is a controlled development checkpoint, not a distributed snapshot or concurrent-ingestion certification.

Encryption and technical account restrictions have been checked through the preceding storage and recovery checks. Data-use authorization, authenticated human access enforcement and scoped disclosure remain pending; no new human access is granted by this checkpoint.

Blockchain commitments, officer evidence bundles and audit algorithms have not been implemented by this documentation step. Stage 3 will first specify versioned bundle membership and protected commitments, including shared evidence and unresolved identities; then implement anchoring. Audit execution must verify and reference the anchored evidence version. Audit findings and corrections are appended as new versions, preserving earlier evidence, commitments and findings.

See [final review procedure](stage2-final-review-v1.md), [family checkpoint](hr-family-import-checkpoint.md) and [reference checkpoint](station-reference-import-checkpoint.md) for the preceding engineering context.
