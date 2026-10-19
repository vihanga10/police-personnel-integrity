# Verified remaining HR/PF import checkpoint

Verified on 2026-10-07 after read-only validation, import, reconciliation and
post-import aggregate count checks on the research development machine.

| Source | Mongo collection | Verified existing records |
| --- | --- | ---: |
| officer_education.csv | education_records | 6,596 |
| operations.csv | operation_records | 19,554 |
| court_details.csv | court_records | 9,538 |
| public_complaints.csv | complaint_records | 998 |
| _demotions_enacted.csv | demotion_events | 8 |
| Total | | 36,694 |

identity.remaining_source_assertion, staging.remaining_delivery_preparation and
staging.remaining_delivery_completion each contain 36,694 records.
identity.source_assertion remains 147,327; source_system remains 3 and
source_assertion_classification remains 0. All remaining assertions stay
UNASSESSED. Operations/courts retain 29,092 null primary-officer subjects;
240 complaint rows retain structural review for unresolved alternate NICs.

Previous identifiers (23,966), officers (6,596), profile receipts (6,596), service
preparations/completions (6,596), history preparations/completions (47,290), SRB
preparations/completions (26,244) and activity preparations/completions (36,635)
remain unchanged. Existing profile destinations and all previous Mongo collection
counts also matched the preceding checkpoints. No values or encryption keys were
displayed by the post-import count check.

Family civil-event versions, next-of-kin versions and source attestations remain
empty. The PF encrypted family relation count remains 6,596. HR family storage,
writer, import and reconciliation still require implementation.

Reported outcomes, dates, authority, participant/reference linkage and valid
periods are not accepted by this evidence import. PF supplies the complaint file;
NPC references are not an independently received NPC source. No user disclosure
or verified-current-state claim is enabled. Stage 2 remains in progress.
