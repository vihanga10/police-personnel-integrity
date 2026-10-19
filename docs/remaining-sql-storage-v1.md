# Remaining SQL delivery storage v1

Adds identity.remaining_source_assertion plus staging.remaining_delivery_preparation
and staging.remaining_delivery_completion for education, operations, courts,
complaints and demotions. No family records or Mongo documents are imported.

Existing identity.source_assertion requires one officer and remains unchanged.
The new assertion table permits null officer_uid only for operations/courts;
other sources require a single opaque subject. Event participants stay in encrypted
payloads pending accepted linkage. The new assertion counts are reported separately
from existing source_assertion counts; neither table implies source truth.

Preparations preserve exact encrypted BSON, SHA-256, routing/policy, source raw
record, assertion, recorded time and structural review counts. Single-subject
preparations require a usable NIC identifier version; multi-person preparations
require null officer/identifier and an explicit multi-person linkage method.
No fabricated officer or identifier is permitted. Source/file/custodian, assertion
provenance and unknown valid periods are enforced. Completion binds event ID and
digest and cannot precede preparation. All three tables reject update, delete and
truncate; application ACLs allow select/insert only. Downgrade is blocked.

The rollback-only checker applies schema transactionally, compares ORM metadata,
checks permissions and rejection paths, uses isolated source/crypto fixtures, and
verifies rollback and research count preservation. No Mongo connection or production
keys. Run before upgrade at d06f4b28ce51. Applied revision stays unchanged by checks.

Family schema review: officer_family_relation already holds encrypted payloads,
but officer_family_civil_event_version contains plaintext event_date and event_type;
officer_next_of_kin_version contains plaintext related_person_name and
relationship_type. Therefore their current models are not ready for the agreed
all-detail encryption rule. The checker verifies civil-event, next-of-kin and
source-attestation destinations are empty. Their encryption migration and atomic
family writer remain a separate required step before any family import. Existing
PF family evidence must be preserved. This step does not declare family readiness.

Classification, source independence, authority and historical eligibility stay
unassessed. Stage 2 remains in progress.
