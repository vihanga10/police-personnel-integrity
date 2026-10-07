# Protected Mongo activity storage v1

## Scope and prerequisite checkpoint

Install four empty collections in police_operations: duty_periods,
firearms_assessments, good_conduct_records and bad_conduct_records. Source planner
checkpoint 6d74f8f covers 36,635 rows with zero structural review rows. It is not an
activity import or an accepted history/authority decision. Firearms record_status
meaning remains unassessed and original values stay preserved as encrypted claims.

Existing reconciled evidence must remain unchanged: service_status_events=6,596;
transfer_events=33,316; promotion_events=13,974; police_number_intervals=15,123;
restriction_records=10,971; restriction_overrides=150. New activity stores must
remain empty during this foundation step. There is no PostgreSQL migration.

## Envelope, indexes and access

Reuse the established encrypted opaque envelope shape with distinct writer policies:
SRB_DUTY_EVIDENCE_V1, SRB_FIREARMS_EVIDENCE_V1, SRB_GOOD_CONDUCT_EVIDENCE_V1 and
SRB_BAD_CONDUCT_EVIDENCE_V1. Additional properties and plaintext personnel fields
are rejected. Classification is UNASSESSED. Ciphertext must be binary and large
enough for the envelope, but only authenticated recovery establishes encryption.
Encryption context binds collection, opaque provenance, writer policy, key version
and millisecond UTC recording timestamp. Unique source/policy index prevents duplicate
source delivery; officer/time index supports scoped retrieval later. No TTL index.

Dedicated account police_activity_app has only role activity_evidence_append_v1:
find and insert on the four activity collections. Existing service/history/SRB
roles and accounts are verified and never broadened. No application update/delete,
schema change, validation bypass, cross-group read or inherited broad roles.
Bootstrap administrative capability remains a separate technical credential;
these database accounts do not implement or replace human RBAC/ABAC.

Private new credentials: ~/ResearchKeys/police-personnel-integrity/mongo-activity-v1.
Directory mode 700 and credentials.json mode 600; reject symlinks and shared
credential directories. Exclusive creation does not overwrite existing passwords.
No password values are printed. Setup creates only missing resources and refuses
unexpected roles, users, collections, contracts, indexes or nonempty activity stores.

## Real-driver check boundaries

Research mutation-denial checks use nonmatching opaque filters. Encryption recovery,
strict validation, duplicate rejection, schema/drop/index denials and bypass denial
use isolated ephemeral fixtures in police_activity_smoke_<uuid>, not research
records. All test keys are ephemeral. Existing account read separation is checked
against the actual protected collections. Cleanup removes only the named isolated
test database and its test accounts/roles; never research evidence or Docker volumes.
Before/after all ten research collection counts must match.

## Operator sequence

1. Install source and run focused tests.
2. Run app.storage.setup_activity_mongo with separate bootstrap/history/SRB/activity
   credential directories. This creates empty stores, a technical account/role and
   private credentials; it imports no officer records.
3. Run app.storage.check_activity_mongo with the same four directories.
4. Review outputs, then commit verified source. Activity SQL delivery storage,
   recovery protocol and guarded import remain future steps.

Foundation checkers are checkpoint-specific; this activity checker verifies the
current service/history/SRB baseline and the new activity stores together.
79 focused tests passed locally, including exact roles, TTL/filter index rejection,
BSON encryption recovery, metadata tampering and private credentials. Real Mongo
checks must run on the operator Mac; no local research server checks are claimed.
All stored details remain encrypted. Human decryption, scoped permissions, IGP
approval and access logs remain pending. No human access grants or classification
changes occur. Stage 2 remains in progress.
