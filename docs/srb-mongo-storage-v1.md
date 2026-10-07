# Protected SRB Mongo storage foundation

Database: police_operations on the existing dedicated local Mongo service at
127.0.0.1:27018. This step adds empty stores; it imports no officer evidence.

| Collection | Writer policy |
| --- | --- |
| police_number_intervals | SRB_POLICE_NUMBER_EVIDENCE_V1 |
| restriction_records | SRB_RESTRICTION_EVIDENCE_V1 |
| restriction_overrides | SRB_OVERRIDE_EVIDENCE_V1 |

## Encrypted contract

All three collections use strict validation and reject extra plaintext fields.
Only opaque event/officer/assertion UUIDs, a raw-row digest, writer policy,
schema version, classification UNASSESSED, recorded time, key version and binary
ciphertext are allowed. Ciphertext length is a shape guard, not proof of encryption;
authenticated recovery remains mandatory in the later writer.

The encryption context binds the collection, provenance metadata, policy,
classification, key version and persisted millisecond timestamp. Unique raw-row
and writer-policy indexes prevent duplicate delivery. An officer/time index supports
later evidence queries. There are no TTL, sparse or partial indexes.

## Technical account separation

- Existing police_operations_app remains find/insert only on service_status_events.
- Existing police_history_app remains find/insert only on transfer_events and promotion_events.
- New police_srb_app uses srb_evidence_append_v1: find/insert only on the three SRB stores.
- No application role receives update, delete, schema administration, validation
  bypass or permissions on another source group's collections.
- Bootstrap credentials are used only for collection/account setup and isolated
  test-fixture cleanup. Existing accounts, passwords and roles are never replaced.
- This is database least privilege, not human RBAC/ABAC or a disclosure permission.

SRB credentials are generated once in the supplied separate private directory,
with directory mode 700 and file mode 600. Symlink traversal and permissive paths
are refused. No password-bearing URI, password or encryption key is displayed.

## Setup and real-driver verification

Setup requires the reconciled existing counts: service 6,596; transfers 33,316;
promotions 13,974. Existing validators, indexes, roles and account assignments
are verified before creating resources. SRB collections must be empty. Retries
verify complete existing contracts and reuse credentials; differing contracts
are refused rather than overwritten.

The checker authenticates the actual SRB, service and history accounts and tests
cross-group read denials. Nonmatching update/delete denials do not target existing
evidence. Schema, drop, index and validation-bypass denials are tested only in an
isolated synthetic database with an equivalent role. Ephemeral AES-GCM fixtures
exercise encrypted recovery after BSON round trip, strict validation and duplicate
rejection. Only the isolated database/users/roles are removed. Research counts
are checked again and must remain unchanged.

The setup/check commands are foundation-specific and require empty SRB stores.
After actual import, use the future reconciliation tools instead. Older foundation
setup/check commands also retain their original checkpoint assumptions; do not
rerun them against later populated stages.

## Pending work

SQL SRB preparation/completion storage, source assertions, guarded delivery,
real-driver recovery checks, importer and reconciliation remain to be developed.
Classification and human authorization remain pending. Source claims stay distinct
from accepted number intervals, restriction state and approved overrides. All
stored personal payloads remain encrypted for ordinary and CID/CCIB officers.
Stage 2 remains in progress.
