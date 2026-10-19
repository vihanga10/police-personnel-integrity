# Protected station reference Mongo storage v1

This step creates empty station_reference_records and
station_sinhala_reference_records collections in police_operations, plus the
technical police_reference_app account with the reference_evidence_append_v1
role. It installs no SQL storage, delivery adapter, importer or human access grant.

Every document contains only opaque document/source-assertion UUIDs, opaque
raw-record identifier, writer policy, schema version, UNASSESSED classification,
recorded timestamp, encrypted payload and key version. Raw-record references are
opaque SHA-256 identifiers. Station codes, names, hierarchy claims, coordinates,
confidence, source text and candidate mappings belong inside the encrypted
payload. Station references have no officer_uid field. SQL assertion linkage and
independent encrypted writer/recovery gates remain pending.

Both collections use strict/error validation with no additional fields. The
binary payload must exceed the AES-GCM nonce/tag-only length. Schema validation
cannot prove ciphertext authenticity or accepted semantics; the future writer
must authenticate recovery. Ciphertext context binds collection, document ID,
source assertion UUID, raw ID, policy, schema, classification, key version and
UTC recorded timestamp at BSON millisecond precision.

Unique indexes reject repeated raw-record/policy deliveries and repeated source
assertion UUIDs. Station names or codes are not plaintext indexes. Duplicate
Sinhala labels remain legitimate review evidence, not duplicate documents.
The account has only find/insert on these two collections, with no inherited
roles. Updates, deletes, schema changes, validation bypass and index management
are excluded. Existing accounts cannot access the reference collections.

The setup verifies all fifteen imported collection contracts and reconciled
counts, exact existing roles/users, all existing application credentials and
expected collection membership before adding Mongo resources. Existing reference
resources are verified without repair and must be empty. Retries reuse private
credentials and verify an existing account before adding missing resources.
No existing account is broadened and no existing evidence is replaced.

The checker verifies permissions on research resources using reads and
nonmatching update/delete filters. Inserts, malformed documents, independent
unique-index collisions, schema/drop/index and bypass denial tests use only an
isolated database with a short name and ephemeral credentials/keys. Cleanup is
restricted to that generated database. Research counts, contracts and accounts
are checked again afterward. No research payloads or credentials are printed.

Credential directories must be separate. The new directory is typically
~/ResearchKeys/police-personnel-integrity/mongo-reference-v1. Its credentials.json
is created once with owner-only permissions and is never replaced on retries.
Symlinked and permissive credential paths are rejected.

Run the unit tests, then setup_reference_mongo and check_reference_mongo with the
bootstrap, history, SRB, activity, remaining and reference credential directories.
Real server checks run on the research Mac; local tests cover BSON round trips,
AES-GCM rebinding, schema/role/index contracts and credential handling.

Reference plans remain unaccepted evidence: 605 candidate mappings and two
unresolved Sinhala labels are preserved for later delivery/import. The storage
check does not promote classification, historical applicability, authority or
linkage. Classification remains UNASSESSED; Stage 2 remains in progress.
