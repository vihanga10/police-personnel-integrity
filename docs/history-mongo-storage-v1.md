# Encrypted history Mongo foundation v1

## Scope

Baseline: clean `feat/identity-resolution` at `ad17f73`.
The duration inspection found 30 negative integer claims. These remain preserved
with REVIEW_REQUIRED status and no normalized duration. Do not calculate replacement
durations from this event's arrival/departure dates. Cancelled transfer claims must
also remain preserved; their historical effect is not inferred during storage.

This step adds `police_operations.transfer_events` and `promotion_events`, initially
empty. It imports no history, adds no SQL tables, and grants no human viewing access.
Stage 2 remains in progress. The SQL preparation/completion adapter and guarded
historical importer are the next implementation boundaries.

## Envelope and database protections

Each collection accepts only the established opaque event/officer/assertion UUIDs,
raw source row digest, writer policy, schema version, UNASSESSED classification,
recording timestamp, encryption key version and binary ciphertext. Extra plaintext
fields are rejected. The validator is strict with error action. A unique
(raw_record_id, writer_policy) index prevents duplicate source delivery; an officer
and recording-time index supports evidence retrieval. No TTL deletes are used.

Writer policies are PF_TRANSFER_EVIDENCE_V1 and PF_PROMOTION_EVIDENCE_V1. Encryption
context binds ciphertext to collection, immutable routing/provenance, key version
and the BSON millisecond recording timestamp. Envelope validation cannot itself
prove encryption. Writers must verify authenticated primary/backup recovery and
source-plan equality before actual delivery, using the forthcoming SQL protocol.

Review flags, original negative values, cancellation claims, authority uncertainty
and unknown valid periods belong inside the encrypted payload. Stored evidence is
not accepted historical truth or a current assignment. Unassessed classification
cannot grant ordinary access. Historical CID/CCIB protection survives later transfers.

## Account separation

Existing police_operations_app and service_evidence_append_v1 stay unchanged.
The new technical account police_history_app receives history_evidence_append_v1:
find and insert only on the two historical collections. It cannot read service
records, update/delete history, change schema/indexes, drop collections or bypass
validation. The service writer cannot read history. These are technical database
permissions, separate from human IGP/SDIG/HQ Admin RBAC and ABAC.

History credentials are generated once in a separate private directory outside Git;
directory mode 700, file mode 600. Existing passwords are never replaced. The Mongo
bootstrap account is used for schema/account setup and isolated fixture cleanup;
it is not the application history writer. Production encryption keys are not needed
for this foundation test.

## Setup and verification

Source installation makes no connections. The setup command verifies the reconciled
6,596 service-event count, service validator/indexes and existing account definitions
before adding empty history collections and the least-privilege history account.
Existing incompatible contracts cause a stop; they are never replaced with collMod.
The initial setup/check expects both history collections to remain empty. Do not
rerun these initial-check commands as an importer after historical records exist.

The real-driver checker verifies both schemas and accounts, then tests strict
validation, duplicate rejection, encrypted review/cancellation preservation and
mutation/schema denials in a unique disposable test database. It independently
checks denial of reads across service/history accounts. Synthetic fixtures use
only ephemeral encryption keys. Cleanup removes only the generated test namespace;
research evidence, accounts and Docker volumes remain preserved. Research counts
must be identical before and after. No SQL connection or migration occurs.

Unit tests cover envelope context rebinding/tampering, BSON recovery, validator
copy isolation and private credential handling. Real server validation/authorization
is established by the checker on the local Mongo server, not by unit tests alone.
