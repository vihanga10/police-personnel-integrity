# Remaining Mongo evidence storage v1

Five empty collections: education_records, operation_records, court_records,
complaint_records and demotion_events. Family details keep their existing SQL
routing and are not imported by this step.

All detail payloads are encrypted; only opaque IDs, provenance, policy, key
version and recorded timestamp are outside ciphertext. Operations/courts require
null officer_uid because they are multi-person evidence. No participant UUID is
invented as the single subject. Other collections require an opaque officer UUID.
Participant details and claims remain encrypted until later linkage/disclosure.

Strict validators reject extra plaintext fields, wrong writer policy, classification,
subject shape and malformed ciphertext. Binary size is a structural check, not
proof of encryption; authenticated recovery is required by the eventual writer.
Unique raw_record_id/writer_policy indexes reject duplicate delivery. Existing
collections, roles and counts are verified without modification.

The separate police_remaining_app technical account has find/insert on only these
five collections; no update/delete, collection administration, validation bypass
or access to previous service/history/SRB/activity collections. This is technical
storage permission, not human RBAC/ABAC or an IGP/SDIG access grant.

Setup uses existing bootstrap credentials to create empty collections and the
new least-privilege account. A private remaining credential directory is created
once; existing passwords are never replaced. Setup stops on contract/count drift.
The real-driver checker uses isolated synthetic documents and ephemeral keys;
only its uniquely named disposable test database is removed. Research evidence
is never removed. Checks cover recovery, validation, duplicate rejection,
permission denials and account separation in both directions.

This package does not connect or write during installation. Setup creates empty
Mongo resources; checks do not import personnel evidence or use production keys.
Run local tests first, then setup, then the isolated checker on your Mac. No local
server checks are claimed by the package. Classification stays UNASSESSED;
Stage 2 remains in progress. Delivery storage/adapters/imports remain pending.
