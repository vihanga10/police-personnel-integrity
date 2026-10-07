# Encrypted family storage v1

## Scope

Migration f28b6d40ea73 follows e17a5c39df62. It converts only the three verified
empty destinations: officer_family_civil_event_version,
officer_next_of_kin_version and source_attestation. Their row counts were zero
at the verified remaining-source checkpoint. Existing officer_family_relation
rows (6,596 encrypted PF father claims), all source assertions, receipts and
Mongo documents remain untouched by the conversion.

The migration locks all three destinations, then checks all are empty before
changing any column. A nonempty destination stops the migration; no evidence
conversion or deletion is attempted. Existing encrypted family relationships
are not rewritten. There is no automatic destructive downgrade.

## Encrypted values and retained metadata

Each destination uses required profile_payload_ciphertext and
required encryption_key_version, matching the protected-payload naming pattern
already used by officer_family_relation. The minimum ciphertext length is 29
bytes. This structural constraint alone cannot prove genuine encryption; the
future writer must authenticate and compare primary/backup recovery.

Civil-event type, reported date and reference are encrypted together; their old
plaintext fields and type/date indexes are removed. Next-of-kin name,
relationship and address move into the encrypted envelope. Its valid_from and
valid_to columns remain null until an explicitly reviewed temporal policy is
implemented. Attestation names, identifiers, asserted rank, signatures and
reported dates likewise reside only in its encrypted payload. Previous separate
ciphertext, identifier-HMAC and key columns are removed from the empty tables.

Opaque officer/relation/assertion/version/chain IDs and transaction metadata stay
queryable to preserve lineage. Attestation routing type, actor UID and resolution
status remain structural metadata with their existing consistency constraints.
An actor UID/resolution flag does not establish action-time authority. Original
claims, missing values and candidate uncertainty must remain in the writer's
encrypted payload. Full application disclosure rules remain pending.

Field-routing.json continues to describe logical members of encrypted family
payloads, not plaintext physical columns. No routing field is dropped from the
source planner. Reported dates do not become accepted state-effective dates.

## Preservation

Existing guard_version_insert and guard_evidence_update remain in place.
Asserted officer rows must reference that officer's supporting assertion.
A replacement must use the same chain, follow the predecessor immediately and
start exactly at its controlled closure time. Ciphertext cannot be overwritten.
Only the existing technical column permissions for transaction_end/record_state
closure remain; human correction approval is still unspecified.

A new relation-owner guard ensures civil-event and optional next-of-kin relation
links belong to the same officer. Deletion and truncation triggers reject removal
of these three kinds of family evidence. The application retains INSERT/SELECT,
cannot update payload columns and cannot delete/truncate family evidence.
Privileges do not implement human HQ Admin authorization or restricted viewing.

## Verification and next steps

Install source and run focused tests first. Then run
scripts/check_family_storage.py before applying the migration. The checker:

- Requires local police_identity_migrator and revision e17a5c39df62.
- Verifies the completed remaining import baseline and empty family destinations.
- Tests refusal for each nonempty old destination inside savepoints.
- Applies the migration only inside an outer rollback transaction.
- Compares database metadata, columns and constraints with the updated models.
- Verifies existing/new triggers and application permissions.
- Uses synthetic fixture values and ephemeral primary/backup keys for recovery.
- Rejects malformed ciphertext/key metadata, payload mutation, deletion,
  truncation, wrong relation ownership and invalid version starts.
- Verifies valid technical version closure and replacement.
- Rolls back schema changes and test rows, checks all registered table counts,
  original columns, function removal and unchanged applied revision.

Only opaque preexisting FK anchors are read; no production personnel values are
decrypted or printed. The checker has no Mongo connection. Its test AAD is solely
for fixtures and is not a production writer interface.

After the rollback checks pass, commit source and apply the migration, then run
alembic current/check and post-migration count checks. A guarded family writer,
atomic provenance receipt, read-only validation, import and reconciliation are
still subsequent steps. No family import or readiness claim is made by this
storage package. Classification remains UNASSESSED; Stage 2 remains in progress.
