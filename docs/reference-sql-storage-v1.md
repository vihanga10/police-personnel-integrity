# PostgreSQL reference delivery storage v1

This step adds storage for encrypted station reference evidence. It does not import either station file or accept the 605 candidate mappings. The two unresolved labels and repeated Sinhala labels remain review evidence. Classification, station identity, historical hierarchy, code stability, coordinate accuracy and valid periods remain unassessed.

## Storage

| Table | Purpose |
| --- | --- |
| identity.reference_source_assertion | Encrypted source claim bound to its staged row, registered file and active POLICE_HR_IS supplying source. |
| staging.reference_delivery_preparation | Exact encrypted BSON, SHA-256 digest, destination policy, code/confirmation references and review counts, bound to the registered master snapshot. |
| staging.reference_delivery_completion | Receipt for the preparation's exact delivery ID and BSON digest. |

There is no officer identifier or accepted station identifier in these tables. Original station payloads remain encrypted. Candidate raw-row references are evidence for later review, not accepted links.

Insert guards verify source provenance, routing, source status and master snapshot registration/counts. Completion guards reject a missing preparation, changed digest or earlier receipt time. Constraints reject invalid review states, invalid encrypted envelope sizes and digest mismatches. UPDATE, DELETE and TRUNCATE triggers protect all three tables. The application account receives SELECT and INSERT only on these tables; this is a service privilege, not a human disclosure grant.

The SQL guards bind storage metadata; they do not parse encrypted payloads or establish source truth. The future writer must verify payload recovery, pinned archive/confirmation, candidate evidence and exact Mongo delivery before recording completion. Separate commits across PostgreSQL and MongoDB require the future recovery adapter.

## Migration and verification

Revision b40d8f62ac95 follows a39c7e51fb84. Migration DDL is frozen independently of the current ORM. Automatic downgrade is deliberately unavailable because evidence removal needs separate review.

Before applying the revision, run scripts/check_reference_storage.py. It requires the current research checkpoint at a39c7e51fb84 and absent reference tables/guards. It uses the local migrator connection and one outer transaction, creates synthetic registered source rows and ephemeral encryption keys, checks both destinations, provenance rejection, exact encrypted BSON recovery with both key copies, digest-bound receipts, mutation rejection and application privileges. It always requests rollback and then uses a fresh connection to verify the original counts, revision and absence of the test tables/functions.

Fixtures use the migrator. Application ACLs are inspected without impersonating the application account; actual application delivery remains pending. No Mongo connection or production encryption keys are used. No personnel or station values are printed. The application does not require access to the Alembic version table.

After successful rollback checks, commit the reviewed source before applying the migration. Verify Alembic current/check and read-only research counts afterwards. Recovery checks and the guarded importer are subsequent steps. Stage 2 remains in progress.
