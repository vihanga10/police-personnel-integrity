# Guarded station reference importer v1

This local development workflow imports encrypted source evidence from station_master.csv (607 rows) and sri_lanka_police_stations_sinhala.csv (607 rows). It does not accept station mappings or grant human access. Human authentication, authorization and permitted disclosure remain separate work.

## Modes

| Mode | Behaviour |
| --- | --- |
| Default | Read-only full preflight and SQL/Mongo delivery-state inspection. No database writes. |
| --write | Full preflight, then recoverable encrypted delivery through SqlReferenceLedger. |
| --reconcile | Read-only verification; every row must already have identical prepared evidence, Mongo readback and a matching completion receipt. Missing evidence is not repaired. |

The modes --write and --reconcile are mutually exclusive. Committed, clean source is required in all modes. The SQL application account and dedicated reference Mongo account are used; bootstrap credentials are not requested.

## Guards and preservation

This first importer is pinned to reviewed BATCH-RAW-001, archive SHA-256 32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2 and source-confirmation SHA-256 b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481. The supplying source must be POLICE_HR_IS for both reference files. Registered archive membership, exact headers/counts, row sequence, original values and both key copies are checked before delivery.

The entire encrypted master snapshot is recovered first to rebuild candidates. The reviewed checkpoint is retained: two master rows with repeated Sinhala labels, 605 single joint candidates and two unresolved structures in the Sinhala file for each of the three comparison modes. Both files retain two rows needing structural review. Those counts are preflight observations, not accepted station identity or approved corrections.

The encrypted payload preserves the planner's original fields, candidate raw-row references, source observations, uncertainties and registered master snapshot provenance. No numeric code conversion, guessed bracket splitting, translation or accepted mapping occurs. Classification remains UNASSESSED; accepted station identity, effective periods, authority and historical hierarchy remain unknown.

Preflight inspects every selected source and all existing reference delivery metadata. Orphan SQL assertions, preparations outside this reviewed batch, orphan Mongo evidence, mismatched documents and missing completed evidence stop the workflow. A private keyed fingerprint detects plan changes between preflight and execution. The SQL adapter independently recovers source/master evidence before each new preparation and receipt, retaining the saved encrypted winner on retry.

SQL assertion and preparation commit atomically before Mongo insertion; the production adapter verifies committed bytes through a fresh connection. Exact Mongo readback precedes a digest-bound SQL completion receipt. Interruptions leave committed evidence preserved. Retry the same workflow to inspect and resume; never delete evidence to restart.

## Private attempt evidence

Attempt journals must be outside the repository in an owner-only directory without symlink traversal. They record aggregates, pinned fingerprints, code revision, policy, opaque raw-row references, delivery outcomes and stop events. No original station values or plaintext plans are saved. Each run creates its own attempt directory, including read-only runs. A journal entry does not constitute a human authorization grant.

## First validation command

Commit the reviewed importer after its focused tests pass. From backend, run the command below without --write or --reconcile:

```bash
uv run python -m app.identity.import_references \
    --batch-id BATCH-RAW-001 \
    --expected-archive-sha256 32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2 \
    --confirmation ../docs/intake-source-confirmation.json \
    --expected-confirmation-sha256 b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481 \
    --expected-master-rows 607 \
    --expected-sinhala-rows 607 \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --reference-credential-directory "$HOME/ResearchKeys/police-personnel-integrity/mongo-reference-v1" \
    --attempt-root "$HOME/ResearchEvidence/police-personnel-integrity/reference-import-attempts"
```

Review the validation output before selecting --write. Afterwards run --reconcile and independent SQL/Mongo count checks. This step requires applied revision b40d8f62ac95 and the previously verified reference storage/recovery checks. It includes no schema migration. Stage 2 remains in progress until final coverage and checkpoint review are complete.
