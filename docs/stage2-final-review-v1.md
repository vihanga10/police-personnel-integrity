# Final Stage 2 received-batch storage review v1

This review evaluates the intake, encrypted staging, transformed evidence and delivery checkpoint for the nineteen registered files in BATCH-RAW-001. It does not establish source truth, independent source status, historical linkage, authority, accepted station mappings or human disclosure authorization.

The received batch contains 166,651 personnel rows across seventeen files and 1,214 reference rows across two files: 167,865 received rows in total. These are source row counts, not distinct officers or a count of all assertions. Internal identity assertions and transformed destinations can have different counts.

## Required gates

| Gate | Evidence |
| --- | --- |
| Exact source coverage | Registered archive/source confirmation, all original fields recovered using both keys, exact staged row IDs, supplying source provenance and SQL receipt/completion coverage for all nineteen files. |
| Encrypted reconciliation | Eight existing import workflows run with --reconcile: profiles, service, transfer/promotion history, SRB numbers/restrictions/overrides, SRB activities, remaining HR/PF, family and station references. |
| Count checkpoint | Existing and reference PostgreSQL table counts, all seventeen Mongo collection counts and retained reference review counts. |
| Preserved uncertainty | No classification upgrades or accepted candidate mappings; unresolved source references and structures remain evidence for later research stages. |

The source coverage inspector compares exact row IDs, not merely totals. It includes the new reference assertion/preparation/completion tables. The prior source coverage inspector remains available as its earlier checkpoint tool. This new version reports reference receipt coverage; it no longer calls reference storage pending.

ReferenceInventory performs literal source-key comparisons. Its full-label Sinhala comparison can still show 607 nonmatches even though the separate bilingual planner preserves 605 component-based candidates. Those observations use different comparison rules and are not accepted mappings. NPC/HRC references have no independently received target catalog; linked_case_no to operation_no remains provisional. Unresolved references are reported as research backlog, not silently repaired or required to become source truth before storage completion.

The runner uses fixed argument arrays with no shell interpolation. There is no --write, --skip or arbitrary module option. The coverage step and all reconciliations are read-only. A failed child or count gate stops the review and prevents a PASSED summary. All original source must be committed and clean before running. The applied reference schema b40d8f62ac95 must already exist; the application does not receive Alembic version-table access.

## Execution

After focused tests pass, commit these sources. From backend run:

```bash
uv run python -m app.identity.review_stage2 \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
    --attempt-root "$HOME/ResearchEvidence/police-personnel-integrity/stage2-review-attempts"
```

Credential root contains the existing private mongo-v1, mongo-history-v1, mongo-srb-v1, mongo-activity-v1, mongo-remaining-v1 and mongo-reference-v1 directories. The runner does not connect as Mongo bootstrap. Its count gate uses the existing technical readers and SQL application account. No permission changes, database migrations or imports occur.

This performs a full fresh reconciliation and can take longer than unit tests, especially the history and SRB activity datasets. Each check and child progress output remains visible. An interruption does not modify database evidence; rerun the read-only review to obtain a complete result.

Each attempt receives an owner-only directory outside Git, with aggregate/opaque summary receipts and child reconciliation journals. Source cells, plaintext plans, ciphertext payload dumps and key material are not exported. A failed attempt records completed checks and stop status; it cannot be treated as a passed review.

## Interpreting success

Only a final Stage 2 received-batch storage review: PASSED result satisfies this received-batch engineering checkpoint. Record that output and the attempt directory in the next completion checkpoint. Full research completion is still pending: data-use authorization, independent source evidence, temporal meaning and accepted historical linkage, reconstruction, authority/delegation verification, contradiction detection, human access enforcement, blockchain audit and research evaluation remain separate work.

The databases are read separately. There is no distributed read snapshot or live concurrent-ingestion readiness claim; run this checkpoint in the controlled development session without other writers. Existing per-import safeguards reject discrepancies. This review does not change classification or apply source-reported effects.
