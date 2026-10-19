# Isolated intake-to-bitemporal pipeline validation V1

This is an integration-validation step. It adds tests and a fixed isolated-launcher suite, not research provisioning or automatic intake. Existing intake/hook/query/recovery algorithms are unchanged. Requires the controlled hook commit `053c39a`, including the corrected staging fixture that creates only `intake_batch`, `intake_file` and `raw_record`.

## Ten scenarios

1. Capture a correction and query the same effective date at both baseline and later recording time. Earlier query digest and original store bytes must survive. Querying an effective date before applicability must produce no candidate.
2. Intake a new staged candidate, then stage and capture its correction through the explicit latest predecessor. Baseline, intake and corrected query results must retain their respective candidates; two outbox versions and three total history versions remain.
3. Interrupt after encrypted outbox commit, before capture. Prior covered queries remain available, but a later known-as-of query is rejected until capture completes. An idempotent retry must not duplicate the outbox intent.
4. Interrupt after event publication, before checkpoint publication. Protected queries must block. A separate signed recovery authorization binds the preserved artifact inventory; recovery and witness advancement must preserve the original event observation time, including after the initial route expires.
5. Interrupt after registry publication, before witness advancement. Queries must block until explicitly authorized reconciliation selects the exact published checkpoint and advances the independent witness.
6. Lose the response after the witness durably advances. Fresh reads and idempotent retry must recognize the captured version without duplicate events.
7. Reject an invalid recovery signature without changing protected stores or publishing query output. Correct independently authorized recovery may then proceed.
8. Detect registry rollback against a newer independent witness. Restoring the exact saved entry in this test permits verified querying again; no production rollback repair is supplied.
9. Reopen database connections, registry and witness from durable encrypted files. Query and retry must preserve the witnessed tip and avoid duplicates. This is object/pool reconstruction, not a complete PostgreSQL/server power-loss experiment.
10. Traverse actual loopback mutual TLS. In the PostgreSQL suite, exercise the public registered routing/capture entries and public protected query entry. Only the full anchored replay/live-readiness loader is replaced by a clearly declared test snapshot. The SQLite suite uses internal loaded hook APIs and the public TLS query entry.

Each successful query must authenticate journal replay, recover identically with primary and backup keys, write owner-only encrypted output, preserve protected stores, and state `JOURNAL_OBSERVATIONS_ONLY`, no accepted state and no source-change-completeness claim. Plaintext personnel values must not appear in the encrypted artifact or public summary. Recovery does not extend coverage to the recovery wall-clock date; queries beyond the last observed event remain rejected.

## Execution and limits

Ordinary local tests use disposable SQLite rows, actual cryptography, synthetic readiness/evidence and an ephemeral loopback TLS service. Three additional unit checks exercise the launcher's pipeline suite/count/skip refusal. The ten PostgreSQL scenarios require the existing attested Docker launcher:

```bash
uv run python scripts/run_isolated_recording_postgres.py --suite pipeline-e2e
```

The launcher accepts only three installed suite names (`recording`, `intake-hook`, `pipeline-e2e`); arbitrary URLs, files, existing containers and database overrides remain rejected. It creates a new PostgreSQL 16 container with temporary data and disposable credentials, provisions only the required test tables there, checks role restrictions and removes the container. It requires all ten scenarios to pass without skips. Without its private attested configuration, the PostgreSQL file skips explicitly.

No independent production witness service is deployed. This harness does not validate real source authenticity, complete capture of all changes, accepted NIC identity, live chain readiness or research accuracy against reviewed ground truth. It does not install schemas in research storage, enable automatic intake, issue production recovery approvals, create production keys, alter CSVs/anchors, push Git commits or run live research. RPC 1 remains deferred. Provisioning, deployment, integrated evaluation and broader research objectives remain pending after these tests pass.
