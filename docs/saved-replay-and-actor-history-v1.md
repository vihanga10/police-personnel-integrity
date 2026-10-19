# Saved algorithm replay and reported action-date actor history v1

## Checkpoint

The operator's completed algorithm run `733e1b56-fac6-4c1b-a655-da3fe54cb200` reported PASSED at revision `0efe084d2541f68907bf8ce1d3482063ba3e25d5`, with cutoff `2024-12-31`. It processed 6,596 officers, 167,004 historical source claims and 168,510 reported authority actions. It retained 397,966 unresolved comparisons and one police-number conflicting-report result. Completion artifact SHA-256: `9c73e198d3ae93aba3b703d853cf2df598812486bad8b41231b6d76290527072`.

Those aggregate operator results are not independently established source truth. This step authenticates and reproduces the original encrypted results before examining reported actor histories. It does not edit CSVs, classifications, source rows, accepted identities or existing blockchain commitments.

## Two separate modes

| Mode | Input and behavior | Authorization |
| --- | --- | --- |
| Saved replay | Recover the exact captured snapshot/commitments and reproduce the completed run's officer scope, cutoff, historical policy, comparisons, actions and counts | No fresh permit; archived verification only, no new date query or live readiness claim |
| Actor/date review | Match each original action to the captured source, then reconstruct every candidate actor at that action's reported date | Current clean committed revision, exact snapshot, fresh dual-chain permit and authenticated successful saved replay receipt |

A stale permit is never extended. Completing saved replay does not issue an audit permit. Review and commit this new source before either runner. Refresh the audit gate only AFTER saved replay passes, then execute the actor/date review immediately using the new permit.

## Saved replay guarantees

`SavedRun` authenticates the encrypted completion inventory with both recovery keys before trusting any plaintext PASSED fields. The recovered context must match the chosen bundle, binding and commitment attempts. Only the supported recorded policies are accepted; unsupported versions stop instead of being interpreted with new rules.

Every output fingerprint is checked, including on subsequent reads. Missing, unexpected, replaced, symlinked or permissively readable files are refused. The authenticated inventory must enumerate exactly the expected officer/action chunks. The plaintext summary must agree with the encrypted report and actual completion fingerprint. A STOPPED run is not a completed run.

The verifier reconstructs each officer result from the captured original catalog, including the recorded historical policy and full supporting/review/future/expired groups. It recomputes temporal comparisons and streams source-derived action reviews in the original order. It checks exact result content, selection metadata, original date, coverage, aggregates and reason counts. Counts alone cannot establish successful replay. Single-officer saved runs preserve the original anchored candidate selection without performing a new NIC lookup.

Snapshot loading separately verifies primary/backup key recovery, commitment-key separation, source membership, exact destination bindings and all original protected commitments. The verifier never treats an encrypted result as proof that its claims were correct merely because it decrypts successfully.

The saved verification receipt is encrypted and recoverable with both key copies. Its identity includes the original completion SHA, attempt ID, source context, policies and recorded scope. The actor runner requires this receipt and rejects a receipt for another run or changed snapshot. Plaintext PASSED does not replace the receipt.

## Actor history and authority boundary

The new review links candidate `officer_uid` values to their subject evidence. An officer mentioned as an authority or recorder is not automatically the subject of that row. Each actor's reported rank, posting, police number, service status and restrictions are reconstructed at the action's reported date, using the same preserved source claims and historical policy.

The action cutoff remains the completed run's cutoff; it is not used as the date of every action. No date defaults to today or to the cutoff. Missing/invalid dates remain unresolved. Ambiguous actor links preserve every candidate separately. Actors outside the anchored universe remain unresolved instead of being silently assigned.

Actor histories are supplied to the temporal authority evaluator as typed actor states. Reported rank candidates remain UNASSESSED; posting text is not converted into a verified geographic scope, current service labels are not assumed active on a historical date, and rank is not converted into a role or legal power. The evaluator still stops with CANNOT_VERIFY where action identity/date, actor state or governing evidence is unassessed. This is functional integration of reported actor histories, not completion of legal-rule/delegation assessment.

Rules, independent governing instruments, action-specific scope, assessed identity and delegation validity remain separate work. The new step cannot legitimately turn every action into VALID merely because the original datasets are preserved or the hashes match.

## Protected output structure

Actor results use three linked inventories, all encrypted:

* `claims-*.encrypted.json`: one complete source-claim inventory per actor, preserving values, original-row/provenance references, issues and destination fingerprints.
* `states-*.encrypted.json`: one compact state per distinct actor/date. Candidate/supporting/review/future/expired claim IDs resolve to that actor's claim inventory. Full source rows are not duplicated for every action.
* `actions-*.encrypted.json`: each original action digest, reported date, candidate identity links, state IDs, unresolved reasons and candidate authority decisions.

An encrypted completion inventory binds every output fingerprint. Terminal/summary outputs contain only aggregate counts, policies, context and unresolved-reason codes. Officer UIDs, NICs, reported ranks, stations and original rows remain within encrypted artifacts. Review results are not findings database inserts, human access grants, corrections or blockchain transactions.

Caching only reuses the same actor/date state within this run. A different date creates another state; a different snapshot produces different inventory/state identities. State status counts measure distinct actor/date states; action counts measure action slots. They must not be interpreted as counts of distinct officers or misconduct.

The fresh permit is checked before processing bounded action batches, around every encrypted output and at completion. Expiry/failure leaves private partial artifacts and STOPPED without PASSED. Saved inputs are not overwritten. Large real runs may exceed the permit window; actual duration is to be measured on the Mac. This step does not claim performance from fixture timing alone.

## Installation, tests and commit

The installer requires a clean `feat/identity-resolution` branch containing commit `0efe084`, validates exact source and package fingerprints, refuses existing new targets and keeps a source-only backup. It does not read personnel data, initialize keys or connect to databases/RPCs.

```bash
unzip -q "$HOME/Downloads/actor-history-step.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/actor-history-step/install.py" --repository "$PWD" &&
git diff --check &&
cd backend &&
uv run python -m pytest -q --tb=short \
    tests/test_saved_research_algorithms.py \
    tests/test_action_actor_history.py \
    tests/test_actor_history_runners.py \
    tests/test_saved_algorithm_snapshot.py \
    tests/test_temporal_authority.py \
    tests/test_historical_reconstruction.py \
    tests/test_audit_gate.py \
    tests/test_research_algorithms.py
```

Tests use invented fixtures, genuine local encryption/recovery and permit checks, actual source adapters and the evaluator. Heavy live/captured collection boundaries are mocked explicitly. Tests cover all 6,596 fixture officers, different action dates, preserved ambiguity, duplicate-state reuse, missing actor dates, changed source/results, reordered results, authenticated but incorrect output, changed keys, altered receipts, expiry and interrupted output. They do not establish actual governing law or research accuracy.

After tests pass, review and commit these five modules, four test files and this document. Do not run the research commands with uncommitted source.

## First: verify the existing saved run

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"

uv run python -m app.identity.verify_saved_research_algorithms \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
    --algorithm-attempt "$HOME/ResearchEvidence/police-personnel-integrity/research-algorithm-attempts/733e1b56-fac6-4c1b-a655-da3fe54cb200" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/saved-algorithm-verification-attempts"
```

Send its final aggregate output and verification attempt directory. No fresh audit gate is needed for this saved replay.

## Then: refresh the gate and review action-date histories

Use the existing complete `public_anchor_args` array (restore it if opening a new terminal):

```bash
uv run python -m app.identity.check_audit_gate "${public_anchor_args[@]}" \
    --publication-fee-budget-eth 2.30 \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts"
```

Once READY, replace BOTH placeholders in the command below. The first is the NEW READY gate, the second is the successful saved verification attempt. These are different directories. Do not use the earlier expired permit.

```bash
uv run python -m app.identity.review_action_actor_history \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
    --algorithm-attempt "$HOME/ResearchEvidence/police-personnel-integrity/research-algorithm-attempts/733e1b56-fac6-4c1b-a655-da3fe54cb200" \
    --saved-review-attempt "$HOME/ResearchEvidence/police-personnel-integrity/saved-algorithm-verification-attempts/REPLACE_WITH_PASSED_VERIFICATION" \
    --audit-gate-attempt "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts/REPLACE_WITH_NEW_READY_GATE" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/action-actor-history-attempts"
```

Missing governing evidence, history/date uncertainty and unresolved candidate identity are preserved. No accepted authority decision, findings persistence or new anchor is claimed by this step. Stage 3 remains in progress.
