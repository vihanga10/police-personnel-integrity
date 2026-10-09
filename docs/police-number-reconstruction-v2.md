# Reported police-number comparison v2

New reconstructions use `REPORTED_HISTORICAL_RECONSTRUCTION_V2`. Only police-number comparison changes. Original source evidence, commitments, chain receipts and encrypted saved results remain preserved.

## Rule

For the requested date, preserve the existing candidate interval convention and partition police-number candidates by exact, nonblank reported `number_type`. Compare exact reported `police_no` strings inside each type:

- Different numbers in the same type remain `CONFLICTING_REPORTS` without accepted precedence.
- Different types alone do not establish a conflict. No type alias, case or whitespace normalization is applied; type equivalence remains unassessed.
- A blank type or blank number prevents a unique answer (`CANNOT_VERIFY`), unless a known-type conflict also exists, in which case that conflict is retained with the missing-field reason.
- Snapshots, unplaced evidence, uncertain dates and queries after capture keep their existing conservative behavior. A nonconflicting typed candidate set can still be `CANNOT_VERIFY`.
- Malformed candidate JSON, repeated JSON keys, extra fields or non-string values stop processing with a value-free error.

`REPORTED_CANDIDATES` never means accepted historical identity, valid number assignment or accepted state. All provenance and candidates remain retained. Classification stays UNASSESSED.

The installed source adapter supplies police-number historical candidates as INTERVAL claims. This change does not introduce per-type event carry-forward, type precedence or accepted date semantics.

## Archived results

Saved-result review accepts v1 and v2, authenticates encrypted chunks with their recorded policy and replays with that exact policy. The selected officer's original v1 result therefore remains `CONFLICTING_REPORTS`; reviewing it does not silently upgrade the result. A new reconstruction under a fresh audit permit is required to apply v2.

The operator's saved explanation review `0feb25da-b25b-434a-b6b9-3a8953269c24` passed for 2024-12-31. It reported two candidate number types and zero types with multiple candidate numbers, alongside two police-number review claims. Under v2 those different types alone do not cause a conflict, but the review evidence still prevents a unique historical answer. This is an expectation from the posted aggregate, not a newly executed research result.

## Verification and next operation

Tests cover same-type conflicts, cross-type coexistence, exact spelling, missing fields, interval boundaries, review evidence, future queries, malformed JSON, value-free explanations, legacy replay and encrypted policy binding.

Commit the installed source after focused tests. The original archived-result review can be rerun without a fresh permit to verify compatibility. Before executing a new selected-officer query, refresh `app.identity.check_audit_gate` after the new commit, then use the resulting permit with `app.identity.reconstruct_history --select-nic --on 2024-12-31`. Enter the NIC only at the hidden prompt. Keep output and credentials private; share aggregate output only.

No authority/delegation verification, correction, findings persistence or blockchain write is added by this step. Stage 3 remains in progress.
