# Anchored research audit gate v1

Stage 3 remains in progress. This package implements read-only audit readiness and encrypted permits. It does not implement or execute historical, authority/delegation or contradiction algorithms, save findings, or publish findings. Classification remains UNASSESSED.

## Current operator checkpoint

The operator reported complete Fabric reconciliation for 6,596 commitments and 68 original VALID transactions. Sepolia is partially published: the create transaction and first 100-officer transaction were reported finalized; 6,496 officers remain. This is an operator-supplied checkpoint, not a new live verification by this package. Existing signed transactions, journal directories, wallet configuration and commitments must be preserved. Additional faucet funding and reviewed cumulative publication budget remain required.

## Gate behavior

The runner is `python -m app.identity.check_audit_gate`. It has no execute option.

1. Require committed source and the exact original publication SHA-256. Validate the full officer inventory and original Merkle tree, including shared/reference coverage.
2. If the stable public journal has no `PASSED.json`, return BLOCKED / PUBLIC_PUBLICATION_INCOMPLETE immediately, exit code 2. This path writes only a private aggregate result, makes no RPC/database connection and issues no permit. A saved completion file is only a hint to attempt live verification; its contents cannot grant readiness.
3. With that hint present, invoke the existing public runner exclusively with `--reconcile`. It freshly reconciles evidence and Fabric, checks the deployment and verifies all 68 original public receipts, finality and all 6,596 commitments at the finalized seal block using both RPCs. Reconciliation cannot prepare or broadcast missing transactions. Preserve the original Fabric output root and original wallet publication journal.
4. After complete public readback, run the live evidence checker again. It recovers the pinned encrypted artifacts, reconciles the received sources, and compares exact source, membership and SQL/MongoDB destination versions. This final check prevents a long public readback from silently extending the ten-minute evidence freshness window.
5. Authenticate the final encrypted live gate with the primary and backup identity keys. Require the original scope, code revision, destination binding digest, exact publication, research Fabric genesis/channel/chaincode, original Sepolia genesis/deployment/writer/runtime/configuration, full counts and UNASSESSED classification. Both chain results must be fresh results created by the runner in RECONCILE mode; public submissions in that run must be zero.
6. Seal an encrypted research audit permit and verify its primary/backup recovery before writing READY. Exit code 0 means gate readiness only. Hard failures return STOPPED, exit code 1, without a permit.

The permit covers a versioned, anchored snapshot, not a verified current personnel state. Original shared records and uncertain membership remain covered as candidate evidence. A blockchain match establishes commitment consistency, not source truth, authority, historical identity or disclosure permission.

## Consumer contract

A future research audit entry point must call `require_audit_permit` before processing its selected snapshot, supplying the exact publication and context: code revision, bundle attempt, destination-binding attempt, commitment attempt and binding-artifact digest. Plain READY/PASSED JSON is not an authorization. The encrypted permit is bound to those values and rejects altered ciphertext, different versions, changed publication, scope mismatch, future timestamps and expiry.

Expiry is exactly ten minutes after the final live fingerprint starts, not ten minutes after issuance. Long final fingerprints may leave little or no valid time; the checker must refuse readiness rather than relax that rule. The final comparison is not a distributed database lock. Future algorithms must operate on the already authenticated captured snapshot, never silently replace it with mutable live reads. Runs and long-running audit resume/checkpoint semantics remain a subsequent implementation step.

Identity encryption keys protect this local permit. Anyone authorized to possess those keys can generate encrypted artifacts; this is not a separate user authentication or independent institutional signature system. The pure `verify_inputs` API expects results obtained by the trusted runner, not arbitrary user-supplied receipt dictionaries. The CLI accepts no externally supplied result files. A READY result does not authorize human disclosure or deploy an audit algorithm.

## Operator sequence

Run focused tests, commit these four source/document files and push. Do not change network.json, original publication journals, or fee caps for this checker.

The CLI accepts the existing public anchoring arguments plus an audit-specific `--output-root`. Use the previously reviewed `--publication-fee-budget-eth` sufficient to account for original signed journal reservations. This read-only budget is passed to the existing verifier and cannot fund/sign/broadcast transactions. It is not automatically raised. The current 0.04 value is suitable for the current partial-batch blocking check; after full publication use that publication's reviewed cumulative budget.

For the existing Mac shell array:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m app.identity.check_audit_gate "${public_anchor_args[@]}" \
    --publication-fee-budget-eth 0.04 \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts"
```

The array must still be defined in that shell and contain all required key, bundle, binding, commitment, credential, network, wallet, backup-wallet and original Fabric-output paths. The final output-root overrides the public runner output root; original Fabric journals remain in the separate original Fabric-output path. If the array was lost, reconstruct it from the existing publication documentation; do not guess journal paths.

With the reported current 100/6,596 progress, BLOCKED is the correct expected result. No complete public anchoring or audit success is claimed. READY can be verified on the Mac only after full publication and successful fresh reconciliation. Keep all private attempts outside Git.

## Validation limits

Synthetic tests exercise complete officer inventory, source/destination context, network/receipt/status mismatch, partial publication, expiry/replay, encrypted permit recovery and tampering. Runner tests mock trusted verifier outputs to confirm read-only invocation order and fast blocking; they do not verify real databases or blockchain state. Existing real-chain verifiers are reused. No research keys, database connection, RPC, wallet signing or blockchain submission are used during local tests or installation.
