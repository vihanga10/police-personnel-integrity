# Public publication finalized-state readback v1

The operator reported all 68 original Sepolia publication receipts verified, followed by RPC 1 rejecting `eth_getCode` at the original sealing block. This identifies a contract-state request failure; it does not independently establish provider pruning or a commitment mismatch. Complete public reconciliation remains pending until the corrected verifier passes on the operator's Mac.

## Verification rule

Keep each original signed transaction, receipt, event and inclusion block unchanged. Verify all 68 original receipts and required confirmations/finality using the existing transaction verifier.

For complete contract-state readback:

1. Ask both configured RPCs for finalized heights and select the lower height. Reject a missing head or a height before the original seal.
2. Fetch that exact numbered block through both RPCs. Require matching block hashes, matching requested heights and well-formed hashes.
3. Verify the original sealing block number/hash independently. Verify that neither provider's finalized height regresses below the selected state height.
4. Read exact compiled runtime, writer, chain ID, officer limit, batch metadata, sealed flag and all 6,596 original commitments at that same fixed numbered state block through both RPCs. Do not fall back to latest, a moving finalized tag or a single provider.
5. Recheck state-block and sealing-block identities and finalized coverage after every chunk and at the end. Any rejected state request, inconsistent value or changed block is a hard failure.
6. Recheck all 68 original receipts and inclusion evidence after complete readback. Only then save PASSED.

The deployed contract has immutable runtime/writer and append-only sealed-batch behavior. Reading it at a later agreed finalized block verifies the exact original committed values without requiring archive state at their original inclusion height. It does not prove that source claims are true or authorize human disclosure.

## Receipts and reports

`sealed_block` and `sealed_block_hash` continue to identify the original sealing transaction's inclusion block. Existing signed journals, mined receipts, cumulative fee accounting and completion-file identity are preserved. Each successful attempt report additionally records `state_verification` with policy `COMMON_FINALIZED_PUBLICATION_STATE_V1`, the fixed readback block and its hash. This observation can differ across later reconciliation runs without changing original publication identity.

The change does not alter the Solidity contract, wallet, network configuration, publication, Fabric ledger, officer commitments, Merkle root or private source evidence. No new deployment or re-upload is required. Reconciliation signs and broadcasts nothing. A fresh evidence/Fabric check is still performed by the guarded Python launcher. Audit gate checks remain required before an audit.

## Local validation

Focused tests cover all 6,596 fixture commitments with seal-height state unavailable; different finalized heads; missing, malformed or disagreeing blocks; state-block changes; original-seal changes; rejected state queries; modified runtime and altered commitments. Existing publication/recovery tests cover original signed transaction replay, pending finality, receipts, exact complete readback and rejection of conflicting or tampered evidence. A compiled local EVM test remains included in the regression command.

## Operator sequence

Install on the clean `feat/identity-resolution` branch, run focused tests, commit/push the four changed source/document files, then rerun `app.identity.anchor_research_public` with the existing arguments, reviewed 2.30 SepETH cumulative budget and `--reconcile`.

Do not use `--execute` for this verification retry. Do not delete/reset journals, modify wallet configuration, replace original transactions, relax finality or infer PASSED from receipt counts alone.

Stage 3 remains in progress. Classification remains UNASSESSED. Research audit execution remains pending.
