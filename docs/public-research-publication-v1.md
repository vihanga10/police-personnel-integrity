# Guarded original research publication on Sepolia v1

## Scope and ordering

Publish the same 6,596 original individual commitments already reconciled on Fabric. The exact original public payload SHA-256 is `fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b`; the existing Merkle root and shared/coverage commitments remain unchanged. No names, NICs, officer_uid values, raw evidence, encryption keys or audit conclusions are published. The contract is unchanged. This publisher uses the original createBatch, 66 appendOfficers calls (100 each, final 96), and sealBatch: 68 original transactions.

The Python launcher invokes the existing Fabric runner in RECONCILE mode against its original output root, which retains the original Fabric journals. That runner first performs all live evidence/reconciliation checks, authenticates the encrypted gate, and verifies all original Fabric transactions and both organization readbacks. The launcher authenticates that gate again with both identity-key copies and checks current source revision and the original publication. An ephemeral MAC key is supplied to Node through stdin; the key is never saved or passed in argv. Node verifies the MAC, ten-minute freshness, exact batch, supplying Fabric network identity and original finalized deployment. A stale saved JSON comparison alone cannot authorize publication.

Ten-minute freshness is checked at entry and immediately before each signing or broadcast. An expired gate stops before the next broadcast; an already prepared original is preserved. The next invocation repeats the live/Fabric checks. Final sealed-block readback can legitimately exceed ten minutes because it does not sign or broadcast: it checks immutable contents at the exact finalized seal block. This is not a verified-current-state claim. Audits must separately gate their exact anchored versions.

## Transaction recovery and reconciliation

One stable owner-only journal lives under the primary wallet root, `publications/<batch_publication_id>`. It stores exclusive/fsynced `<index>-PREPARED.json` signed bytes and `<index>-MINED.json` original inclusion receipts. A process lock prevents concurrent publishers. Original signed transaction bytes, nonce, EIP-1559 fee caps, call data, compilation/runtime, contract, source-publication digest and network configuration are bound and checked on every retry. There is no replacement, fee bump, competing nonce or automatic reset.

An acknowledged or ambiguous original broadcast is reconciled by its original hash. Both RPCs must report successful identical receipts, exact transaction fields, inclusion in the recorded block and the exact expected Created/Appended/Sealed event. Readback or reorg differences stop. Only a missing original receipt allows an EXECUTE retry of the same signed bytes; nonce consumption or an unrelated pending transaction stops. RECONCILE never signs, broadcasts or creates a missing original transaction. VALIDATE never signs or broadcasts. MINED is provisional and does not mean publication complete.

All 68 original transactions must be finalized and meet the existing confirmation policy before completion. The publisher queries each of the 6,596 stored commitments through both RPCs at the exact seal block, checks metadata, officer count, shared/reference coverage commitments and seal, and repeats original inclusion checks afterwards. It saves PASSED only when all checks agree. Full readback is bounded to four concurrent calls. Receipt/provider-trusted finality does not substitute for independent consensus validation.

## Fees, funding and partial progress

The publication budget is explicit and cumulative across every original prepared publication transaction; it excludes the already-paid contract deployment. Default `--publication-fee-budget-eth 0.025`. It may be raised explicitly after reviewing validation; hard research-test policy is at most 5 test ETH. This limit is not a spending recommendation. Maximum reserved exposure uses signed gas limits times the configured max fee, so it conservatively exceeds actual charges. Existing wallet RPC configuration, fees and original deployment bindings are not changed.

For the next eligible operation only, both providers estimate gas and add 20% headroom. All operations must fit both current block gas limits and EIP-7825's 16,777,216 individual-transaction cap. Each new signing requires sufficient wallet funds, idle identical nonce, base fee plus tip fitting the configured fee cap, and cumulative original reserved costs fitting the publication budget. If any chunk exceeds the protocol cap, stop for contract/planning review; never split the fixed contract chunk incorrectly or silently redeploy.

VALIDATE returns READY or FUNDING_OR_BUDGET_REQUIRED for the next operation and a conservative worst-case remaining exposure. It cannot estimate later state-dependent chunks before earlier calls are mined. That remaining exposure is a policy upper bound, not a fee quote. EXECUTE can stop safely with partial progress on a missing receipt, budget/funding pause or stale gate. Rerun the same guarded command with fresh checks after resolving the reported condition. Add only free faucet Sepolia test ETH; real ETH is unnecessary. Additional test funding will likely be needed beyond the current 0.05 original faucet grant. A complete publication is not inferred from a next-operation preflight.

## Install and test

Run `node --test test/public-*.test.js test/sepolia-*.test.js` in blockchain/public, and the focused Python tests in backend. No new npm dependency or lockfile is required. The locally compiled EVM integration tests use generated fixture commitments and an explicit fixture adapter for Sepolia genesis/finality and a bounded gas estimate; they do not run against real Sepolia. Mac/live fresh-gate and publication verification remain to be performed by the operator.

## Operator validation command

Commit the source first. The CLI requires a clean feat/identity-resolution branch containing `94706a2`. Use the original Fabric output root so RECONCILE finds its existing original transaction journals.

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"

public_anchor_args=(
    --key-file .secrets/identity-keys.json
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json"
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json"
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025"
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762"
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50"
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity"
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1"
    --fabric-output-root "$HOME/ResearchEvidence/police-personnel-integrity/research-fabric-anchor-attempts"
    --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1"
    --backup-wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1-backup"
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/research-public-anchor-attempts"
    --publication-fee-budget-eth 0.025
)

uv run python -m app.identity.anchor_research_public "${public_anchor_args[@]}"
```

Send the aggregate next-operation validation output before EXECUTE. VALIDATE performs database/Fabric/Sepolia reads and saves owner-only local attempts; no blockchain submissions or database writes. Once the reviewed budget and funding are sufficient, the same command with `--execute` submits research commitment transactions. With `--reconcile`, it verifies original transactions without broadcast and cannot complete a partially unprepared batch. Do not change network.json after original deployment preparation: the deployment client binds that configuration.

If receipts are initially absent, wait briefly and rerun the same guarded EXECUTE to continue; it can broadcast only original prepared bytes or the next authorized missing call. If all 68 calls are mined but awaiting finality, use RECONCILE until complete. No audit run is authorized merely by partial public upload.

## Primary API references

- https://ethereum.org/developers/docs/apis/json-rpc/
- https://eips.ethereum.org/EIPS/eip-7825
- https://docs.ethers.org/v6/single-page/
- Existing contract/policy: docs/public-anchor-foundation-v1.md and docs/sepolia-deployment-v1.md.

## Local verification result

64 Node tests passed (30 publisher/authorization tests and 34 existing deployment/recovery tests), including full 6,596-fixture readback and original 68-transaction reconciliation; 60 focused Python tests and seven installer fixtures passed. Compiled EVM integration verified journaled creation and 100 fixture officer writes. These are local tests, not a public research upload. The separate earlier unchanged-contract foundation test covered all 6,596 EVM fixture writes on the operator Mac.
