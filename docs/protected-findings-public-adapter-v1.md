# Protected public findings adapter V1 — isolated fixture integration

## Scope

This is a trusted backend library with **fixture transports only**. It supplies
no HTTP endpoint loader, deployment command, request route, environment-file read,
wallet provisioning or live network adapter. All endpoints must be distinct HTTPS
hosts ending in `.invalid` and supplied capabilities must explicitly declare
`fixture_transport: true`. These flags are an internal capability contract, not a
sandbox or evidence that an arbitrary callback is safe. Never accept these objects,
approver keys, encryption keys or callbacks from an HTTP request.

RPC 1 remains deferred. Existing databases, CSVs, contracts and evidence anchors
are unchanged. Source installation adds files only. Tests use generated wallets,
generated Ed25519 approvers and controlled provider doubles; their receipts,
finalized blocks and source-loader callbacks are fixtures. Genuine local-EVM
contract tests from the previous step remain included in the regression command.
These tests do not demonstrate independent live providers, consensus verification,
real Fabric-to-public integration, production recovery or research execution.

## Files and dependencies

- `artifact.js`: binds the committed contract's immutable writer references and
  computes the actual expected runtime SHA-256 from bytecode bytes.
- `network.js`: strict fixture configuration, Sepolia chain/genesis identity,
  recent latest heads, canonical quantities and common finalized block selection.
- `public-adapter.js`: transaction preparation/signature verification, bounded
  single submission and exact two-provider finalized observation.
- `protected-public-runner.js`: approval/full-loader guards and encrypted retention.
- Two fixture/test files, plus this document.

No existing file is updated. The standalone findings package's existing test glob
runs the new tests. Existing ethers 6.15.0, solc 0.8.30 and Ganache 7.9.2 dependencies
are reused. Retention reuses the reviewed AES-256-GCM store from the Fabric bridge;
new operation/selection hashes and policy domain bind it to the public run. Use a
separate owner-only directory, outside and non-overlapping with the repository,
and a dedicated encryption key. Key separation from other domains must be enforced
by the operational trust configuration, which is pending.

`runtime_sha256` here is SHA-256 of raw deployed bytecode bytes. Do not substitute
the original OfficerEvidence deployment helper's JSON-string digest convention,
or the compiler's unresolved runtime template. The new adapter computes and checks
the expected writer-bound FindingsAnchor runtime itself; no caller-chosen ABI or
artifact overrides are accepted. It never deploys a contract.

## Protected selection and approval

The signed selection binds `private_sha256`, `public_sha256`, `history_sha256`,
`code_revision` (full 40-character Git revision), `network_config_sha256`, the
existing public destination, exact public payload and original Fabric receipt.
The payload's Fabric destination/transaction/receipt hashes must match that receipt,
and its publication ID, public digest and Merkle root must match the Fabric payload.
The Fabric receipt must identify a VALID commit with both organizations.

Schema and SHA matching do NOT authenticate that receipt. `checkLoaded(action,
selection, mode)` is a mandatory **trusted full-loader boundary**. Before each
critical action it must replay original anchored evidence and verify the permit,
prepared encrypted commitments, source revision, witnessed findings/recording
history and keys, current readiness/authority, and original Fabric receipt using
fresh authenticated two-organization observation. It must return the exact approved
selection. Test callbacks return fixtures; there is no operational Python-to-Node
composition or full research replay installed by this step.

Approvals use Ed25519 backend-selected trust keys, exact selection/mode, canonical
UTC timestamps and at most ten minutes of validity. EXECUTE and RECONCILE require
separate fresh grants. Original retained EXECUTE approval is checked historically
for its signature/scope/bounded interval; expiry does not invalidate its audit
record. The current grant is checked again after asynchronous guards.

## Transactions, retention and recovery

The compiled `publish(bytes32,bytes32[5])` ABI is used unchanged. Before signing,
both fixture providers must report the pinned Sepolia identity, recent heads,
matching idle wallet nonces, sufficient balances, bounded gas and fees. Runtime,
writer and policy/namespace constants are read at one common finalized block.
A publication already present cannot be signed as a fresh operation; its original
transaction lineage is required. Only the precise encoded `publication absent`
revert permits preparation; transport/authorization failures do not imply absence.

The signed EIP-1559 transaction is parsed with genuine ethers. Its signer, type,
chain, destination, zero value, exact calldata, empty access list, canonical signed
encoding, nonce, gas and fee fields must match preparation. Gas is bounded at
500,000 with a 20% estimate margin; configured max fee <=20 gwei, max total cost
<=0.1 ETH, and confirmations 12–128. These are local safety caps, not gas forecasts
or a budget authorization for real deployment/submission.

The encrypted immutable stages are intent, plan (including signed raw bytes),
attempt, acknowledgement and final receipt. File/directory permissions, exclusive
publication, fsync, locking and AES-GCM binding are enforced by the existing store.
The attempt is durable **before** entering the submit path. Each initial submit
invokes one provider exactly once with the retained bytes. No automatic second
provider broadcast, nonce/fee replacement or transaction regeneration occurs.

After an attempt, EXECUTE and RECONCILE only observe the original hash. Missing
receipts are PENDING, never ABSENT. If a process stops after the attempt marker but
before actual delivery, it remains pending and needs separately reviewed manual
recovery; this package intentionally does not rebroadcast. Reconciliation needs
no wallet and writes no stages. A previously saved final receipt is always freshly
re-observed; missing/regressed finality or changed inclusion is a hard stop.

The directory lock covers one operation, not every operation sharing a wallet.
Production needs a dedicated writer/serialized nonce allocation and independent
anti-rollback protection. AES-GCM and local inventory hashes detect alteration,
but do not detect deletion or restoration of a whole earlier directory. Live
execution stays unavailable while independent recovery protection and operational
composition remain pending. Stale locks require inspected recovery, never automatic
removal by this runner.

## Final verification

Both receipts must agree and describe the original successful transaction, exact
one-time Published event and inclusion block. Signed transaction fields, the exact
transaction index inside that block, event address/data/topics and execution fees
are checked. The receipt must have status 1 and bounded gas/price. Finality requires
both finalized views to cover inclusion and both latest heads to satisfy the
confirmation threshold. State queries use the lower common finalized height,
whose hash must agree on both providers and not exceed their latest heights.

At that fixed block, both providers must return the exact compiled runtime,
writer/constants, five stored hashes and first recorded block number. Original
inclusion and verification blocks are read again to detect changes during checks.
The final receipt preserves the coordinator's schema and original inclusion hash;
advancing finalized heads do not change the saved receipt. This is verified
agreement between the supplied fixture views, not cryptographic proof of consensus.
Distinct hosts alone cannot establish real administrative/provider independence.

The result reports `ISOLATED_PUBLIC_VERIFIED` or PENDING and always explicitly
sets `both_chains_anchored: false` and `live_chain_verification: false`.
No accepted research state is changed by this library.

## Validation and next work

From the repository:

```bash
cd blockchain/public/findings
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Node 24. Native Ganache bindings may fall back to JavaScript as previously tested.
New tests cover signed-byte retention, one-attempt submission, restart/read-only
recovery, interruption at every retained stage, acknowledgement loss, missing
receipts/finality, provider disagreement and reorgs, signature/approval/scope checks,
Fabric binding, malicious signers, fee/nonce/gas safeguards, runtime/event/storage
readback, private paths and encrypted-artifact tampering. Package installation is
also smoke-tested with temporary real Git repositories and exact source checks.

Validation result: **187 tests passed, zero failures/skips** (90 previous contract/
schema tests + 97 new adapter/runtime tests). The new writer-bound artifact was
compared to actual local-EVM deployment bytecode; provider/finality observations
remain doubles. Twelve installer smoke scenarios passed. In smoke copies only,
the required ancestor was substituted with the temporary repository fixture commit;
the delivered installer requires the user-confirmed 1053bbb ancestor.

Pending: genuine disposable dual-chain integration, operational full-loader bridge,
independent recovery witness, reviewed provisioning/deployment/writer trust and
live HTTP transport with safe read diagnostics. Then fresh readiness, RPC 1
resolution and separately authorized live execution/evaluation. No production
credentials or existing RPC configuration should be supplied to these tests.

Primary references:
https://ethereum.org/developers/docs/apis/json-rpc/ and
https://docs.ethers.org/v6/single-page/ .
