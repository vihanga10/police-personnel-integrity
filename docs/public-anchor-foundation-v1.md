# Sepolia public commitment foundation v1

This step records the verified private Fabric checkpoint and supplies a Solidity contract, offline publication/proof planner, and local EVM tests. It does not deploy a public contract, create a wallet, contact an RPC endpoint, submit research transactions, or run an audit.

## Exact coverage and immutability

Use Ethereum Sepolia (chain ID 11155111) for this research demonstration. Test ETH pays gas; faucet funding can avoid a real-money payment, but balances, faucet limits and future availability require checking before deployment. Sepolia is a public test network, not a promise of permanent production evidence retention.

The original OFFICER_PROTECTED_COMMITMENT_V1 publication is reused without recomputing or replacing its values. Contract storage includes every individual officer's original opaque publication handle and commitment, batch version 1 (fixed by this contract), the original public payload SHA-256, shared/coverage/batch commitments and original Merkle root. No officer UUIDs, NICs, names, ciphertext, keys, findings or classifications are contract inputs.

A 6,597-leaf tree comprises 6,596 officer leaves plus one batch leaf. The contract exactly reconstructs the original lowercase, sorted-key JSON officer and batch leaf forms. Hashing is SHA-256 with 0x00 leaf and 0x01 parent domain bytes; the last node duplicates at odd levels. Proofs include the leaf index and exact tree width, rejecting reordered, shortened and incorrectly duplicated paths. Leaf proofs are prepared off-chain, verified on-chain for each inserted officer, and supplemented by later full readback.

Only an immutable writer address may create, append or seal. A zero writer and any chain other than Sepolia are refused. Each append is exactly 100 records, except the last 96, ordered by original opaque handle. All 66 chunks are required before seal. Exact create/chunk/seal replays emit no new state-change events; any conflicting replacement fails. There is no upgrade proxy, owner transfer, delete or edit method. New received evidence will require a separately specified versioning workflow; this contract does not accept commitment version 2.

The contract verifies membership in the declared root. The original full-publication SHA-256 and shared/coverage metadata are recorded declarations, not independently regenerated HMACs or a full JSON payload hash computed on-chain. The guarded publisher must validate the entire original publication, authenticate its live gate and Fabric receipts, and read back every value before any audit-ready claim. Offline JSON receipt comparison alone cannot authenticate a network or authorize submission.

## Local checks

From the repository root:

```bash
cd blockchain/public
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Dependencies are pinned in package.json and package-lock.json: solc 0.8.30, ethers 6.15.0, Ganache 7.9.2. Compiler settings: optimizer runs 200, viaIR false, EVM Shanghai. Ganache runs an in-process local EVM with chain ID 11155111 solely to exercise the constructor guard. It is not the public Sepolia network. Its generated accounts and fixture commitments contain no research input. The lockfile marks Ganache's Darwin-only bundled fsevents entry optional so npm ci works on both Linux and macOS without changing its version or integrity. Node 24 may report a native µWS module incompatibility and use the JavaScript fallback; no remote RPC is involved.

The complete local EVM test can take roughly 10–20 minutes depending on the machine; it logs progress every ten chunks and has a forty-minute timeout for slower hosts. The tests compile the actual Solidity source, deploy its bytecode locally, exercise access restrictions and proof rejection, submit all 66 chunks, query all 6,596 stored values, seal, and test conflicting and exact retries. Local gas measurements are not a public fee quote. The contract is research code, not an independently audited production contract.

After source commit, optional captured-only compatibility check:

```bash
node blockchain/public/check-plan.js \
  "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50/public-commitments.json" \
  fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b \
  "$HOME/ResearchEvidence/police-personnel-integrity/research-fabric-anchor-attempts/279faf60-f0d7-48c1-ada1-741de89846a9/PASSED.json"
```

The checker requires owner-only regular files with no symlink components and emits aggregate public values only. It checks the saved RECONCILE result against the original publication, private network identity and 68/6,596 counts. It exports no files and does not refresh live evidence. A forged local JSON receipt is not blockchain proof; live authenticated reconciliation is required in the future publisher.

## Still required before public submission

Implement dedicated test-wallet/RPC configuration with secrets outside Git, pinned contract compilation/deployment receipt and runtime bytecode checks, fresh live evidence and Fabric reconciliation, gas and faucet-balance preflight, durable original signed transaction journals, ambiguous submission recovery, receipt/finality/reorganization checks and full contract readback. Then compare all 6,596 values and metadata with Fabric. Do not treat a local test, offline plan or transaction broadcast as completed public anchoring. Audit algorithms and encrypted append-only finding storage follow verified dual-chain anchoring.

## Primary references

- https://ethereum.org/en/developers/docs/networks/ — Sepolia application testnet and faucet resources.
- https://docs.soliditylang.org/en/v0.8.30/ — pinned Solidity compiler semantics.
- https://www.soliditylang.org/blog/2025/05/07/solidity-0.8.30-release-announcement/ — compiler release.
- https://github.com/ethers-io/ethers.js/releases — ethers version history.
- https://github.com/trufflesuite/ganache — local EVM testing implementation.

## Development verification

All 26 Node tests passed against the compiled Solidity contract and local Ganache EVM. The full 6,596-record store/readback/seal/retry test passed. Seven disposable-repository installer checks passed; clean npm ci also passed with the pinned lockfile. The full EVM run took about 19 minutes on the development host.

Measured fixture gas: maximum 100-officer chunk 6,375,977; all 66 chunks together 416,822,946. These figures exclude deployment, batch creation, sealing and any retries. They are local gas-unit measurements, not a Sepolia fee/funding estimate. Actual network estimates and faucet availability must be checked before signing.
