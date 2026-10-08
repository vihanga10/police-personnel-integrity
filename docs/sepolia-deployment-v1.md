# Dedicated Sepolia wallet and guarded empty-contract deployment v1

## Scope

The public contract foundation was tested on the operator's Mac: 26 tests passed, including all 6,596 fixture commitments. The operator committed and pushed it as `f257a75`. This step adds wallet recovery and deployment tooling. It does not publish research commitments, run an audit, access personnel databases or change the Fabric ledger.

Deploying an empty contract can precede the fresh evidence gate. Publishing research commitments cannot: the following publishing step must rerun the live evidence comparison, reconcile Fabric, bind the exact original publication and verify all public records after submission. Merely deploying this contract does not complete Stage 3.

## Wallet protection

Initialization creates a new dedicated random Ethereum wallet, encrypted JSON keystore, random 32-byte unlock-secret file and matching backup copies. All files are owner-only (`0600`) in separate owner-only (`0700`) directories outside Git. Both copies are decrypted and compared before use. No private key, recovery phrase or unlock secret is printed or supplied as a command argument. A public wallet address is printed for faucet funding.

The unlock file is deliberately available for unattended signing. Keeping it beside the encrypted wallet protects against accidental disclosure of the keystore alone, but does not protect against compromise of that directory or the operating-system account. This is a local research testnet wallet, not a hardware-backed production custody system. Keep both directories private and make an additional offline backup if required. Never put this wallet on mainnet or fund it with real assets.

The recorded primary and backup paths cannot be interchanged to create a second deployment. Existing wallet roots are refused rather than reset. A failed partial initialization preserves its files for inspection.

## RPC and deployment checks

Edit the private `network.json` generated in the primary wallet directory. Supply two HTTPS Sepolia RPC URLs from distinct hosts. Never paste API-bearing URLs or this file into the chat. Distinct hostnames provide a second observation; they do not prove independent operators or independently validate Ethereum consensus. Both providers remain trust dependencies.

Hard network pins:

- Chain ID: `11155111`.
- Genesis block hash: `0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9`.
- Current heads must be no older than two minutes, with at most 30 seconds future clock tolerance.
- Deployment gas limit is at most 12,000,000 and below both observed block limits. This is below the EIP-7825 transaction cap of 16,777,216.
- Default maximum fee: 5 gwei; priority fee: 1 gwei; maximum deployment exposure: 0.025 test ETH. These are configurable limits, not a fee quote or required funding amount. Hard policy limits: at most 20 gwei and 0.1 test ETH.
- Both RPCs must see an idle, identical wallet nonce before initial preparation and sufficient test balance for the maximum signed cost. Estimate gas on both and add 20 percent headroom. Base fee plus configured tip must fit the cap.
- At least 12 confirmations and inclusion below each RPC's `finalized` block are required. Twelve confirmations alone are insufficient.

Default validation uses RPC reads and gas estimation only. It cannot sign or submit a transaction. `--execute` is the only broadcasting mode. `--reconcile` can verify and save a local completion receipt, but cannot prepare or broadcast a deployment.

The exact Solidity 0.8.30 / optimizer-200 / Shanghai / no-IR compilation is reused. A second compilation exposes immutable-reference offsets and is required to reproduce the original bytecode exactly. The expected runtime fills only the compiler-identified immutable `writer` address. Both RPCs must report that exact runtime and the correct writer, chain and officer-count getters at the original deployment block.

## Durable recovery

One stable `deployment` journal belongs to the primary wallet root:

- `PREPARED.json`: original signed EIP-1559 transaction bytes and derived hash/address, compilation identity, network/configuration binding.
- `PASSED.json`: verified original transaction and inclusion block, runtime/compiler bindings, actual gas usage, two-RPC finality/readback result and zero research submissions.
- `run.lock`: single-process exclusion; a dead same-host process lock may be released without modifying the transaction or ledger. A live or ambiguous lock stops work.

Files are exclusive, owner-only and fsynced with their parent directory. A crash cannot silently replace a prepared transaction or completion. Signed transaction bytes are themselves public-broadcast material; private journals nevertheless stay outside Git. They do not contain the private key.

A retry can only rebroadcast the original signed bytes, with the original nonce, fees and deployment data. There is no automatic replacement or fee bump. If the response is lost, read both RPCs first. A consumed nonce with no original receipt stops for review. If finality has not arrived, the result is PENDING and no completion is invented. Do not delete a journal or initialize another wallet to work around a failure.

Reconciliation requires the original successful receipt, exact transaction fields, inclusion in the recorded block, agreement between providers, correct runtime and finality. It rechecks the inclusion block after finality queries. A failed receipt, readback mismatch, altered signed journal, changed configuration or displaced block stops. RPC-trusted finality is an observation, not a proof obtained by running a local consensus client.

## Operator workflow

Install and run focused tests before committing this source:

```bash
cd "$HOME/Developer/police-personnel-integrity/blockchain/public"
node --test test/sepolia-*.test.js
```

No new dependency or package-lock change is required. Native Ganache binding warnings may fall back to JavaScript as in the previous successful tests. Tests use dedicated random fixture wallets, fake RPCs and a local EVM. The local EVM adapter explicitly supplies test finality/genesis responses; it is not real Sepolia verification. No research keys or live RPC credentials are used.

After committing and pushing reviewed source, initialize:

```bash
cd "$HOME/Developer/police-personnel-integrity"
node blockchain/public/deploy-sepolia.js \
    --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
    --backup-wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1-backup" \
    --initialize-wallet
```

Save the printed public address. Obtain free Sepolia faucet test ETH; faucet availability, quotas and provider account requirements vary. Do not purchase mainnet ETH for this workflow. Use a trusted faucet and share only the public address with it.

Edit the private configuration on your Mac:

```bash
nano "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1/network.json"
```

Replace the two placeholder URLs with your Sepolia endpoints. Preserve JSON syntax and owner-only file permissions. Leave default fee bounds unless a reviewed preflight requires changing them. Configuration changes after preparation are refused; they require review, not journal deletion.

Run read-only preflight:

```bash
node blockchain/public/deploy-sepolia.js \
    --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
    --backup-wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1-backup"
```

Send only the aggregate preflight output before the first deployment. It contains the public address and maximum test fee exposure, not RPC URLs or keys. Deployment, when ready, uses the same command with `--execute`. That command sends only the empty contract creation transaction. If it returns PENDING, wait for finality and use the same command with `--reconcile`. A generic stopped message preserves private context; check the current phase and configuration without sharing sensitive files.

The CLI requires a clean committed `feat/identity-resolution` branch containing `f257a75`. Initialization and each deployment invocation record the current source revision in their aggregate output. The journal binds exact contract compilation, configuration and writer; later source revisions must still reproduce these bindings.

## Next work

Live Sepolia deployment verification is still required on the Mac. Then implement guarded publishing of the same 6,596 original individual commitments, with durable signed chunk transactions, fresh evidence/Fabric gates, original receipt and full-record comparison. Audit algorithms and finding storage remain pending; classification remains UNASSESSED.

## Primary references

- Sepolia network configuration: https://github.com/eth-clients/sepolia
- Ethereum JSON-RPC, block tags and estimation: https://ethereum.org/developers/docs/apis/json-rpc/
- Ethereum fee fields: https://ethereum.org/developers/docs/transactions/
- EIP-7825 gas cap: https://eips.ethereum.org/EIPS/eip-7825
- Ethers transaction and encrypted-wallet APIs: https://docs.ethers.org/v6/single-page/
- Solidity immutables: https://docs.soliditylang.org/en/v0.8.30/contracts.html#immutable

## Package verification

Development checks: 26 focused tests passed, including an actual compiled-contract deployment on a local EVM, four interrupted signed-transaction recovery paths and encrypted wallet backup recovery. Seven disposable installer fixtures passed: clean installation, dirty tree, wrong branch, dependency drift, payload drift, existing target and symlink target. No live Sepolia, production wallet or research evidence was used by these tests.

## Operator-observed deployment estimate correction (2026-10-08)

Both Sepolia providers reported 8,804,119 estimated gas, giving 10,564,943 with the existing 20% margin. The earlier 8 million local bound rejected that deployment. The local bound is now 12 million in both initial preparation and original signed-transaction verification; it remains below EIP-7825, and the observed block limits, budget, balance, nonce and fee checks still apply. This is an operator-reported live estimate, not a deployment receipt. The contract compilation and wallet are unchanged.

At the operator's configured 5 gwei fee cap, maximum signed exposure is 0.052824715 test ETH, exceeding both the 0.025 budget and 0.05 balance. A 2 gwei cap would give 0.021129886 test ETH at the same gas estimate, but is usable only if live base fee plus configured tip fits that cap. The installer does not change private fee configuration. Do not increase the budget or delete journals merely to pass validation. Before any private fee adjustment, verify no PREPARED.json exists and inspect both current base fees. Keep the budget and wallet recovery unchanged.

The regression suite models the exact reported gas estimate and checks fee budget, balance, both block limits, gas boundary and original signed-transaction validation. These tests use synthetic RPC responses, not a live Sepolia deployment.
