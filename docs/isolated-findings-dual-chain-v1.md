# Isolated findings dual-chain validation V1

This is a test harness, not an operational anchoring endpoint. It composes the
existing protected Fabric bridge and public runner using synthetic opaque findings.
Fabric is verified first; its original FINAL/VALID receipt, destination and bare
64-character transaction ID are bound into the public payload with canonical
SHA-256 digests. Public EVM transaction IDs retain their distinct `0x` format.
Every public runner guard re-observes the original Fabric receipt before proceeding.

## Evidence and limits

| Check | Execution |
|---|---|
| Local Node suite | Actual Ganache EVM, real compiled contract, real signed transactions, Fabric receipt doubles |
| Docker suite | Genuine Fabric SDK/mTLS, disposable two-organization peers, actual Ganache EVM |
| Public genesis pin | Simulated Sepolia genesis identity; Ganache is not Sepolia |
| Public `finalized` head | Simulated test input, not proof of consensus finality |
| Two public provider views | Two wrappers over the same EVM; not independently operated providers |
| Source/permit/history gate | Synthetic selection equality plus fresh Fabric receipt observation, not full research replay |
| Production readiness | Not established; no research records or production keys used |

The wrappers expose no HTTP listener or real public RPC. The contract is deployed
only in memory, with randomly generated disposable funds and keys. Runtime,
transaction, receipt, event and state readback come from actual EVM execution.
Only genesis identity, finalized selection and fault injections are simulated.
The existing public adapter's `independent_readback` field is interpreted as
agreement between supplied fixture views here, not operational independence.
Both runners still report `both_chains_anchored: false`; the summary explicitly
reports simulated public finality, absent public provider independence and absent
live research readiness.

## Fifteen composed scenarios

1. Uncertain Fabric submission before delivery: stop public work; reconcile only, never automatically replay.
2. Fabric VALID receipt binds exact public event/storage and original transaction IDs; restart and read-only reconciliation preserve bytes.
3. Stop between chains, then recover original Fabric lineage before public signing.
4. Lost Fabric acknowledgement after delivery: recover original ID before public execution.
5–10. Stop after public intent, plan, attempt, submission, acknowledgement and final receipt. Intent/plan can resume safely; a durable attempt prohibits automatic signing/submission again.
11–12. Lost public transport before/after actual EVM delivery: pending versus verified recovery without rebroadcast.
13. Unavailable finality, inadequate confirmations and missing provider receipt: pending, followed by read-only recovery.
14. Provider disagreement, saved-final regression and denied Fabric gate: fail closed.
15. Corrupted encrypted retained plan: fail without another signature/submission.

The Node suite has **two top-level tests**. One executes all fifteen scenarios;
the second checks each Fabric/public binding field and transaction ID format.
The Docker entry also runs all twelve established genuine Fabric peer checks,
including writer denial, immutable conflicts, extra fields, credential drift,
SDK rehydration and an actual invalid MVCC transaction.

## Run locally on the Mac

From the repository:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_isolated_findings_dual_chain.py \
  tests/test_isolated_findings_fabric.py -q

cd "$HOME/Developer/police-personnel-integrity/blockchain/public/findings" &&
npm test
```

Expected Python total: 19 passed. Expected Node total with the previously installed
adapter: 189 passed, no skips. Ganache's native binding fallback can print a warning;
judge the final test result. If dependencies are missing, use the already pinned
`npm ci --ignore-scripts --no-audit --no-fund` in the findings package.

Then, with Docker Desktop running:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/run_isolated_findings_dual_chain.py --suite dual-chain
```

This explicit launcher downloads/builds images if needed, creates fresh temporary
Fabric identities/channel/chaincode and executes fixture-only transactions. It
creates no host ports, existing networks, named ledger volumes or Docker socket
mounts. It uses the existing ownership-label cleanup logic and removes only this
run's containers, network and image; shared images remain. Success also removes
the private temporary directory. Failure retains private logs before cleanup.
The final peer-test phase is bounded to 30 minutes; other phases to 10 minutes.
Do not upload the entire temporary directory: it contains disposable private keys.
A failure phase and a narrow diagnostic log are sufficient for diagnosis.

Expected final message:

```
12 real Fabric peer checks and 15 dual-chain scenarios passed. Public execution used a real local EVM; public finality and provider independence remain simulated.
Owned disposable containers/network/image removed. Shared images preserved.
```

## Package and maintenance

Eight additions only: launcher, launcher tests, dedicated Dockerfile, dedicated
peer entry, local EVM transport, composed scenarios, Node test and this document.
Existing source is unchanged. The new launcher freezes the already validated
isolation/cleanup helpers; tests compare those helpers with the original launcher.
The installer pins the underlying modules and original peer entry. Future changes
to either base require a deliberate compatibility review of this harness copy.
Both dependency lockfiles are reused unchanged and installed separately in the
container. Every relative module and compiler contract source is allowlisted and
checked before delivery; no CSV, .env, private credential or node_modules is copied.

The installer checks branch `feat/identity-resolution`, ancestor `89eb373`, exact
source hashes and staged targets. `--check` writes nothing. Installation adds
source/tests/docs only, never invokes Docker/npm or changes a database. An existing
partial installation is rejected for inspection. Interrupted installation may
leave partial files; normal exceptions roll back only the created file inodes.
Package hashes check accidental modification, not independent publisher identity.

## Remaining before research execution

Actual combined Fabric/EVM execution must pass on the Mac; Docker is unavailable
in the development environment. Operational full-replay/permit/history/readiness
wiring, independent recovery witnesses, real public provider integration,
reviewed deployment and provisioning are still pending. This harness cannot
establish historical intake dates or real Sepolia finality. RPC 1 remains deferred.
Original evidence anchors, CSVs and research databases remain untouched.
