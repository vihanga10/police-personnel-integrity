# Dedicated public findings contract V1

## Status and scope

Source and isolated EVM tests only. No deployment command, RPC configuration,
production credentials, wallet provisioning, database migration or backend hook
is provided. RPC 1 remains deferred. Passing these tests is not live anchoring,
consensus/finality verification, an independent security audit or research evaluation.

The separate `FindingsAnchor` contract does not call, inherit, replace or update
`OfficerEvidence`. Later finding/correction/review histories produce new opaque
publication IDs through the existing salted HMAC preparation. A published ID is
immutable. The contract does not interpret review outcomes or decide historical truth.

## Wire mapping

The existing coordinator's public-stage schema remains unchanged:

| JSON field | ABI |
| --- | --- |
| `policy` | Constant `FINDINGS_PUBLIC_ANCHOR_V1`; checked by pure preparation |
| `namespace` | Constant `findings-anchor-v1`; checked by pure preparation |
| `publication_id` | `publish` argument 1, `bytes32` |
| `public_sha256` | argument 2 array index 0 |
| `merkle_root` | array index 1 |
| `fabric_destination_sha256` | array index 2 |
| `fabric_transaction_id` | array index 3 |
| `fabric_receipt_sha256` | array index 4 |

All six hash fields must be nonzero lowercase 64-character hex in JSON, then
converted to bytes32 with a `0x` prefix. No entry descriptions, officer identifiers,
NICs, names, dates, counts or review decisions appear in this public contract schema.
`argumentsFor()` rejects missing/extra fields, inherited/accessor values and wrong
policy/namespace. It is a pure conversion, not receipt authentication.

The contract exposes `publish(bytes32,bytes32[5])`, `readPublication(bytes32)` and
four constant/immutable getters. Publish calldata is exactly 196 bytes; read
calldata exactly 36 bytes. Trailing data and unknown selectors are rejected.
Native currency is rejected by the available entry points (forced balance transfers
are outside that guarantee). The immutable writer is selected at construction;
zero writer and non-Sepolia chain IDs are rejected. Tests simulate Sepolia's chain
ID in a local in-memory Ganache EVM, not by connecting to Sepolia.

Only the writer can publish, including retries. Exact retries return without
storage writes or new events. Any metadata conflict reverts and retains the first
record. The publication stores its first mined block number and emits all opaque
metadata once. This block number is chain observation metadata, not evidence
intake/system time or effective time. EVM contracts cannot directly know their own
transaction hash; original transaction identity must be retained and checked by
the later protected adapter using the event and transaction receipt.

Public reads are intentionally permissionless. Hiding officer identity depends on
trusted salted HMAC generation and private key/salt handling, not on public-chain
access control. A malicious authorized writer can submit arbitrary hashes; this
contract cannot authenticate a Fabric receipt, verify its VALID status, enforce
both-organization readback, check the Merkle content, or establish finality.
Those checks are mandatory in the pending protected public adapter and dual-chain
integration. The constant namespace separates schemas; the future adapter must
also pin chain/genesis, deployed address, writer and actual runtime bytecode.

## Compile and test

From the repository:

```bash
cd blockchain/public/findings
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Use Node 24. Dependencies match the existing public foundation: solc 0.8.30,
ethers 6.15.0, Ganache 7.9.2, with a separate package/lockfile. The compiler is
checked against `0.8.30+commit.73712a01`, optimizer 200, Shanghai, no viaIR.
The compiler's `runtimeTemplate` includes unresolved immutable writer references;
it is NOT the deployed runtime pin. The later adapter must bind the selected
writer and compare the actual deployed runtime. No artifacts are saved by compile.

Ganache can print a native µWS compatibility warning on Node 24 and use its
JavaScript fallback; the test result determines success. The lockfile marks the
bundled Darwin-only `fsevents` dependency optional so clean installs work on Linux
and macOS. No dependency lifecycle scripts are run. Tests select Ganache's in-memory
provider explicitly and generate disposable accounts; environment RPC URLs and
existing wallets are not read. Dependency downloads use the npm registry.

Local validation: 90 tests passed, zero failures/skips. Coverage includes Python
canonical hash/vector mapping, schema rejection, bytecode compilation, wrong chain
and zero writer, writer restrictions, mined failures, all five metadata conflicts,
zero fields, events/readback, exact retry opcode trace (no SSTORE/LOG), 20 later
publications, historical readback, malformed/extra calldata and value rejection.
A separate local OfficerEvidence deployment receives a fixture batch; its batch
and runtime remain unchanged after findings writes/retries/conflicts. The original
contract source is read from its existing repository path and never overwritten.

The fixture's opaque public commitments reuse the prior Python/Fabric vector.
Fabric destination and receipt objects in `test/public-vector.json` are fabricated
serialization fixtures, clearly labelled, and carry no live authentication claim.
No research records are used. Twelve installer smoke scenarios passed with real
temporary Git repositories; only the ancestor ID was substituted in smoke copies
to match their fixture commit. They cover read-only check, installation, idempotency,
wrong branch/ancestor, source/package drift, existing/staged targets, symlinks,
hardlinks and normal-exception rollback. The installed files also passed all 90
tests using dependencies from a clean npm ci.

## Next integration work

Protected public transaction preparation/retention, explicit submission approval,
ambiguous-submit reconciliation using the original transaction identity, independent
finalized readback, and dual-chain end-to-end failure/recovery tests are pending.
Operational backend wiring, independent recovery protection, witness deployment,
research readiness, RPC 1 resolution and reviewed live deployment remain pending.
No automatic migration/rotation/admin/deletion path is included. Lost/compromised
writer management requires a separately reviewed deployment/operational plan.

Primary references: Solidity 0.8.30 compiler via the pinned npm package;
https://docs.soliditylang.org/en/latest/contracts.html and
https://ethereum.org/developers/docs/smart-contracts/testing/ .
