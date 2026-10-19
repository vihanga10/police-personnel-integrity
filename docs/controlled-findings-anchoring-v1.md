# Controlled findings anchoring: isolated coordinator v1

This step implements and tests transaction ordering, signed authorization,
durable retry state and receipt binding for a findings publication. It DOES NOT
implement a Fabric Gateway, Solidity contract, RPC verifier, production wallet,
deployer or operational command. Both injected adapters must explicitly be test
fixtures. Success is `ISOLATED_BOTH_VERIFIED`, with `findings_anchored=False` and
`live_chain_verification=False`. Do not cite these tests as real dual-chain
anchoring, real consensus/finality validation or completed research evaluation.

## Inputs and authorization

The internal `run_isolated` boundary takes an original fully verified snapshot,
a configured findings registry/witness, dedicated commitment keys and their
backup, an externally approved encrypted commitment artifact SHA-256 and public
payload SHA-256, a signed approval, separately configured trusted approver keys,
two isolated adapters and an existing owner-only recovery directory outside the
repository. Fixtures supply the snapshot in tests; this is not a request API.
No public wrapper accepts request-provided snapshots, keys or destination pins.

Approval signatures use Ed25519 over canonical JSON, an explicit policy, mode,
key ID, actual issuance/expiry timestamps and exact selection. Maximum validity
is 600 seconds. Selection binds the saved encrypted artifact, complete witnessed
history digest, exact public digest, committed source revision and both chain
destinations. Caller-provided approver keys are not a trust configuration.
This step creates only ephemeral test signing keys; it provisions no authority.
Production eligibility, authorization and key-domain separation are still pending.

The backend regenerates commitments using both copies of the dedicated keys and
opens artifacts using both encryption recoveries. Source context/publication,
subject universe, snapshot content, permit deadline, key/configuration pins,
actual clock, destination identities and files are checked repeatedly. EXECUTE
also reselects the same latest witnessed history before and after stages. A new
history version stops execution; it cannot silently rebase this publication.
RECONCILE requires a fresh signed read-only approval and all existing plans/final
receipts. It can audit a prior publication without asserting latestness.

## Separate findings destinations

The Fabric destination pins genesis SHA-256, channel, dedicated chaincode,
`findings-anchor-v1` namespace and both Org1MSP/Org2MSP readbacks. The original
`officer-evidence-v1` chaincode is explicitly refused. Public destination pins
Sepolia chain ID 11155111, lowercase nonzero contract/writer addresses, runtime
code SHA-256, findings namespace and FINALIZED policy. Approval must later select
a newly verified dedicated contract address; a namespace string alone does not
prove contract separation. Original evidence contracts and anchors are untouched.

Private-ledger payload includes only opaque publication handle, keyed commitment,
public payload digest and Merkle root. Public payload includes those opaque
publication/root/digest fields and an exact private destination digest,
transaction ID and final receipt digest. No raw officer UUID, NIC, name, finding,
decision, source reference or private artifact digest is sent to either adapter.
Transaction identifiers, writer identities and timing can reveal metadata;
privacy here is a payload property, not an anonymity claim.

## Ordering and durable recovery

1. Retain the original signed EXECUTE approval in an encrypted immutable intent.
2. Ask the private adapter to PREPARE a transaction without broadcasting.
3. Save the exact transaction identity/envelope in dual-recoverable encrypted
   storage, fsync it, then submit only that transaction if observed ABSENT.
4. Require an exact VALID receipt, pinned destination and both peer readbacks.
5. Save that receipt, prepare and persist the public transaction that binds it.
6. Require successful execution, finality and independent public readback.
7. Save its receipt, reobserve the private transaction after public verification,
   then recheck the permit, approval, files, destinations and current history.

All outputs are 0600 inside an existing 0700 directory outside source and findings
stores. Nonoverwriting hard-link publication and directory fsync reuse the existing
encrypted storage primitive. A directory flock serializes cooperating processes
on the same local filesystem. This is not a distributed lock or protection against
a privileged administrator. Missing final receipts after acknowledgement loss
can be completed in EXECUTE with a renewed same-selection approval, preserving the
original transaction plan. A PENDING, unexpected or invalid observation stops.
An error is never interpreted as ABSENT. Completed records cannot be rebroadcast
if a later observation reports absence. No receipt or transaction plan is deleted.
Unexpected staging remnants are preserved for inspection, not auto-cleaned.

There is no atomic transaction across chains. A private success/public failure
remains a partial publication. A complete public write followed by failed private
reverification is also a stopped run, with artifacts retained. An old saved result
does not establish permanent chain validity, latestness or anti-rollback safety.
Locally rolled-back recovery files cannot be detected independently by this step.

## Adapter contract and remaining implementation

The adapter is a trusted backend/test boundary, never an untrusted JSON receipt.
`inspect(destination)` independently verifies the pinned destination.
`prepare(operation,payload,destination)` has no chain writes and reserves exact
transaction bytes/identity. `observe(plan,payload,destination)` authenticates
that transaction and the exact contract readback, returning ABSENT, PENDING or
a FINAL receipt. `submit` broadcasts only the saved transaction. Plans and
receipts have strict schemas; public submissions bind the verified Fabric result.
The test adapters model these guarantees; flags such as `finalized=True` are NOT
cryptographic or network evidence on their own. No operational adapter exists yet.

Before enabling a real path: implement append-only dedicated findings chaincode
and public contract, endorsement/MVCC and writer authorization, exact transaction
encoding and nonces, authenticated Gateway/RPC transports, genesis/runtime/address
verification, independently read chain receipts/state and finality, fee budgets,
bounded retries, offline recovery, key trust configuration and protected runner
loading. Exercise those real adapters on disposable chains before deployment.
Record externally pinned recovery/result digests in the approved anchoring workflow;
do not accept a locally editable old result as independent anti-rollback evidence.
RPC 1 remains deferred; original evidence reconciliation, actual witness deployment
and fresh readiness must pass before any real research execution or chain writes.

## Validation scope

Tests use the existing encrypted findings/registry/witness and full permit fixtures
plus in-memory ledger adapters. They cover signed approval scope/time, sequential
chain binding, acknowledgement loss, pending transactions, exact retries,
read-only reconciliation, receipt mismatch, invalid/private single-peer receipt,
public revert/nonfinality/single readback, missing completed transactions, source
and history changes, destination separation, storage boundaries and corruption.
Original findings inventory remains unchanged; tests do not use existing databases,
RPC endpoints, production wallets, original ledger transactions or real chains.
