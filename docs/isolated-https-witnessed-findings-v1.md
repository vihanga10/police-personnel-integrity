# Genuine Fabric peers with HTTPS recovery witnesses: isolated validation v1

## What this step adds

Adds a disposable integration harness for the committed secure witness protocol.
The original production-source libraries and previous launchers remain unchanged.
New files compose the genuine Fabric Gateway SDK and two real Fabric peers with
mutual-TLS HTTPS recovery witnesses running in separate Node child processes.
The public leg executes the existing findings contract on a real local Ganache EVM.

Installing these sources does not run Docker, create a ledger, generate operational
credentials, provision research storage, enable intake, deploy a witness service,
submit to an existing chain, or select existing database/RPC/wallet configuration.
RPC 1 remains deferred. Explicit test execution creates only owned disposable
resources with temporary test credentials. No live research records are used.

## Test topology and trust

The existing Dockerfile.dual installs the unchanged pinned Fabric SDK and public
package lockfiles. The launcher retains the previously tested Fabric 2.5.16
network and findings-chaincode lifecycle, with two peer organizations and an
orderer. It creates no host ports, named ledger volumes, host network, Docker
socket mount or existing network references.

Within the disposable runner, the Fabric and public witness services have distinct
TLS CAs, server/client certificates, Ed25519 keys, authoritative directories and
child process IDs. HTTPS listeners bind only ephemeral, explicitly configured
loopback ports. A pinned backend configuration creates the real secure client;
requests cross a genuine TLS 1.3 socket. There is no local-call witness fallback.

The test provisioner explicitly invokes the committed administrative provision
command for a new operation before making its client available. Provisioning is
not an HTTP route. The witness process starts from the pinned service configuration,
validates private files, and reopens durable signed history on restart. The child
has test-only fault injection over its private parent IPC channel. That facility
is not present in the committed HTTPS service API and must never be used as an
operational service entry point.

All processes intentionally share the test host, OS user and container security
domain. Separate processes are not evidence of independent administration or
independent anti-rollback storage. This package does not establish AWS deployment,
production witness trust, key rotation, or a migration of fixture histories.

## Completion requirements

A successful Docker run requires both completion receipts. The first confirms
all 12 existing genuine SDK/peer checks, including:

- authenticated peer TLS, exact genesis and normalized lifecycle definitions;
- actual endorsement, VALID commit and exact findings readback from both peers;
- encrypted retention, original transaction recovery and read-only reconciliation;
- denied writer, conflicting immutable content and private-field rejection;
- original SDK transaction-byte rehydration and actual MVCC invalid-commit rejection.

The second additionally requires six HTTPS/Fabric checks:

1. A fresh witness child process reopens the original checkpoint, while the runner
   reconciles the same Fabric transaction without endorsement or submission.
2. A CA-valid but unapproved TLS client is refused before the Fabric SDK factory.
3. A witness outage stops before the SDK factory; restarting it permits only
   reconciliation of the original transaction.
4. A whole local recovery-directory rollback is refused against the fresh HTTPS
   tip before SDK access; restoring the exact retained bytes restores reconciliation.
5. Failure before the witness commits an attempt checkpoint prevents broadcast.
   Read-only recovery cannot repair it; writable recovery confirms the original
   attempt, then only observes the original unsubmitted transaction.
6. Failure after the witness commits an attempt checkpoint but before its HTTP
   acknowledgement also prevents broadcast and transaction replacement.

The last two checks use actual endorsed SDK transaction bytes. They verify exactly
one endorsement, zero submissions, and the expected authoritative sequence both
before and after the injected failure. Missing transaction observation is asserted
as a bounded QSCC error, not treated as permission to issue another transaction.

The run also requires all 16 prior composition scenarios, now using HTTPS witnesses:
interruption between chains, acknowledgement loss, each retained-stage interruption,
uncertain transmission before/after delivery, pending receipts/finality, disagreement,
changed Fabric gate, corrupted retained plan and whole-directory rollback. The public
runner rechecks the original verified Fabric receipt through genuine peer queries.

## Evidence boundaries

`PEER-PASSED.json` records 12 genuine checks.
`HTTPS-WITNESS-PASSED.json` must identify 16 composition scenarios, six HTTPS checks,
two actual SDK submission barriers, real peer execution, HTTPS process transport
and witness restart, with zero research records. It must explicitly retain:

- `independent_witness_deployment_verified: false`
- `public_finality_simulated: true`
- `public_provider_independence: false`
- `live_research_ready: false`

The secure service protocol is not the old local-call witness fixture; nevertheless,
the generated credentials, loaded-source gate, network and deployment remain test
fixtures. The fixture source gate checks equality and does not replay a research
snapshot, establish an AlgorithmPermit, authenticate source custodians or prove
research readiness. The original runners' gates are not waived for live execution.

## Local and Mac validation

Local tests exercise actual HTTPS processes, provisioning, before/after update
failure, restart, outage, denied client, operation isolation and rollback. The local
composition uses Fabric receipt doubles plus actual EVM execution. Python checks
verify source closure, isolation/cleanup helper preservation and strict completion
requirements. These checks are not a substitute for the Docker peer run.

After installation, run the commands in README.md. Docker Desktop must be running
for the final launcher. Its phases may take several minutes; it retries bounded
read-only peer startup/observation operations. Witness updates and blockchain
submissions are never automatically retried by the harness's protected runners.

Success message:

```text
12 real Fabric peer checks, 6 HTTPS witness checks (including 2 SDK submission barriers) and 16 HTTPS-witnessed dual-chain scenarios passed. Public finality and independent deployment remain unverified.
Owned disposable containers/network/image removed. Shared images preserved.
```

Cleanup inspects ownership labels before removing only this run's resources. It
never prunes all containers/networks/images. Successful temporary directories are
removed; private failure logs remain for diagnosis. Failure directories also contain
disposable private keys: share only the requested narrow log, never the entire
folder or credential files. A cleanup failure is a failing suite.

## What remains after this step

Even a successful peer run is not operational deployment. Independent witness
hosting/storage administration, reviewed trust and key lifecycle, full backend
readiness composition, live public-provider integration, scoped search/UI and
research evaluation remain outstanding. RPC 1 and fresh readiness must be resolved
before live research execution. No push to GitHub or AWS deployment is performed.
