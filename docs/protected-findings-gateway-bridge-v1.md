# Protected findings Gateway retention and loaded-runner bridge

## Scope and status

This adds a trusted backend library and isolated tests, without enabling a
network entry point. The bridge composes the existing FindingsAdapter with
concrete encrypted filesystem retention and submission-state tracking.
No original evidence client, chaincode, Python coordinator, CSV, database,
configuration or dependency file is changed. No credentials are provisioned.

The Python dual-chain coordinator remains fixture-only. Its ABSENT protocol is
not adapted to this runner: unavailable observations always throw. Operational
Python/backend composition, independent recovery-state protection, genuine SDK
serialization/TLS/peer tests, deployments and public-chain integration remain
pending. Installation or unit-test success does not complete those requirements.

## Interfaces and trust boundary

`runProtectedLoaded(options)` is INTERNAL. The default mode is RECONCILE.
It accepts a backend-verified selection, a signed approval, backend-pinned
approver public keys, a dedicated pre-provisioned recovery directory and 32-byte
AES key, and trusted `checkLoaded` and `adapterFactory` capabilities. Neither
request input nor an HTTP caller may select these callbacks, keys or paths.

The selection binds exactly:

- private commitment ciphertext SHA-256 (externally approved);
- public commitment SHA-256;
- verified findings-history SHA-256;
- committed source revision;
- externally approved Gateway configuration SHA-256;
- the dedicated Fabric destination;
- the exact opaque findings publication payload.

The Node-specific approval policy is PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1. Its
body has policy, key_id, mode, issued_at, expires_at and selection. Signature is
canonical base64 Ed25519 over sorted canonical JSON. Times use exact UTC ISO
format with milliseconds. Approvals last at most 600 seconds and are checked
before and after protected operations. EXECUTE and RECONCILE grants are distinct.
The original EXECUTE approval is retained and authenticated for audit even after
it expires; every new run requires a fresh grant. This establishes configured
key authorization, not legal authority or delegation eligibility.

`checkLoaded(action, selection, mode)` MUST return the exact independently
verified selection after checking full original anchored replay/readiness,
AlgorithmPermit, dual-key private commitment verification, original source
context, actor/subject scope, immutable configuration and latest independent
findings witness. EXECUTE must select current witnessed history. RECONCILE may
verify the originally approved historic publication without claiming latestness.
This callback is a trust boundary, not a proof obtained by echoing request input.
Tests inject a controlled callback; production wiring is intentionally absent.
A backend closure must additionally validate externally retained recovery state
before execution to address directory rollback. No such service is provisioned.

`adapterFactory({retention, authorize, mode, expectedConfigSha256, destination})`
MUST create the configured existing FindingsAdapter, using connectFindings and
its externally approved configuration in a future operational composition.
The bridge owns retention and supplies its protected gate as authorize.
RECONCILE must construct READ_ONLY mode. Tests use FindingsAdapter with a
controlled transport and protobuf block fixtures, without contacting peers.

## Durable state and recovery

Each recovery directory belongs to one approved selection. Five immutable
AES-256-GCM artifacts are possible: intent, plan, attempt, ack and final.
AAD binds the policy, operation, selection digest and exact stage. Nonces are
random 96-bit values; tags are 128-bit. Keys are copied into the session and the
internal copy is cleared on close. Keys are never written to the journal.

Writes use owner-only temporary files, file fsync, exclusive hard-link publication,
temporary-file removal and directory fsync. Exact existing values are accepted;
replacement is refused. Writable restart fsyncs existing files and the directory
before network access. Paths must be outside and disjoint from the repository,
owner-private (including the immediate parent), non-symlinked, with no multiply-linked artifact files. Unexpected
files, partial-write leftovers and stale locks stop the operation.

A directory lock rejects overlapping writers. Normal exceptions release it.
An actual process crash can leave a lock or partial-write file. No automatic
lock stealing or deletion is implemented; supervised authenticated recovery is
required. Tests cover ordinary interruption/failure injection, not power-loss
filesystem guarantees. The target must be a local filesystem supporting the
required POSIX operations, not an object store or unreliable shared filesystem.

The first submission is allowed only if no attempt exists and there is no ack or
final receipt. The bridge fsyncs an attempt marker BEFORE calling submit. If
anything fails after that marker, later runs only observe the retained transaction.
They do not endorse again, generate a replacement transaction or automatically
broadcast again. If the process stopped between marker and actual broadcast,
this may block progress until separately approved/manual recovery is developed.
Safety is preferred over pretending an unavailable transaction is absent.

Before the attempt, interruption after a retained plan may safely resume the first
submission. After a committed transaction with acknowledgement or receipt loss,
recovery rechecks the exact original block/VALID proof and both organization
readbacks using the existing adapter. FINAL success requires that fresh proof;
a saved receipt alone cannot produce success. Read-only reconciliation can verify
a committed original attempt without saving a missing receipt or any other state.

The result reports FABRIC_COMMIT_VERIFIED, the exact receipt and a recovery
inventory digest. It explicitly reports both_chains_anchored=false. A final gate
runs before returning. No public anchoring, accepted officer-state mutation,
consensus attestation or independent ledger signature verification is added.

## Limits that must stay on the completion checklist

- AEAD prevents unauthenticated alteration/substitution; it does NOT detect an
  attacker restoring/deleting the entire recovery history with valid old bytes.
  The returned recovery digest is not an independent witness. External retention
  and authenticated recovery-state checks are required before operational use.
- Filesystem permissions do not isolate malicious code running as the same OS
  user or holding encryption keys. Keys and runner/service identities need
  independent provisioning and protection.
- Genuine Fabric SDK compatibility and disposable two-organization peer testing
  are still required. These tests are isolated fixtures, not actual ledger writes.
- Operational backend/Python loader wiring, recovery supervision, authority trust,
  service deployment, public contract/adapter and RPC 1 remain pending.

## Verification

49 new bridge/retention tests plus 152 existing Fabric tests: 201 passed,
zero failures/skips. Includes real temporary filesystem and AES/Ed25519 crypto,
concurrent-session exclusion, encryption tampering, plan/selection drift, approval
expiry and gate failures, fsync failures, directory replacement, lost acknowledgements,
read-only verification and immutable retries. No production key or service created.

Node API references: https://nodejs.org/docs/latest-v24.x/api/fs.html and
https://nodejs.org/docs/latest-v24.x/api/crypto.html. Existing SDK/peer verification
limitations in findings-fabric-gateway-v1.md remain applicable.
