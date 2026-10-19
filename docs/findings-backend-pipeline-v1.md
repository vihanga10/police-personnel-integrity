# Protected backend pipeline integration

Base revision: `7b00530`, branch `feat/identity-resolution`.

This package completes the missing coordinator between the existing protected
source/findings gates, Fabric backend service and configured local-public backend
service. It supplies connected acceptance tests; it does not declare their peer
phase passed before it is executed. RPC 1 remains deferred. No original CSV,
database, evidence anchor, production key or deployed service is modified.

## Approval and execution flow

Backend administration constructs an EXECUTE source gate and a RECONCILE source
gate for the same repository revision, witnessed findings object and commitment
selection. Both are exact `FindingsBackendGate` objects. The production entry
accepts no snapshot, source-loader callback, injected SDK, caller-provided receipt
or approval-signing callback. The existing gate still performs full original
snapshot replay and requires a fresh audit permit.

Construct `FindingsBackendPipeline` with the backend-selected gates, exact service
options, public configuration/destination and pinned Ed25519 approver public keys.
The coordinator pins these objects and settings; configuration drift stops the
next phase.

| Method | Purpose and required approval |
| --- | --- |
| `fabric_selection()` | Derive opaque Fabric approval scope from verified source and witnessed findings |
| `run_fabric(approval)` | Use the signed Fabric EXECUTE grant, or RECONCILE grant if the coordinator is read-only |
| `public_selection(fabric_read_approval)` | Freshly reconcile the original VALID Fabric transaction through both organizations; derive public scope |
| `run_public(fabric_read_approval=..., public_approval=..., expected_selection=...)` | Re-derive and match that scope, then invoke the actual configured public service with its separately signed approval |

The Fabric approval uses `PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1`. The public
approval uses `PROTECTED_FINDINGS_PUBLIC_FIXTURE_V1`. Public preparation requires
a new **read-only** Fabric approval after the Fabric transaction exists. The
public selection binds the exact original Fabric receipt, destination and
transaction ID, plus the same findings Merkle root and public-artifact digest.
An approval for one phase cannot approve another phase or a changed selection.
This package contains no production approver private key and issues no production
approvals automatically.

Every public worker boundary keeps the existing full source check and original
Fabric observation. The coordinator rechecks the source and receipt again before
return. Finding explanations and correction/review history remain encrypted in
the existing journals; the source gate binds them to the commitment and witness.
No personal data or plaintext findings are added to either chain payload.

## Interrupted operations and recovery

The existing witnessed encrypted transaction retention is the durable execution
record. The coordinator does not create another competing recovery ledger or
select a new transaction after uncertainty.

After a failure, preserve both recovery directories and the original signed
selection. Reconstruct source gates in `RECONCILE` mode, supply fresh bounded
Fabric/public RECONCILE approvals for the original selections, and invoke
`run_public`. Read-only recovery never creates an intent, signs a replacement,
endorses a new Fabric transaction or resubmits to either chain. Missing receipts
remain `PENDING`; a valid Fabric receipt alone is not dual-chain completion.

The approved public selection is returned by `public_selection` and must be
retained by the backend's controlled approval workflow. It is already bound into
the existing signed approvals and encrypted worker intent/plan. It is not a
plaintext personnel dataset. Fresh reconstruction re-derives its receipt from
Fabric instead of trusting a submitted status or receipt.

## Results

`ISOLATED_PIPELINE_VERIFIED` means the connected local pipeline verified the
original Fabric receipt and the configured local-EVM publication. `PENDING`
remains explicit. The result includes a workflow digest, both approved selections,
the original Fabric receipt and the protected public result. It continues to
report public finality as simulated and provider/witness deployment independence,
both-chain live anchoring and live research readiness as false.

No changes to the existing default runtime or public-network fixture policy are
made. A backend API/UI is a later stage; this is the trusted service entry those
components can call once their authentication/scope controls exist.

## Acceptance evidence

| Check | What it establishes | Status when packaged |
| --- | --- | --- |
| 32 coordinator tests | Real signed approvals and protected findings gate composition; chains and original loader use declared test substitutes | Passed locally |
| 21 launcher checks | Owned isolation, exact source packaging and rejection of incomplete/overstated completion summaries | Passed locally |
| 2 driver process checks | Actual isolated driver rejects invalid approval/expired source before workers | Passed locally |
| 1 runtime harness test | Genuine local HTTPS/mTLS, disk wallet and EVM configuration used by the new acceptance driver | Passed locally |
| Disposable connected peer suite | Actual coordinator, both Python services, both fixed Node workers, genuine Fabric SDK/peers, HTTPS witnesses/RPC and local EVM | Must run on Mac; Docker unavailable in packaging environment |
| Original anchored research snapshot through the connected pipeline | Genuine original-batch replay and current audit permit, without source substitution | Blocked until fresh readiness; RPC 1 deferred |

The disposable peer suite includes nine new connected scenarios:

1. Fabric receipt to public execution through the actual coordinator/services.
2. Fresh-process read-only reconciliation of both original transactions.
3. Invalid public approval blocked without a new public submission.
4. Source denial at public SIGN, retaining intent and no broadcast.
5. Source denial at public SUBMIT, preserving the attempted plan and explicit pending recovery.
6. Source denial at public ACK, recovering the original committed transaction.
7. Lost public acknowledgement, recovered without a duplicate broadcast.
8. Fabric HTTPS witness outage blocking public progression without fallback.
9. Public recovery-directory rollback rejected against its HTTPS witness.

It also reruns the existing 11 backend-bridge scenarios, 12 real Fabric peer checks,
6 HTTPS witness checks and 16 dual-chain scenarios. Its Python test driver
explicitly substitutes the original source gate/replay. Production coordinator,
chain services and workers are loaded unchanged. Protected source/history and
findings cryptography are exercised separately by the coordinator's existing
gate fixtures. This complementary test coverage is not an original-batch replay.

Both HTTPS RPC views share one local EVM; Sepolia genesis and finalized heads are
fixtures. Witness child processes are on one test host. Neither public consensus
finality nor independent deployment is established. The completion receipt must
state these limits or the launcher fails.

## Stage 1 sign-off

The remaining integration code is supplied here. Do not mark stage 1 fully
accepted solely because the installer or local tests pass. First run the focused
checks and disposable connected peer suite on the Mac. Record their exact output.
Original-batch end-to-end replay must remain an explicitly open validation item
until RPC 1, current source readiness and the audit permit are resolved. The
coordinator provides no override for that requirement. Later authentication/UI
work can use this service interface while live execution remains disabled.

## Installation and cleanup

The installer adds twelve source/test/document files only and requires the exact
known prerequisites plus ancestor `7b00530`. `--check` writes nothing. The explicit
Docker launcher creates an owned private run, copies only listed sources, and
starts a disposable network without research credentials, fixed host ports,
existing ledger volumes or Docker-socket mounts. Cleanup deletes only resources
carrying this run's ownership labels. It preserves shared images and retains
private failure logs if a phase fails. No global prune or original-network reset
is performed. Use the package README commands.
