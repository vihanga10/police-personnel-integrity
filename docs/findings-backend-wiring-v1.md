# Backend findings gate and witnessed Fabric worker

## Scope

This step adds a trusted backend integration library. It derives a Fabric
selection from existing encrypted findings commitments and connects the Python
verification gate to the committed witnessed Node runner over private child
process pipes. No FastAPI route, background job, intake activation, storage
provisioning, dependency installation, key generation or chain deployment is
performed by the installer. Existing CSVs, databases and original anchors are
unchanged. RPC 1 remains deferred.

Operational backend wiring remains partial: public network transport still
accepts fixture providers only. The Fabric adapter still pins local endpoints.
This package does not broaden those policies or assert live research readiness.

## Backend verification

Construct `FindingsBackendGate` only in trusted backend code with administrator
configuration and a `WitnessedFindingsRegistry` configured for mTLS. No HTTP
request may supply trust maps, directory paths, callbacks, loaded snapshots,
configuration pins, SDK modules or a registry object.

Construction and every protected callback:

1. Check the full current Git revision and a clean working tree.
2. Call the original `load_verified_snapshot`, including complete original
   evidence replay, both-key recovery and the existing unexpired audit permit.
3. Reload original and findings commitment keys; enforce domain separation.
4. Recover the externally pinned encrypted preparation with both recovery keys,
   regenerate commitments, and check the saved public artifact.
5. Check original snapshot context, original publication digest, subject and
   registry authority pins.
6. Select current findings using the configured witness. EXECUTE requires exact
   latest history. RECONCILE permits a previously prepared publication only when
   its entries are an authenticated prefix of current witnessed history in the
   same journal, registry and witness scope.
7. Derive the exact opaque Fabric payload, preserve the initial source/key/scope
   digest, and check the permit and clean revision again.

The gate never substitutes CSV event dates for intake or recording timestamps.
It never creates or extends readiness. A newly committed backend revision needs
a fresh matching original audit permit before operational use.

`gate.selection` returns a copy containing only existing opaque commitment
values, history digest, code revision, approved gateway configuration digest and
dedicated destination. It does not expose officer UID, NIC, name, explanations,
history entries, salt or secret key material.

## Approval and execution

An independently configured backend approver signs the exact selection using
the existing `PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1` policy. The body contains
`policy`, `key_id`, `mode`, canonical millisecond UTC `issued_at` and `expires_at`,
and `selection`. Signature encoding is canonical Ed25519 Base64. Expiry is
bounded to ten minutes and checked before and after every backend callback.
RECONCILE requires its own fresh approval. This library does not issue approvals
or create approver keys.

The internal `findings_backend_service.run_fabric` entry requires a typed gate,
backend-selected approver public keys, an absolute configured Node executable,
the pinned private gateway and witness configurations, a separate owner-private
retention directory and an owner-private raw 32-byte recovery key file. Recovery
keys must differ from evidence encryption/lookup, original/findings commitment
and journal/registry/witness-client signing keys. Key bytes and permissions are
rechecked during callbacks. Retention cannot overlap commitment, journal or
registry storage.

The fixed committed `findings-backend-worker.js` obtains keys from private files,
constructs only the configured mTLS recovery-witness capability, loads the
locally installed pinned SDK packages from `fabric/integration/node_modules`,
and constructs the authenticated Fabric adapter. No request-selected module,
shell command, witness fixture or public provider is accepted by this entry.
SDK packages are installed by a separately authorized setup action using the
existing integration lockfile; calling this service never installs them.

Private pipes carry the opaque selection, signed approval, public approver keys
and configured paths. Secret recovery key bytes and plaintext evidence never
cross these pipes. Every ordered guard request must complete Python verification
before the Node runner can continue. The service uses a bounded overall deadline
(default 300 seconds, maximum 600), bounded frames, strict duplicate-field
handling, a minimal child environment and no shell. Unknown/reordered messages,
child crashes, source changes, approval expiry, witness errors and timeouts stop
the operation. Only the owned worker is terminated; retention is preserved.

The witnessed runner retains the original transaction plan and confirms the
attempt checkpoint before submission. Ambiguity does not trigger an automatic
EXECUTE retry or replacement transaction. Diagnose the failure and obtain a
fresh RECONCILE approval for the exact same selection and recovery directory.
The library adds no scheduler retry policy. An authorized EXECUTE may repair
only the existing runner's exact one-stage local-ahead interruption, under its
fresh approval; it cannot adopt an outdated or divergent local directory.

Returned success means `FABRIC_COMMIT_VERIFIED` with VALID and exact readback
from both organizations. The parent rechecks source and result scope before
returning. `both_chains_anchored`, independent deployment verification, public
transport enablement and live research readiness remain false.

## Isolated verification

Run from `backend`:

```bash
uv run python -m pytest \
  tests/test_findings_backend_gate.py \
  tests/test_findings_backend_service.py -q
```

Run from the repository root:

```bash
node --test \
  blockchain/fabric/client/test/findings-backend-worker.test.js \
  blockchain/fabric/client/test/secure-witnessed-findings-gateway.test.js \
  blockchain/fabric/client/test/recovery-witness-https.test.js
```

The new Python tests use real AEAD, signed permits, commitments and witnessed
history fixtures; the original full-loader call and operational configuration
boundary are explicitly substituted in those tests. Pipe tests use real child
processes with worker doubles. Node tests include real child HTTPS witnesses and
encrypted retention with an SDK adapter double. These checks do not establish
genuine-peer execution of the new Python service or live readiness.

The prior isolated HTTPS/genuine-peer suite remains a regression check of the
existing runners. It does not execute this new Python backend gate/worker bridge.

## Remaining work

- Validate the new Python service, pipe guards and actual SDK worker together on
  disposable peers, including failures after verified attempt retention.
- Implement and test bounded authenticated operational public-provider transport,
  independently configured provider identities and public finality verification.
- Compose both operational stages and their approvals with fresh original Fabric
  re-observation before/after public verification.
- Configure and provision backend trust, witness bindings, separate recovery keys
  and storage under explicit administration. Establish independent witness
  hosting, administration and rollback protection; HTTPS alone does not prove it.
- Add authenticated scoped access and UI, resolve RPC 1, then perform fresh
  integrated readiness and authorized research evaluation.

This package does not enable any of those pending operational actions.
