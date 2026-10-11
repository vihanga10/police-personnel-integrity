# Public findings backend bridge foundation

## Scope

This additions-only step supplies a typed Python source/Fabric verification gate,
a private-pipe public service, an isolated Node worker library and regression
tests. It uses the existing witnessed public runner and encrypted retention.

This does **not** complete operational public-chain transport. The fixed pipe
worker's default transport factory deliberately throws before credential reads,
signing or any public RPC. It cannot load a request-specified module, endpoint,
wallet or fixture. A configured factory and full Python/Node/Fabric/public
end-to-end validation remain pending. RPC 1 is deferred.

Tests explicitly supply trusted isolated capabilities to the Node library entry.
They use a real local EVM and real HTTPS witness; Sepolia identity, consensus
finality, provider independence and source replay are fixtures. No public test
result establishes actual public-chain anchoring or independent deployment.

## Backend checks

`FabricReceiptVerifier` accepts only an existing typed `FindingsBackendGate` in
RECONCILE mode and exact backend-configured service options. Every verification
calls the original read-only Fabric service, which replays the source and
verifies the retained original VALID transaction and both organization readbacks.
The verifier pins its original receipt, gate identity and configuration. It
accepts no caller-supplied observer, transaction plan or receipt hint.

`FindingsPublicBackendGate` also requires a typed source gate. EXECUTE uses the
source gate's latest witnessed-history policy; RECONCILE uses its authenticated
prefix policy. At every public action it checks the source before and after re-observing
Fabric, so a source change during that observation also blocks approval. The source and Fabric gates must agree on their complete selection,
repository and committed revision. Public metadata is derived from that
verified receipt: publication ID, public artifact hash, Merkle root, Fabric
destination digest, original transaction ID and exact receipt digest. Original
evidence anchors, dates and data are not edited.

Public approvals are Ed25519 signed with the existing public fixture policy,
exact selection/mode and a maximum ten-minute lifetime. Fabric approval and
service options remain independently configured and bounded. Expired approvals
stop execution; the bridge does not renew them automatically or waive readiness.

The public service reuses the bounded ordered private-pipe protocol, including
explicit source denial and controlled child cleanup. Its worker path is fixed
relative to the repository. It cannot select an arbitrary process or SDK.
Public recovery storage must be separate from findings, commitment and Fabric
recovery stores. The 32-byte key must differ from evidence/signing/commitment
keys and the Fabric recovery key. The key never enters the pipe frame.

## Public runtime boundary

Network configuration remains `FINDINGS_PUBLIC_NETWORK_FIXTURE_V1`: two distinct
HTTPS `.invalid` endpoints, bounded fees and 12–128 confirmation policy. Both
Python and Node reject live configurations. Node pins canonical private network
file bytes to the approved configuration hash. The HTTPS recovery witness is
constructed from private files and authenticated pins; no fixture witness or
insecure fallback is accepted by the worker.

The default runtime factory is unprovisioned. Library tests pass fixture RPC and
wallet capabilities explicitly after source/approval checks. Those capabilities
cannot be supplied in JSON pipe messages. An actual provisioned live transport
will require a separate reviewed policy and factory; simply changing an endpoint
or a result flag cannot enable it.

The existing runner retains encrypted intent, signed plan, attempt,
acknowledgement and final receipt. A witnessed attempt must be confirmed before
broadcast. Source rejection and uncertain submissions preserve the original
transaction identity; RECONCILE cannot sign, replace or broadcast a transaction.
Pending receipt/finality evidence stays PENDING. Rollback protection and stale
lock refusal remain intact. No automatic retry or lock removal is introduced.

The Python service rejects fabricated live/dual-chain/independence claims and
checks exact result scope, transaction hash and verification fields. Successful
isolated results are labeled `public_finality_simulated=True`,
`provider_independence_verified=False`, `public_transport_enabled=False` and
`live_research_ready=False`.

## Tests and commands

From backend:

```bash
uv run python -m pytest \
  tests/test_findings_public_backend_gate.py \
  tests/test_findings_public_backend_service.py \
  tests/test_findings_backend_gate.py \
  tests/test_findings_backend_service.py \
  tests/test_findings_backend_shutdown.py -q
```

From `blockchain/public/findings`:

```bash
node --test --test-concurrency=1 \
  test/findings-public-backend-worker.test.js \
  test/public-adapter.test.js \
  test/witnessed-public-runner.test.js \
  test/secure-witnessed-public-runner.test.js
```

The source gate tests reuse the declared full-loader/witness fixtures and
substitute Fabric service observations. They verify fresh rechecking, receipt
binding, source changes, configuration drift, signed scope and separate recovery
keys/stores. The Node tests exercise the actual worker library against a local
EVM and HTTPS witness. They check attempt barriers, original transaction
recovery, source denial, file drift, witness outage, default-factory refusal and
actual private-pipe denial/EOF/order handling. These are complementary isolated
tests, not the complete operational Python-to-public execution pipeline.

Installer `--check` is read-only and requires branch `feat/identity-resolution`,
commit `5ac3eb0` as an ancestor and exact prerequisite hashes. Installation only
adds the eight reviewed source/test/document files. It starts no services,
installs no dependencies, provisions no keys and submits no transactions.

## Next work

Configured public RPC/wallet transport and its independently pinned trust policy,
full bridge integration with disposable Fabric peers/local EVM, then fresh live
provider/finality readiness after RPC 1 resolution. Research authorization,
independent witness deployment, authenticated UI/access, integrated research
execution and academic evaluation remain separate readiness/work items.
