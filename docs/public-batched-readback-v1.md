# Bounded public commitment readback v1

## Confirmed blocker

At source revision `37efe515d90c293990b44b88707f44fe3cdae929`, the operator's safe diagnostic reported `HISTORICAL_STATE_UNAVAILABLE` from RPC 1 for `eth_call` at fixed finalized block `0xb5428a`, after progress reached 5,400/6,596. No audit permit was issued and the automatic actor-history runner did not start. The diagnostic identifies provider state unavailability; it does not establish a commitment mismatch, deleted transaction or exact provider retention policy.

This package reduces officer-read round trips with small read-only batches. It does not claim that batching guarantees historical state availability or bypass an unavailable block. Live behavior must be verified on the Mac; a provider with the required historical-state support may still be needed.

## Transport and verification

`endpoint.batch()` accepts 1–10 idempotent read requests per HTTP batch. Writes, notifications, unknown methods and oversized/invalid input are rejected before network access. All request IDs share the existing per-provider counter, remain distinct, and are replaced on a retry while methods and parameters remain captured unchanged.

The JSON-RPC 2.0 batch specification allows unordered responses. The reader correlates every response by ID, reconstructs original request order, and rejects missing, duplicate, unexpected or differently typed IDs, invalid protocol versions, malformed/oversized JSON, simultaneous result/error fields or incomplete arrays. A single top-level error object cannot masquerade as batch coverage. No successful subset is returned on an error.

Recognized transient transport/HTTP/provider errors retain the prior three-attempt limit and bounded backoff. A permanent error anywhere in a batch takes precedence over another member's rate-limit error. Historical-state loss, reverts, malformed data, authorization failure and permanent provider rejection stop; they are never converted into success. Existing single-call and signed-broadcast behavior is preserved.

Reference: [JSON-RPC 2.0 specification, section 6](https://www.jsonrpc.org/specification#batch).

`publication-engine.readAll()` reads ten officer commitments per provider/batch, with at most two officer-read HTTP requests in flight. Every value is independently compared with its exact original expected commitment. The final group contains six entries; no padding or missing officer is accepted. The normal fixture run uses 660 batches per provider, 1,320 total, instead of 13,192 individual officer-read HTTP requests. Individual record count and provider coverage remain 6,596 each. Other receipt/runtime/block checks still make their own bounded read calls.

Both providers read the SAME lower agreed finalized height for the ENTIRE verification. Original sealing inclusion stays pinned. Runtime, writer, metadata/count/seal, finalized block hash, original seal block and finality checks remain unchanged, including checks after every original 100-officer chunk and at the end. All 68 original receipts are still verified before/after full readback by the existing engine. The result policy is unchanged because transport batching does not change what is verified.

There is no latest-state substitution, mid-run block switch, shortened sample, new anchor or single-provider acceptance. Production endpoints expose `batch()`; provider batch rejection stops instead of silently falling back to slow requests. Call-only fixture/adaptor objects remain usable with a bounded individual-call path for compatibility.

## Tests and installation

The installer requires a clean `feat/identity-resolution` branch containing `37efe51`, exact previous source fingerprints and reviewed dependencies. It keeps replaced source backups and refuses unexpected new targets. No CSV, database, wallet, RPC or blockchain operation is performed by installation or local fixture tests.

```bash
unzip -q "$HOME/Downloads/public-batch-read-step.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/public-batch-read-step/install.py" --repository "$PWD" &&
git diff --check &&
cd blockchain/public &&
node --test \
    test/public-batch-read.test.js \
    test/public-rpc-recovery.test.js \
    test/public-finalized-read.test.js \
    test/public-recovery.test.js \
    test/public-publisher.test.js \
    test/public-publisher-evm.test.js
```

Tests use invented fixtures and a compiled local EVM. They include shuffled response arrays, duplicate/missing/unknown IDs, incomplete or malformed batches, blocked writes, permanent errors mixed with transient errors, bounded original-parameter retries, exact all-officer coverage on both providers, the six-entry final group, a transient failure near position 5,100, altered/missing commitments, unchanged runtime/block checks and existing transaction recovery. Fixture timing does not establish actual provider throughput or research accuracy.

Review and commit after tests pass:

```bash
cd "$HOME/Developer/police-personnel-integrity"
git add \
    blockchain/public/rpc-read-batch.js \
    blockchain/public/rpc-read-recovery.js \
    blockchain/public/publication-engine.js \
    blockchain/public/test/public-batch-read.test.js \
    blockchain/public/test/public-rpc-recovery.test.js \
    docs/public-batched-readback-v1.md
git diff --cached --check &&
git commit -m "Batch exact finalized public commitment readback with strict ID coverage" &&
git push &&
git status --short --branch
```

## Real verification

Use the existing read-only audit-gate command only after source is committed. If it stops, send the safe `Public readback diagnostic:` line and final output. Historical-state unavailability still requires provider investigation; do not repeatedly run the same failing long gate, reset journals, re-upload commitments or edit permit expiry.

Once a NEW gate reports READY, start actor-history processing automatically using the established combined gate/actor command, with that newly returned attempt directory. No stopped gate issues a permit. The saved algorithm verification attempt `0b71d6e5-48ee-4584-9bbd-0b09964a5650` remains bound to the unchanged original results and need not be rerun solely for transport changes. The new commit requires a fresh gate/permit before research execution.

Original CSVs, encrypted evidence and all existing commitment/transaction versions remain preserved. Authority/delegation assessment, findings storage/anchoring and final Stage 3 evaluation remain pending.
