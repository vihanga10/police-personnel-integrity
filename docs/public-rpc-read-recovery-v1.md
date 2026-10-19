# Safe public RPC read recovery v1

## Observed checkpoint

The operator reported successful saved replay at revision `85717bf`, followed by one expired permit and repeated generic failures during full public reconciliation. Attempt `071302e3-5447-4037-b35d-8f9f03852409` reached public officer readback 5,100/6,596 without issuing a permit. A subsequent small read-only sample verified positions 5,100, 5,101, 5,200 and 6,596 through both RPC providers. Another full gate attempt then stopped with the same generic error handler.

These observations do not establish whether the cause was transport, rate limiting, historical-state availability, quota exhaustion or a verification failure. This package improves recovery and makes the next failure actionable. It does not claim that the live problem is already fixed.

## Recovery rules

`rpc-read-recovery.js` supplies the existing RPC endpoint interface. Only an explicit allowlist of idempotent read methods can retry. Each call has at most three attempts, the existing twenty-second request timeout and delays of 500 ms then 1,500 ms. Retries preserve the original method and parameters, including the exact fixed finalized block. Request IDs remain distinct.

Transient transport errors, selected HTTP failures (408, 429, 500, 502, 503, 504), and explicitly recognized JSON-RPC rate/busy errors can retry. Unknown rejection codes/messages, invalid parameters, reverts, explicit historical-state errors, recognized exhausted daily/monthly quotas, malformed/oversized responses and authentication failures stop. No generic catch converts a verification mismatch into a success.

Signed transaction broadcasts are never automatically repeated by this transport. Existing transaction journals, authorization checks and original signed-byte recovery remain responsible for execution. A retry cannot bypass an expired signing authorization.

All original publication-engine checks remain unchanged: both providers, common fixed finalized block, pinned runtime, exact 6,596 commitments, 68 original receipts, original seal inclusion and before/after block stability. There is no latest-state fallback, skipped officer, single-provider acceptance or sample-only success.

## Safe failure output

The guarded public CLI now prints `Public readback diagnostic:` before its existing preserved-state message. Recognized RPC failures expose only a fixed category, known method, safe block tag, attempt count, HTTP status, numeric RPC code and provider index when the endpoint is constructed by the production provider array. Provider URLs, raw response/error text, API keys, signed bytes, officer handles and personnel values are withheld. Unknown local failures expose only `UNCLASSIFIED_SAFE_FAILURE`.

Permanent historical-state loss is not solved by retrying the same block. If reported, we must investigate that provider's state availability or improve the bounded reader while maintaining the same fixed-state verification semantics. If a quota is exhausted, a code retry cannot create provider quota. Never change a permit expiry or delete a journal to get past these failures.

## Install and test

The installer requires a clean `feat/identity-resolution` branch containing `85717bf`, validates exact dependencies and replaced source bytes, rejects unexpected targets and keeps a source-only backup. Installation makes no RPC, wallet, database or blockchain changes.

```bash
unzip -q "$HOME/Downloads/public-rpc-recovery-step.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/public-rpc-recovery-step/install.py" --repository "$PWD" &&
git diff --check &&
cd blockchain/public &&
node --test \
    test/public-rpc-recovery.test.js \
    test/public-finalized-read.test.js \
    test/sepolia-finalized-read.test.js \
    test/sepolia-wallet.test.js \
    test/sepolia-deployment.test.js \
    test/public-recovery.test.js \
    test/public-publisher-evm.test.js
```

Tests use invented fixtures and a compiled local EVM. They cover bounded retries, unchanged block/parameters, exhausted retries, permanent errors, secret redaction, no broadcast retry, all 6,596 fixture commitments with an injected transient failure at position 5,101, existing receipt recovery and hard stops on runtime/block/commitment changes. No operator RPC configuration, private keys or live research evidence is used.

After reviewing passing tests, commit these files:

```bash
cd "$HOME/Developer/police-personnel-integrity"
git add \
    blockchain/public/rpc-read-recovery.js \
    blockchain/public/sepolia-rpc.js \
    blockchain/public/publish-research.js \
    blockchain/public/test/public-rpc-recovery.test.js \
    docs/public-rpc-read-recovery-v1.md
git diff --cached --check &&
git commit -m "Add bounded read-only RPC recovery and safe public diagnostics" &&
git push &&
git status --short --branch
```

## Retry only after source is committed

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m app.identity.check_audit_gate "${public_anchor_args[@]}" \
    --publication-fee-budget-eth 2.30 \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts"
```

RECONCILE is read-only and uses the existing publication journal. If it stops, send the new safe diagnostic and the final aggregate output. Do not repost private configuration or keys. READY is required before any actor-history execution; use the new gate directory and the existing saved-verification receipt `0b71d6e5-48ee-4584-9bbd-0b09964a5650`. The older stopped attempts issue no permit.

The new source commit requires a new audit permit. Saved-result replay does not need to be repeated solely because transport code changed; the encrypted replay receipt remains bound to the original completed run and evidence. Governing-rule assessment, findings persistence/anchoring and final Stage 3 evaluation remain pending.
