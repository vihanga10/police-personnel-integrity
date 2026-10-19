# Numeric JSON-RPC 429 read recovery v1

The operator reported HTTP 200 with numeric RPC error code 429 from provider 2, during an `eth_call` at fixed finalized block `0xb5436a`. The prior classifier treated that code as a permanent RPC rejection, so the gate stopped without issuing a permit. This output did not report a commitment mismatch.

This change recognizes numeric 429 as a transient provider throttle for allowed idempotent reads, including a member of a batch and a correctly formed whole-batch `id:null` error. Historical-state loss, invalid requests, authentication rejection, reverts and exhausted daily/monthly quotas still take precedence and stop immediately. String codes and malformed responses are not accepted as numeric throttles.

The existing bound is unchanged: at most three total attempts, with 500 ms and 1,500 ms delays. Every retry preserves captured methods, calldata and the exact finalized block. No partial batch is returned as verified coverage. Signed broadcasts remain single-attempt. Continuous throttling still stops safely; this fix does not establish provider capacity or guarantee a completed live readback. Existing block, receipt, runtime and exact all-officer comparison checks are unchanged.

## Local verification

```bash
unzip -q "$HOME/Downloads/public-rate-limit-fix.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/public-rate-limit-fix/install.py" --repository "$PWD" &&
git diff --check &&
cd blockchain/public &&
node --test \
    test/public-rate-limit.test.js \
    test/public-batch-read.test.js \
    test/public-rpc-recovery.test.js \
    test/public-finalized-read.test.js
```

These fixtures check single reads, batch members and whole-batch throttling, recovery, exhausted retries, parameter preservation, permanent-error precedence, redacted diagnostics and no repeated signed broadcast. Existing complete two-provider fixtures still compare all 6,596 commitments. Local tests do not access real RPCs or execute a research audit.

## Commit after tests pass

```bash
cd "$HOME/Developer/police-personnel-integrity"
git add \
    blockchain/public/rpc-read-recovery.js \
    blockchain/public/rpc-read-batch.js \
    blockchain/public/test/public-rate-limit.test.js \
    docs/public-rpc-429-recovery-v1.md
git diff --cached --check &&
git commit -m "Recover bounded numeric RPC 429 throttling during exact readback" &&
git push &&
git status --short --branch
```

The installer requires the preceding batch-reader files to be committed on a clean `feat/identity-resolution` branch and checks their exact fingerprints. It backs up replaced source and refuses conflicting new files. It changes no CSV, encrypted evidence, wallet, database, transaction or ledger.

After committing, run a fresh read-only audit gate. A stopped gate issues no permit. Send any fixed diagnostic category and final output; do not modify permit expiry or re-upload commitments. Persistent throttling or provider quota exhaustion will require endpoint capacity investigation. Stage 3 and actor-history review remain pending until their real runs pass.
