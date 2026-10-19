# Proactive public RPC read pacing v1

## Trigger and scope

The operator's run at revision `449ffa908910955f7c229002317de687c6edce11` passed live evidence reconciliation, complete Fabric readback and all 68 public original receipts. Public commitment readback reached 700/6,596 before provider 2 returned HTTP 429 on all three bounded attempts at fixed finalized block `0xb54408`. No permit was issued. This is verified-read progress, not a count of stored commitments or a reported commitment mismatch.

The existing numeric-429 classification is preserved. The new scheduler proactively limits per-provider traffic rather than relying on a continuously busy loop followed by short retries.

## Scheduling

Each production endpoint gets an independent queue. Each logical read reserves 100 milliseconds: a ten-call HTTP batch reserves one second. Requests within a provider dispatch serially; providers can operate concurrently. Other runtime, receipt, block and metadata reads use the same queue. Count weighting is a conservative transport policy, not an account-specific compute-unit measurement or guarantee of service capacity.

An HTTP or numeric JSON-RPC 429 adds a five-second cooldown for that provider, including already queued reads. Retry count remains at most three. Every retry uses the original captured method, calldata and block. No successful subset becomes coverage, no state block is switched and no provider is omitted. Permanent historical-state loss, reverts, authentication failures and exhausted quotas remain hard failures. Signed broadcasts bypass the read queue and are never automatically repeated by this change.

The scheduler uses a monotonic clock. Injected transport fixtures explicitly enable it with virtual time; ordinary prior transport fixtures remain fast. Production callers require no configuration change and cannot disable pacing through network.json. Tests exercise production default wiring, weighted queuing, cooldown, sustained rejection and complete fixed-block readback.

The officer-read component alone now takes about eleven minutes minimum at this rate, plus receipts, block checks, network delays and evidence checks. This does not extend any audit permit. The existing audit-gate runner refreshes live evidence AFTER full public verification before issuing its short-lived permit. A provider must retain the requested finalized state for the entire readback; pacing cannot repair missing historical state.

## Endpoint capacity

[Alchemy throughput documentation](https://www.alchemy.com/docs/reference/throughput) describes account-wide limits and a rolling ten-second window. Its free-tier example uses 300 compute units/second; do not assume this is the operator's actual allowance. [Compute units](https://www.alchemy.com/docs/reference/compute-units) describes method-dependent weighting. Batching reduces HTTP round trips but does not eliminate logical read load.

The limited probe prints a service label without the URL/API key and makes 50 fixed-block writer reads per provider. It validates Sepolia identity and block agreement. It neither measures account quotas nor proves full all-officer readiness. If service is ALCHEMY, inspect account throughput, current usage and quota in the signed-in Alchemy dashboard, and stop other jobs using that account while verifying. Never paste API keys, unlock files or complete private network.json into chat.

## Install and test

```bash
unzip -q "$HOME/Downloads/public-pacing-step.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/public-pacing-step/install.py" --repository "$PWD" &&
git diff --check &&
cd blockchain/public &&
node --test \
    test/public-pacing.test.js \
    test/public-pacing-probe.test.js \
    test/public-rate-limit.test.js \
    test/public-batch-read.test.js \
    test/public-rpc-recovery.test.js \
    test/public-finalized-read.test.js
```

Installer requires the previous batch and numeric-429 fix committed on a clean feat/identity-resolution branch and checks exact source/dependency fingerprints. It changes source only, preserves backups and refuses conflicting targets. Tests use invented fixtures and virtual scheduling; timing is not a measured real-provider benchmark. No CSV, database, wallet, evidence or blockchain changes occur.

## Short live probe before another full gate

After tests pass, run:

```bash
node check-rpc-pacing.js \
    --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1"
```

This reads private network configuration, not keystores or unlock files. It accesses RPC endpoints but submits no transaction. Send only the safe probe output. A failed probe means investigate provider capacity/state before repeating the full gate.

## Commit

```bash
cd "$HOME/Developer/police-personnel-integrity"
git add \
    blockchain/public/rpc-read-pacing.js \
    blockchain/public/rpc-read-recovery.js \
    blockchain/public/check-rpc-pacing.js \
    blockchain/public/test/public-pacing.test.js \
    blockchain/public/test/public-pacing-probe.test.js \
    docs/public-rpc-pacing-v1.md
git diff --cached --check &&
git commit -m "Pace logical RPC reads per provider with bounded throttle cooldown" &&
git push &&
git status --short --branch
```

Once the probe and account capacity checks pass and source is committed, run the existing fresh read-only gate. Use its new READY directory immediately for actor-history processing. A stopped gate issues no permit. Persistent 429 or historical-state loss requires an endpoint with the necessary capacity and retained state; do not repeatedly rerun failing long checks or reset journals. Existing commitments, datasets and short-lived permit rules remain preserved. Stage 3 is still in progress.
