# Bounded public publication recovery

## Scope

The research contract, commitment values, Merkle proofs, original transactions, dedicated wallets and existing journals remain unchanged. The supplied real output reports successful finalized first-chunk receipts from both providers, batch count 100, unsealed status and balance 0.025037903666759115 test ETH. This is an operator-supplied checkpoint, not a full officer readback or complete public reconciliation. The current installed source commit was not supplied and is not guessed here.

## Recovery behavior

The guarded Node client enables receipt waits of 45 seconds, with a three-second polling interval, and a finality wait of 60 seconds. The polling helper enforces 0–60-second configured windows and 1–5-second intervals. Polling is read-only. Every RPC retains its existing 20-second request timeout. A started verification round may finish beyond a nominal wait window; no unbounded retry loop is introduced.

A newly prepared transaction is submitted through the existing guarded path and then polled. An existing prepared transaction with missing receipts is polled before the original recovery logic decides whether the same signed bytes may be rebroadcast. That path can use a second bounded window after a permitted rebroadcast. A consumed nonce or an available receipt never authorizes a competing replacement. Failed or mismatching receipts remain hard stops.

Once both receipts pass the complete existing transaction, event and inclusion checks, the original receipt is recorded and the next operation is considered. Budget, balance, gas, nonce, contract identity and authorization checks remain enforced. No provider error or mismatch is ignored. If the wait expires, return PENDING and preserve the exact original journal.

After all 68 operations are mined, a bounded finality poll refreshes and checks every original receipt. The existing all-6,596-officer readback and final inclusion rechecks still precede PASSED. Reconciliation cannot sign, broadcast or prepare missing transactions; validation remains read-only on chain.

## Authorization

A stale gate inside the publication engine returns PENDING / FRESH_AUTHORIZATION_REQUIRED. Original prepared transactions and mined receipts remain untouched. The ten-minute rule is unchanged and still enforced at entry and immediately before each signing or broadcasting operation. The guarded launcher must perform a new live evidence/Fabric review after expiry; the update neither renews authorization from old output nor persists or reuses the ephemeral session key.

Polling can finish reading an already submitted transaction after gate expiry, but no next write can occur. Initial authorization/MAC validation and deployment verification errors still stop the launcher normally. Other verification failures remain errors, not ordinary pending outcomes.

## Funding and use

Install, run local tests, commit the source, then review faucet funding and the explicitly selected cumulative publication budget. The default 0.025 and previously selected 0.04 test-ETH budgets do not cover the complete publication. This update does not increase budget, fee cap or gas cap, alter RPC configuration, or supply test ETH. A fresh guarded EXECUTE run resumes existing journals; it does not create a second research batch.

Local tests cover delayed and one-provider receipts, bounded timeout, exact original recovery, expiry during polling, no writes from reconciliation, minimum gas headroom, funding stops, all 68 fixture transactions and all 6,596 fixture commitments. A compiled local EVM test exercises actual contract calls. These tests do not establish real Sepolia publication completion.
