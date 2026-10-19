# Findings recovery witness V1 — isolated development

The new witnessed entry points require a separate recovery authority. They do not
fall back to the older retention-only runners. The authority records signed,
append-only checkpoints of stage digests, bound to an operation and selection.
It signs a fresh challenge response on every critical check. The backend also
signs its requests; arbitrary callers cannot advance the authority.

## What is implemented

- Explicit administrative provisioning of a new, empty operation. A missing
  registration stops the runner; registration is never automatic in runner code.
- Ed25519 request/response authentication with pinned keys, fresh random challenges,
  bounded timestamps and a bounded transport timeout.
- Immutable checkpoint history with previous-checkpoint digests and compare-and-swap
  advances. An exact uncertain-update retry is idempotent; changes, removals and
  stale conflicting updates are rejected. A final checkpoint is terminal.
- Separate owner-only authority paths, directory identity checks, signed history
  verification and fsync before attestation. Unknown files, gaps, corrupt records,
  wrong modes and hardlinks stop verification. A held write lock is not cleared by
  another caller; interrupted locks require controlled operator recovery.
- AES-GCM local retention unchanged. The authority stores stage digests only, not
  the retained transactions, approvals, receipts, explanations or private keys.
- Witnessed Fabric and public runners verify the authority before source/chain
  checks and before new work. The attempt must be durably stored locally AND
  confirmed by the authority before a transport submission is entered.
- Once an attempt exists, neither runner automatically signs, endorses or submits
  again. Reconciliation continues to re-observe the original chain identity.
- Whole-directory rollback detection before further signing, SDK construction or
  broadcasting. Local ciphertext remains authenticated separately.

## Interrupted updates

The order is local immutable write → authority compare-and-swap → fresh authority
readback → proceed. No chain submission occurs during this confirmation gap.

| Situation | Behaviour |
|---|---|
| Authority equals local stage inventory | Continue only after the existing approval and source/chain checks |
| Local is an exact single-stage extension of authority | Read-only stops; a fresh approved writable run may confirm that one local write |
| Authority advanced but its acknowledgement was lost | Fresh readback discovers the matching state; no second local write or transaction |
| Authority is ahead of local | Stop: local rollback or missing recovery material |
| Equal stage counts but different stage digests | Stop: divergence |
| Local is more than one stage ahead | Stop for controlled recovery; never automatically adopt it |
| Authority unavailable, replayed reply, wrong key or timeout | Stop; do not infer absence or choose an older checkpoint |
| Witnessed attempt exists but transmission never happened | Keep original lineage; no automatic resubmission or replacement |

An unconfirmed write that was never known to the authority cannot be reconstructed
from its digest alone. If that local write is lost, stop and investigate as needed;
this protocol's submission guarantee relies on authority confirmation BEFORE
transmission. It does not claim distributed atomicity or automatic repair of every
storage failure. Existing nonempty histories require a separately reviewed
migration; empty provisioning is not a migration or a historical timestamp.

## Important limits

**The supplied authority service is a local durable fixture, not an independently
hosted service.** Separate directories under the same OS user do not establish an
independent security domain. Restoring or compromising both authority storage and
retention storage can defeat this fixture. Independent hosting, durable protected
service state, authenticated secure transport, key lifecycle and operational trust
configuration are deployment work. No production deployment is included.

The fixture transport never opens a port or selects live URLs. Protocol signatures
are tested, but network transport confidentiality, service certificates and real
host independence are not established. Protected full-replay/permit/history gates
remain fixture boundaries until operational backend wiring is completed. The old
entry points remain available for their existing isolated tests; callers must use
the new witnessed entry points for this protection. Neither API is a public route.

Public execution uses actual Ganache EVM transactions. Public genesis/finality are
simulated and both public views share one engine. This is not Sepolia finality or
independent-provider verification. Returned results explicitly identify a witness
fixture and continue to report no live dual-chain anchoring/readiness.

## Files and maintenance

Four core additions: `recovery-witness.js`, `witnessed-retention.js`,
`witnessed-findings-gateway.js`, `witnessed-public-runner.js`.
The two new runners preserve the existing approval/operation domains and source,
transaction, receipt and readback checks, but await witnessed retention barriers.
Existing runner source is unchanged. The witnessed copies and isolated launcher
are pinned to their tested base modules; future base changes require compatibility
review. The checkpoint clock is an authentication clock only, not an invented
historical system/intake date.

Additional files provide service/runner tests, a dedicated disposable fixture
provisioner, witnessed dual-chain scenarios, a peer entry, a launcher and launcher
packaging checks. Fourteen source/test/document additions in total. Existing
source, CSVs, original anchors, research databases and credential stores remain
unchanged. Installation never starts Docker, deploys contracts or provisions a
research witness. No push or live research run is performed. RPC 1 remains deferred.

## Tests and commands on the Mac

The developer environment has no Docker. Actual witnessed Fabric peer execution
must pass on the Mac before this step is considered peer-validated. The local
Node suites include a fresh Node process reopening durable authority state,
rollback attacks, signature/nonce/role checks, stale CAS, terminal-final rules,
authority tampering, outage/timeout, before/after-commit uncertainty and runner
submission barriers. Fabric runner tests use authenticated-shaped transport
fixtures; public tests include actual EVM execution.

```bash
cd "$HOME/Developer/police-personnel-integrity" &&
node --test \
  blockchain/fabric/client/test/recovery-witness.test.js \
  blockchain/fabric/client/test/witnessed-findings-gateway.test.js \
  blockchain/fabric/client/test/protected-findings-gateway.test.js

cd "$HOME/Developer/police-personnel-integrity/blockchain/public/findings" &&
npm test

cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_isolated_witnessed_findings.py \
  tests/test_isolated_findings_dual_chain.py \
  tests/test_isolated_findings_fabric.py -q
```

Expected totals: 77 selected Fabric/service Node tests, 200 public-package Node
tests (including sixteen witnessed composition scenarios), 24 Python checks;
no skips. Native Ganache bindings may use the tested JavaScript fallback.

With Docker Desktop running:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/run_isolated_witnessed_findings.py --suite witnessed
```

This runs twelve genuine peer checks through the witnessed Fabric runner, an
actual SDK preparation followed by an injected attempt-witness failure (asserting
zero submission), and sixteen witnessed composition scenarios including whole
public/Fabric recovery-directory rollback. Synthetic opaque fixture inputs only;
no research records are selected. The public contract executes on a local EVM.

Expected success:

```
12 witnessed Fabric peer checks, 1 actual SDK witness barrier and 16 witnessed dual-chain scenarios passed. Witness service and public finality remain fixtures; no independent deployment is established.
Owned disposable containers/network/image removed. Shared images preserved.
```

The launcher retains the validated source allowlist, fresh cryptographic material,
private temporary directory, no host ports/socket/named ledger volume, exact
resource ownership labels and scoped cleanup. Both existing lockfiles are reused.
The final peer phase is bounded to thirty minutes; other phases to ten minutes.
Failure retains private diagnostic logs after owned Docker resources are removed.
Do not upload the full temporary directory; it contains disposable private keys.

The installer requires branch `feat/identity-resolution`, ancestor `02c6c54` and
exact prerequisite hashes. `--check` writes nothing. It refuses staged targets,
partial installations, unsafe paths and altered prerequisites. Normal failures
remove only created file inodes; process interruption needs manual inspection.
Package hashes detect accidental changes, not independent publisher authenticity.
