# Disposable Python/Node findings bridge validation

## Scope

This package exercises the committed Python
`findings_backend_service.run_fabric` and `_exchange`, the committed
`findings-backend-worker.js`, the genuine pinned Fabric Gateway SDK, two actual
disposable Fabric peers and actual HTTPS recovery witnesses together.

The original research-source gate is explicitly substituted with an isolated
selection/denial fixture. No original evidence replay, AlgorithmPermit,
authority configuration or live research readiness is claimed. The real
committed approval-verification function is compiled without modification and
used by the driver. The gate remains unchanged. The service and worker gain an ordered denial response so a controlled source rejection can unwind its owned retention session before bounded shutdown.

The fixture replaces the gate class/configuration helper modules solely in its
own short-lived Python process. It imports the actual service file rather than
reimplementing its orchestration or pipe transport. The actual worker has no
SDK adapter double or injected submit transport. Its SDK, credentials, mTLS
connections, original endorsed transaction, VALID commit and two-organization
readback all belong to the disposable network. The driver labels the output
`SUBSTITUTED_SOURCE_REPLAY_FIXTURE`; the completion receipt requires this limit.

## Controlled denial and actual crashes

The Python service sends only the matching guard ID and `denied`, never an approval or sensitive failure details. It preserves the original source error and gives the worker at most three seconds, within the existing operation deadline, to unwind. An unresponsive worker is terminated. The worker accepts only the exact pending denial ID; malformed or out-of-order replies fail closed.

Offline subprocess tests exercise the actual transport, actual worker pipe and actual encrypted retention session. They verify denial/EOF cleanup and preservation of encrypted intent. A forced process crash keeps its stale lock, and a fresh retention object refuses it. No lock is automatically deleted and no transaction is automatically retried. Peer scenarios use controlled denial to test recovery; they do not claim hard-kill recovery is automatically safe.

Nine files are added and three exact pinned files are updated: the service, worker and existing service test. The installer backs up those three sources beside itself. `--check` changes no source files.

## Eleven new scenarios

1. Real Python service and pipe guard compose with the actual worker/SDK for a
   retained original transaction, HTTPS checkpoint and VALID two-peer receipt.
2. Fresh Python and Node processes reconcile the same transaction with unchanged
   recovery bytes and unchanged ledger heads.
3. Invalid signed approval stops before retention or ledger writes.
4. Fixture source denial at ENTRY stops before creating a worker transaction.
5. Denial before attempt retention leaves the actual endorsed plan; fresh
   EXECUTE approval resumes that same original plan.
6. Source denial after the witness-confirmed attempt prevents broadcast. A
   fresh read-only recovery cannot broadcast or replace the original identity.
7. Denial at FINAL after submission, acknowledgement and actual commit preserves
   the original ID and supports read-only reconciliation without writing final.
8. Denial at ACK after actual submission preserves an uncertain original attempt;
   read-only observation waits for the original VALID commit, then subsequent
   reconciliation neither broadcasts nor writes.
9. Whole local recovery rollback is rejected against the real HTTPS witness tip.
10. HTTPS witness outage has no fallback; restart preserves the original ID.
11. RECONCILE without original intent cannot create an endorsement or publication.

Ledger head comparisons are taken only after the relevant original commit has
been observed. A submission acknowledgement is not treated as commit finality.

The prior twelve peer checks, six HTTPS checks (including two real SDK witness
barriers) and sixteen local-EVM dual-chain scenarios remain in this disposable
suite. Public-chain finality and provider independence remain simulated.

## Isolation

The launcher retains the original exact isolation helpers: unique labels,
network and resource names; no host ports or Docker socket mounted into the
runner; no existing peer, credential, database, wallet, key or research data
selected. Source copying uses an explicit allowlist. It adds only the two
committed backend Python source files to the build context, with no backend
configuration, `.env`, research CSV, key material or installed dependency tree.

The Node-based test image also installs Debian Python and its cryptography
package for the test driver. No dependency is installed into your research
environment by the installer. Locked SDK and EVM dependencies are installed
inside the disposable image. Test credentials are generated only after explicit
launcher execution; no production keys are created.

The driver requires the owned disposable-run marker, its explicit fixture
policy, fixed `/work/fabric` source exclusion and request/material paths within
the owned test root. Denial controls exist in test-driver input only. No
production API, route, service or hook is enabled.

Success requires all three completion receipts, including eleven unique backend
scenario names, actual Python/worker/SDK/peer flags, real HTTPS transport,
simulated full-source replay, zero research records and false live readiness.
Owned containers, network and image are removed; shared images are preserved.
Failure retains private diagnostics and generated test credentials. Share only
the requested log, never the entire retained directory.

## Commands

From backend, run the offline launcher/driver checks:

```bash
uv run python -m pytest \
  tests/test_findings_backend_gate.py \
  tests/test_findings_backend_service.py \
  tests/test_findings_backend_shutdown.py \
  tests/test_isolated_backend_findings_peers.py \
  tests/test_isolated_https_witnessed_findings.py \
  tests/test_isolated_witnessed_findings.py \
  tests/test_isolated_findings_dual_chain.py \
  tests/test_isolated_findings_fabric.py -q
```

From the repository root, run the Node regression and shutdown checks:

```bash
node --test \
  blockchain/fabric/client/test/findings-backend-worker.test.js \
  blockchain/fabric/client/test/findings-backend-shutdown.test.js \
  blockchain/fabric/client/test/secure-witnessed-findings-gateway.test.js \
  blockchain/fabric/client/test/recovery-witness-https.test.js
```

Then, from backend with Docker running, explicitly create the disposable network:

```bash
uv run python scripts/run_isolated_backend_findings_peers.py --suite backend-peers
```

Expected successful summary: eleven backend bridge scenarios, twelve actual
Fabric peer checks, six HTTPS witness checks and sixteen dual-chain scenarios.
The launcher exits nonzero if testing or owned-resource cleanup fails.

## Remaining limits

No Docker executable is available in the development environment, so genuine
execution of this new suite must be confirmed on your Mac. Offline checks are
not evidence that these peer scenarios passed. Fresh actual research replay and
readiness, operational public-provider transport and finality, independent
witness deployment and authorization/configuration remain pending. RPC 1 stays
deferred. Existing CSVs, databases and original anchors remain unchanged.
