# Priority 4: application research findings publication

This source update adds a live-capable operator path for the Priority 3 generated
application review ledger. It does not claim that a chain transaction has occurred.
The old protected findings pipeline, its two workspaces, its legal-authority gates
and its fixture-only public adapter are unchanged. An application review approval
is not police legal authority. It is not migrated into a protected review journal.

## What is committed

One publication covers one officer's complete saved application prefix: original
comparisons, requests, decisions, append-only correction versions, signed policies
and the exact signed source presentations those entries referenced. Pending and
rejected records remain part of the history; anchoring is not approval of them.
Empty prefixes cannot be published. A later record needs a new publication; an
earlier verified prefix is never advertised as covering the new record.

Only opaque HMAC-derived handles, commitments and a Merkle root go on-chain.
Names, NICs, officer UUIDs, account names, reasons, source rows and search terms do
not. Dedicated random content/publication/recovery keys have primary and backup
copies. Source presentations are archived encrypted atomically with new review
records. An old missing presentation is backfilled only from an exact signed hash
match, never fabricated from a newer copy.

## Installation, with the application stopped

```bash
bash "$HOME/Downloads/application-priority4-findings/run-priority4.sh"
```

The installer checks the Priority 3 ancestor and expected source hashes; it refuses
partial installations, source mismatches and unrelated dirty changes. It tests and
commits source only. It does not create a contract, configure credentials, import
datasets, modify source journals, grant roles or submit any chain transaction.
Original `network.json`, transaction journals and original data anchors are retained.

Start the application with the existing `serve_research_workspace.py` command and
same TLS files. In an officer's Anchoring tab, Application review findings displays
retained observations separately from Protected findings observations. Login scope
and disclosure restrictions apply, including direct URL access. No website account
can supply a receipt, select a chain destination or broadcast a transaction.

## First private setup: no RPC calls or transactions

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/anchor_application_findings.py initialize \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/application-findings-v1"

uv run python scripts/inspect_findings_destinations.py \
  --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1" \
  --findings-root "$HOME/ResearchKeys/police-personnel-integrity/application-findings-v1"
```

Share only the status/policy/file paths. Never upload private JSON credentials,
keys, wallet files, tokenized RPC URLs or encrypted personnel stores. This inventory
does not prove a chaincode is deployed or an identity is authorized.

## Required dedicated destinations (not inferred or provisioned automatically)

Fabric must have the existing committed `blockchain/fabric/findings-chaincode`
installed/approved/committed under the **new** name `findings-anchor-v1` on channel
`personnel`, with both Org1MSP and Org2MSP endorsement. Never recreate the existing
network or overwrite `officer-evidence-v1`. The Org1 enrollment identity must have
the explicit certificate attribute `findings.anchor=true`; its mTLS client
certificate/key must be separate. The existing V2 findings Gateway configuration
requires exact genesis bytes/identity, each organization's chaincode-definition
hash, TLS roots and owner-only certificate/key files. Merely using an admin account
or copying an evidence-anchor configuration is insufficient.

The specific Fabric deployment/enrollment commands depend on the already-running
network's CA and test-network locations. Confirm those paths/configuration first;
do not run network-reset or CA re-enrollment commands blindly. The installed
`findings-gateway.js` authenticates all pins and both organizations on every phase.

For Sepolia create a **separate**, private findings configuration using your existing
QuickNode and Alchemy URLs; no paid upgrade is required by this code:

```bash
uv run python scripts/configure_findings_network.py \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --output "$HOME/ResearchKeys/police-personnel-integrity/application-findings-v1/findings-network.json"
```

Both URLs are entered at hidden prompts. The script prints the file SHA256, not the
URLs. Defaults are a 5-gwei maximum fee, 1-gwei tip, maximum **0.025 Sepolia ETH per
transaction**, and 12 confirmations plus finalized state. These are caps, not price
predictions. A preview must pass before explicit execution. No funds are transferred
by configuration preparation. Review the caps privately before executing.

```bash
cd "$HOME/Developer/police-personnel-integrity/blockchain/public/findings"
node deploy-live.js \
  --network-file "$HOME/ResearchKeys/police-personnel-integrity/application-findings-v1/findings-network.json" \
  --network-sha256 FINDINGS_NETWORK_SHA256 \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --backup-wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1-backup" \
  --journal-root "$HOME/ResearchKeys/police-personnel-integrity/application-findings-v1/deployment" \
  --preview
```

Replace `FINDINGS_NETWORK_SHA256` with the printed hash. After reviewing a successful
preview, the same command with `--execute` deploys the dedicated findings contract.
`--reconcile` is read-only. Deployment retains the original signed transaction;
unknown acknowledgements do not automatically send to the second provider. Never
delete a pending journal or change fee/nonce/config pins to work around a failure.
Deployment may be PENDING until both receipts, finalized state and confirmations
are available. A `PASSED.json` is produced only after exact runtime/writer/constants
and original transaction inclusion agree on both providers.

## Prepare and publish an application prefix

Stop the website. Save at least one comparison through `/reviews` first. Obtain a
**new full original-source READY audit permit** at the installed, committed code
revision using your existing read-RPC-profile runbook. A small RPC probe, archived
READY result or login session cannot replace the 600-second audit permit. Updating
code may require preparing a new pinned read profile. Keep SQL, Mongo and Fabric up.

The CLI requires these common arguments for preparation and publication:

```text
--repository /absolute/repository
--state-root /absolute/application-findings-v1
--app-root /absolute/research-app-v1
--connection-root /absolute/generated-connection-v1
--audit-gate-attempt /absolute/new-READY-audit-attempt
```

Run `uv run python scripts/anchor_application_findings.py prepare` with those common
arguments and `--officer OFFICER_UUID`. It performs all original-source commitment
replay and both-key recovery, validates the application prefix and stores an
encrypted job. It prints a non-personal `publication_id`. Preparation is not anchoring.

Run `execute` with the common arguments and:

```text
--publication PRINTED_PUBLICATION_ID
--fabric-config /absolute/reviewed/findings-gateway.json
--fabric-sha256 EXACT_GATEWAY_FILE_SHA256
--network-config /absolute/application-findings-v1/findings-network.json
--network-sha256 EXACT_NETWORK_FILE_SHA256
--deployment-passed /absolute/application-findings-v1/deployment/PASSED.json
--wallet-root /absolute/sepolia-v1
--backup-wallet-root /absolute/sepolia-v1-backup
```

These values must be real reviewed paths/hashes, not examples or fixture receipts.
The source permit, original disk inputs, code revision, private destination pins
and exact application prefix are rechecked at every worker boundary. Source expiry,
replacement or a new application record stops the operation. The signed Fabric plan
is retained before submission, and both organizations must return VALID inclusion
and exact readback. Only then is Sepolia metadata built from that verified receipt.
The signed Sepolia plan and an attempt marker are retained before broadcast. Both
original receipts, event/inclusion/runtime, fixed finalized block and exact state
readback must pass before `BOTH_CHAINS_VERIFIED` is returned.

## Failure and recovery

Use `reconcile` with the same arguments and original job/configuration. It never
endorses, signs or broadcasts, and cannot create a missing plan. If Fabric committed
but Sepolia was not yet prepared, a new explicit `execute` can progress the missing
phase with a fresh source permit; the retained Fabric attempt prevents resubmission.
An attempted but unobserved transaction requires operator diagnosis. No automated
rebroadcast, nonce replacement, fixture fallback or deletion of recovery locks is
provided. Unknown acknowledgements remain uncertain until readback verifies them.
The owned worker has a deadline, bounded protocol and safe shutdown. Raw provider
diagnostics and credential-bearing SDK stderr are not exposed.

Verified/PENDING observations are append-only encrypted workspace records tied to
the exact entry references and workspace audit chain. The local job observation
files are an inventory aid, not trusted HTTP receipt inputs. HQ access logs retain
the operator attempt/outcome and scope-protected observation reads. Logout clears
the screen, not stored observations or logs. A new finding entry changes the UI to
`NEW_FINDINGS_NOT_ANCHORED` even if an earlier prefix was verified.

## Evidence boundaries

Automated tests use generated fixture records and mocked production transports.
Existing suites also test the real contract on a local EVM; neither proves this
Mac's live deployment. A `BOTH_CHAINS_VERIFIED` result covers a specific application
prefix, not all 6,596 officers and not the separate protected findings journals.
Two distinct RPC hosts and two Fabric organizations are verified, but independently
deployed recovery witnessing is **not established** by this operator path. The UI
reports verification time and does not claim a fresh chain check on page load.
Do not label Priority 4 live-complete in the report until the actual dedicated
destinations, publication receipts, recovery replay and scoped Mac UI are verified.
