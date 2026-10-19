# Local Fabric deployment and recovery verification v1

This step creates a dedicated local Fabric test network, enrolls an anchoring client with `evidence.anchor=true`, deploys `officer-evidence-test-v1`, and verifies transactions with random test commitments. It does not submit the protected research publication, connect to personnel databases, grant human data access, run audit algorithms, or publish to a public chain.

## Scope and dependencies

The setup uses the official Fabric installer from the `v2.5.16` release, Fabric binaries/images 2.5.16, Fabric CA 1.5.17, Gateway Node SDK 1.8.0 and grpc-js 1.14.4. It records the actual release/sample commits, installer digest, Docker image digests/architecture, runtime npm lockfile digests and channel genesis digest. The official installer can select the samples main branch if no matching samples tag exists; the exact downloaded sample commit is recorded and retained. Direct npm dependencies are pinned; transitive versions are resolved once, locked and recorded during setup. This is a captured local research environment, not an independently verified software supply-chain attestation.

Docker must be running. Setup downloads software, creates CA/orderer/peer containers and ledger volumes, creates the `personnel` channel and deploys test chaincode with endorsement by both Org1MSP and Org2MSP. It requires a clean committed repository. Existing Fabric names, network, volumes or occupied ports cause preflight to stop before setup. The official sample uses fixed names and ports; this command cannot run beside another network using them.

Official references:

- https://hyperledger-fabric.readthedocs.io/en/release-2.5/install.html
- https://hyperledger-fabric.readthedocs.io/en/release-2.5/test_network.html
- https://github.com/hyperledger/fabric/releases/tag/v2.5.16
- https://hyperledger-fabric-ca.readthedocs.io/en/latest/users-guide.html
- https://hyperledger.github.io/fabric-gateway/main/api/node/

The sample network and its bootstrap identities are for local research testing. Production governance, certificate lifecycle, resilient ordering, network exposure and operational deployment remain separate work.

## Install and source checks

From the repository root, install the guarded package and run:

```bash
git diff --check
cd backend
uv run python -m pytest -q --tb=short \
    tests/test_fabric_network_setup.py \
    tests/test_anchor_gate.py
cd ..
node --test \
    blockchain/fabric/client/test/journal.test.js \
    blockchain/fabric/chaincode/test/evidence.test.js
```

These local tests do not prove that Docker deployment or the Gateway SDK works on the Mac. Commit the reviewed source before running network setup:

```bash
git add backend/scripts/setup_fabric_network.py \
    backend/tests/test_fabric_network_setup.py \
    blockchain/fabric/client \
    docs/fabric-network-v1.md
git diff --cached --check &&
git commit -m "Add dedicated Fabric network enrollment and durable recovery checks" &&
git push &&
git status --short --branch
```

## Dedicated network creation

Use a new empty private directory outside Git; keep all existing research keys untouched. From `backend`:

```bash
uv run python -m scripts.setup_fabric_network \
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1"
```

The root is owner-only. CA enrollment material, anchoring and reader private keys, configuration, generated locks, setup receipts and logs remain inside it. Logs may contain enrollment credentials: share only the printed aggregate phase/status output, never full logs, wallet files or configuration. Keep the root and Docker ledger volumes together; credentials alone do not back up the ledger.

If setup stops, preserve the directory, containers and volumes. The setup intentionally refuses a nonempty directory and does not automatically resume, reset or delete an interrupted network. Inspect the last aggregate phase and repair that phase before continuing. Do not run `network.sh down`, Docker prune, remove ledger volumes or create a replacement network under the same recorded identity.

## Real deployment and recovery checks

After setup reports PASSED:

```bash
node "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/runtime/client/check-network.js" \
    "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/gateway-config.json" \
    "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1/recovery-checks"
```

The checker generates and retains a random fixture of 6,596 opaque entries; it accepts no research publication input. It commits batch metadata, 66 ordered chunks and a seal: 68 transactions. It checks successful VALID commit status, original transaction IDs, both peer observations, complete officer readback, a rejected conflicting chunk and a rejected write by the ordinary reader identity.

Four controlled interruptions cover prepared endorsement, submitted transaction, observed VALID status and saved receipt. Every operation is then replayed with its saved original transaction material and reverified. Prepared bytes, commit-status bytes and receipts are saved atomically with owner-only permissions. Channel genesis identity binds the journal to this network.

Rerun the same checker with the same paths to verify recovery and replay. A successful rerun rechecks the existing transactions and entries; it does not generate replacement transactions or delete evidence. If a real transport failure is ambiguous before the commit-status journal is saved, retries retain the original endorsed transaction ID. This can still require investigation if the gateway cannot establish its original VALID commit; the checker stops rather than inventing a receipt. The four controlled cases do not establish recovery from every possible network or process failure.

Test ledger records remain preserved. A fresh journal creates another random test batch; use the existing journal for recovery. Setup itself is not rerunnable against an existing root.

## Completion boundary

Only the Mac's successful setup and real checker output establish local deployment readiness. Container presence or unit tests alone are insufficient. Fabric binary/image compatibility, CA enrollment, endorsement, gateway access and actual commit readback remain unverified until these checks pass.

The actual research anchoring client and separate research chaincode deployment follow. Immediately before any research submission, rerun the live evidence gate and enforce its ten-minute freshness limit. Research writes must use the exact protected publication already verified; record and reconcile original transaction receipts. Public anchoring of the same 6,596 commitments, public-chain confirmations and the audit integrity gate remain pending. Classification stays UNASSESSED.

## Guarded repair of the original version-format stop

The original checker compared `Version: 2.5.16` with binaries that report `Version: v2.5.16` (and similarly for CA). The corrected parser accepts a single optional v/V prefix, verifies an exact version and rejects other versions, suffixes, missing or repeated version declarations.

After installing, testing and committing this fix, resume only the original pre-network stop:

```bash
uv run python -m scripts.setup_fabric_network \
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1" \
    --resume-pre-network
```

Resume requires the original setup revision 6f6899a, the four successful download/version command receipts, matching captured release installer and clean tracked downloaded sources. It rejects any network-start attempt, other setup material, Fabric containers/volumes/network or occupied ports. It preserves prior logs and downloads and re-executes both version commands into separate logs before starting the network. This is a narrow repair path, not general recovery of a partially created ledger. If resume stops after starting, preserve everything and inspect that phase; do not retry by deleting files.
