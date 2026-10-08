# Fabric anchoring foundation and live evidence gate v1

This step prepares the private-ledger contract and freshly compares live databases with the previously committed evidence snapshot. It does not deploy Fabric, enroll a blockchain identity, submit a ledger transaction or run an audit. The operator's original 6,596 commitment values remain unchanged.

## Live gate

`app.identity.check_live_anchor_gate` authenticates both identity key recoveries, dedicated commitment key copies, the passed bundle/binding attempts, and the complete saved commitment mapping/publication payload/summary. It replays using the **original authenticated generator revision**, not the new tool's revision.

It then runs all eight Stage 2 reconciliation workflows and exact received-file coverage, reads a repeatable-read/read-only SQL snapshot, verifies original source recovery and provenance, fingerprints all 35 scoped SQL tables and compares all 17 MongoDB collections with their exact prepared BSON. The complete inventories must match the captured versions. Final count checks follow. Matching counts alone cannot pass this gate.

A mismatch stops the attempt. It does not rewrite, repair, delete or replace a commitment. Investigate the changed evidence; legitimate corrections require a separately preserved version and protocol planning. The received batch remains classification UNASSESSED.

A successful new private attempt contains:

- `live-gate.encrypted.json`: dual-key-authenticated gate, exact publication digest, commitment/binding references, comparison timestamps and publication plan.
- `publication-plan.json`: protected publication handles/values and transaction layout, without source values or officer UUIDs.
- Aggregate `STARTED.json`, `PASSED.json`, and child reconciliation journals.

The freshness limit is ten minutes from the **start of fingerprint collection**, not the end of a long run. Completion time is recorded separately. A future submitter must authenticate the gate and check its age and payload digest before submission; long runs and resumes require another live gate. This foundation has no submission command, so the age check is currently a tested rule for the next adapter.

Pause imports/corrections during live comparison and future anchoring. SQL/Mongo checks do not acquire a distributed lock or establish a simultaneous cross-store snapshot. A freshness interval cannot prevent a writer from changing evidence afterward. The forthcoming submission adapter must compare before submission, recheck on resume, check final evidence versions and record transaction/readback results. Audit runs must use an exact anchored version and independently pass their own integrity gate.

## Immutable contract

The JavaScript contract supports `CreateBatch`, `AppendOfficers`, `SealBatch`, and read-only queries for batch/officer/chunk/seal. There is no update/delete API. It accepts only opaque handles, commitment values, policy/version metadata and ledger transaction IDs. Names, NICs, UUIDs and extra source fields are rejected.

One registered batch fixes the canonical publication SHA-256, shared/coverage/batch commitments and supplementary Merkle root. Its 6,596 ordered officer records are appended in **66 chunks**: 65 of 100 and a final 96. Together with registration and sealing, this plans **68 write transactions**. Each officer gets its own ledger state entry; chunking does not replace individual officer commitments with a root.

The contract validates strict ascending handles, exact sizes and sequential chunks. Reads before inserts provide Fabric MVCC dependencies. Original metadata, chunk and officer records are never rewritten. Exact retries return their original write transaction IDs; conflicting retries fail. A seal is appended only after complete coverage, canonical full-publication SHA-256 and Merkle root verification. An incomplete batch remains visibly unsealed and cannot count as fully anchored.

Write authorization requires `Org1MSP` and certificate attribute `evidence.anchor=true`. Read queries require `Org1MSP` or `Org2MSP`. These are research-network identities, not verified Sri Lanka Police authorities or human personnel-access grants. Standard cryptogen user certificates do not satisfy the anchoring attribute; a dedicated CA-enrolled identity is required in the network step. Fabric endorsement policy should require both organizations. No network, endorsement policy or enrollment has been configured by this installer.

Dependencies are explicitly selected as `fabric-contract-api` and `fabric-shim` 2.5.8. The local rules tests require only Node's built-in test runner. No npm installation occurs here. Before deployment, install and verify the actual SDK dependency tree and retain its generated lockfile; transitive dependencies are not yet locked or integration-tested. The Fabric wrapper is prepared but **not yet verified against a real peer**.

## Receipts and recovery

The Python receipt rule requires a valid committed transaction (validation code integer zero and success true), a block number, exact network/channel/chaincode binding, exact payload digest, original write transaction ID, and matching independently queried `Org1MSP`/`Org2MSP` results. An endorsement/simulation result is insufficient. Receipt data must later be acquired from authenticated Gateway/peer connections. A locally edited JSON file cannot prove a ledger transaction.

Timeout recovery must query an existing immutable batch/chunk/officer/seal and retrieve the original transaction status before retrying. Never delete ledger entries or silently reinitialize a network to repair a missing receipt. Actual Gateway acquisition, durable transaction journals and interruption/recovery integration tests are the next adapter work; only the contract rules and receipt validator are implemented here.

The same 6,596 publication records will later be submitted to the public test network. Public integration remains pending; a private root or batch seal alone does not fulfill the dual-ledger requirement.

## Run sequence

After installation, from repository root:

```bash
git diff --check
cd backend
uv run python -m pytest -q --tb=short \
    tests/test_anchor_gate.py \
    tests/test_protected_commitment.py \
    tests/test_destination_binding.py
cd ..
node --test blockchain/fabric/chaincode/test/evidence.test.js
cd backend
uv run python scripts/check_fabric_prerequisites.py
```

The prerequisite checker invokes only Node version, Docker client/server version, Docker Compose version and Docker info. It reports capability aggregates without usernames/proxy endpoints. It does not pull images, create/remove containers or touch an existing Docker network. Passing prerequisites does not establish Fabric binary/image availability, native ARM support, endorsement readiness or network security.

Then commit the installed source/tests/docs as one reviewed step. From repository root:

```bash
git add \
    backend/app/identity/anchor_gate.py \
    backend/app/identity/check_live_anchor_gate.py \
    backend/scripts/check_fabric_prerequisites.py \
    backend/tests/test_anchor_gate.py \
    blockchain/fabric/chaincode \
    docs/protected-commitment-checkpoint.md \
    docs/fabric-foundation-v1.md
git diff --cached --check &&
git commit -m "Add live evidence anchor gate and immutable Fabric contract foundation" &&
git push &&
git status --short --branch
cd backend
```

Run the read-only live gate on the Mac using the existing private directories:

```bash
uv run python -m app.identity.check_live_anchor_gate \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/live-anchor-gate-attempts"
```

Expected publication SHA-256 remains `fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b`. Send only aggregate test/preflight/live-gate summaries. Keys, signing material and evidence artifacts stay private.

## Network setup next

Use a separately retained Fabric local research/test network, outside the source/data directories, with two peer organizations, a CA-enrolled anchoring identity and a distinct channel/chaincode. Do not run `network.sh down` against an existing network or replace its ledger volumes. Retain network genesis/configuration identity and receipts for later chain verification. Docker on the Mac must be running.

Official references reviewed for this foundation:

- [Fabric installation](https://hyperledger-fabric.readthedocs.io/en/release-2.5/install.html).
- [Fabric local test network](https://hyperledger-fabric.readthedocs.io/en/release-2.5/test_network.html): education/testing configuration, not a production deployment template.
- [Fabric Gateway transaction Status](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/Status.html): committed transaction status.
- Publisher packages: [fabric-contract-api](https://www.npmjs.com/package/fabric-contract-api) and [fabric-shim](https://www.npmjs.com/package/fabric-shim).

Local validation uses synthetic commitment fixtures and mock ledger contexts. It verifies contract logic and Python/JavaScript canonical payload/root agreement, not Fabric endorsement, persistence, MVCC behavior, real certificate authorization or peer commit confirmation. Docker is unavailable in the development workspace; these real-network checks must be completed on the Mac before anchoring the research commitments.
