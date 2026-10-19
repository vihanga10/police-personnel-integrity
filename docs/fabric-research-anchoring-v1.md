# Guarded original research commitment anchoring v1

This step deploys a separate `officer-evidence-v1` chaincode on the existing `personnel` channel. The test namespace, its 6,596 random commitments and all original transaction journals remain preserved. Deployment creates lifecycle transactions but submits no officer research commitments. No network recreation, ledger reset, evidence import, human access grants, source classification or audit execution occurs.

The Mac's preceding real checker passed 6,596 test entries, 68 VALID transactions, four controlled interruptions, conflicting-write rejection and unauthorized-write rejection. This permits moving to a guarded research deployment; unit tests here alone do not prove actual research anchoring.

## Source checks

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest -q --tb=short \
    tests/test_research_anchor.py \
    tests/test_research_fabric_deployment.py \
    tests/test_anchor_gate.py
cd ..
node --test \
    blockchain/fabric/client/test/research-anchor.test.js \
    blockchain/fabric/client/test/block-identity.test.js \
    blockchain/fabric/client/test/journal.test.js \
    blockchain/fabric/chaincode/test/evidence.test.js
```

Commit all installed files before deployment. The installer manifest identifies the exact files. This package modifies the repository gateway helper to allow an explicitly selected research namespace while retaining test-only behavior by default. It also targets each read proposal to that gateway's MSP organization; writes still request endorsement by both organizations. Reference APIs: https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/ProposalOptions.html and https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/Proposal.html .

## Separate deployment

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m scripts.deploy_research_fabric \
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1"
```

Deployment requires the recorded setup, successful real test report, preserved captured genesis and unchanged original dependency locks. It refuses an existing research definition or previously started research deployment. It copies source into separate research runtime directories and uses the original pinned lockfiles with npm ci. The original runtime client and test chaincode remain intact.

The sample deployment command sets version 1.0, sequence 1 and AND endorsement by Org1MSP.peer and Org2MSP.peer. Committed definitions are queried from both organizations and checked for matching version, sequence, validation parameter and plugins. Private receipts preserve their exact definitions, source digests, configuration digest and the captured network identity. This records configured deployment evidence; it is not independent evaluation of every lifecycle/block signature. No sequence bump or redeployment is automatically attempted.

If deployment stops, retain the partial deployment, logs and ledger. This script is intentionally not a general-purpose deployment resumer; inspect the reported phase/code locations before repair. Do not remove receipts, reset containers or recreate the network.

## Original publication and a fresh live comparison

Define arguments once from backend. These identify the operator's already verified captured attempts and dedicated keys:

```bash
research_anchor_args=(
    --key-file .secrets/identity-keys.json
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json"
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json"
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025"
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762"
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50"
    --expected-public-sha256 fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity"
    --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1"
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/research-fabric-anchor-attempts"
)

uv run python -m app.identity.anchor_research_fabric "${research_anchor_args[@]}"
```

Default mode is read-only VALIDATE. The runner invokes the complete live gate itself: all eight reconciliation workflows, exact SQL/Mongo fingerprints and final counts. It authenticates the encrypted gate with both encryption-key copies, checks publication SHA, source revision, commitment attempt, exact scope and publication plan. The original generator revision and original officer commitments are preserved.

After recovering the authenticated gate, Python authorizes only this publication/plan/network/mode with a fresh ephemeral 32-byte session key. The key goes to Node through stdin, never an argv argument, environment variable or saved plaintext file. The private authorization artifact holds opaque commitment data and its session MAC; it contains no personnel values, NICs, UUIDs or encryption keys. The Node client verifies the MAC, exact officer/chunk/Merkle shapes and timestamps. This enforces the trusted Python-to-Node handoff; it is not protection against an operator who controls the OS and all signing/encryption keys.

## Submit, then reconcile

Once read-only validation has passed:

```bash
uv run python -m app.identity.anchor_research_fabric "${research_anchor_args[@]}" --execute
```

This command writes the exact existing 6,596 commitments, metadata and seal to Fabric's research namespace. It reruns a fresh live gate automatically before starting. Both endorsement and submission check the gate's ten-minute age from fingerprint-start time. If expired, the runner stops; rerun the same --execute command to obtain a new gate and continue the existing transaction journal. The deadline is never silently extended.

Original endorsed transaction bytes, submission/status handles and VALID receipts are retained in `output-root/journals/<opaque batch handle>`. The journal binds network content identity, channel, chaincode and each operation. No replacement transaction is created for an existing committed chunk. Changed commitments, journal bindings or original receipts cause a stop. Ambiguous network failures retain the original transaction and can require inspection when VALID commit proof cannot be recovered; this adapter does not claim universal fault recovery.

After successful submission:

```bash
uv run python -m app.identity.anchor_research_fabric "${research_anchor_args[@]}" --reconcile
```

RECONCILE also performs a new read-only live evidence comparison. It requires all original receipt files, rechecks each original VALID transaction and reads all 6,596 commitments from both targeted organizations. It cannot endorse or submit missing transactions. Only EXECUTE can continue an incomplete delivery.

One metadata transaction, 66 chunks and one seal produce 68 original application transactions. Lifecycle deployment transactions are separate. The Merkle root supplements all 6,596 individual stored values; it does not replace them. Successful execution means anchoring and integrity verification, not acceptance of historical identity, dates, authority, restrictions or source truth.

Private deployment logs may contain credentials. Share only printed aggregate summaries and code locations. Preserve all keys, journals, captured block and Docker ledger volumes. Public-chain anchoring of the same per-officer values remains a later step. Audit algorithms and findings have not run; classification remains UNASSESSED.
