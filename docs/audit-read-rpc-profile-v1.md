# Complete audit verification with a separate read profile

The original wallet `network.json` is part of the deployed contract and signed
publication-journal identity. Keep its bytes, both wallet copies, original
transactions, encrypted source artifacts, datasets and ledgers unchanged.

This update adds an explicit, owner-only QuickNode/Alchemy read profile. The
profile records the current committed code revision, original configuration
digest, original URL digests, original public payload digest and two actual
read URLs. QuickNode replaces only the transport used for RPC 1's reads;
Alchemy must remain exactly the original RPC 2. The pinned original network
configuration continues to identify every original transaction.

The original full audit gate and its authorization, deployment, receipt,
commitment, finality, common-block and ten-minute freshness checks are unchanged.
The transport validates the profile and original configuration before each
request. Only the guarded `publish-research.js` RECONCILE invocation can activate
it. Writes, altered profiles, changed source revisions, partial environment pins
and redirects are rejected. There is no fallback to PublicNode or a moving state
block. Existing bounded pacing and transient read recovery remain in force.

The fresh public result records the read profile hash and QUICKNODE/ALCHEMY
providers. The unchanged permit seals the digest of that complete result. No
transport evidence is inserted into or substituted for an original transaction
journal. A failed or incomplete readback cannot issue a permit. The normal final
live evidence check still occurs after complete public readback; no expiry is
extended.

## Install, test and commit

Extract `audit-read-rpc-profile-step.zip` into Downloads. Then:

```bash
cd "$HOME/Downloads/audit-read-rpc-profile-step" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"

cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest tests/test_audit_read_rpc_profile.py tests/test_audit_gate.py tests/test_public_anchor_authorization.py -q &&
cd ../blockchain/public &&
npm ci --ignore-scripts &&
node --test test/audit-read-rpc-profile.test.js test/public-rpc-recovery.test.js test/public-batch-read.test.js test/public-rate-limit.test.js test/public-pacing.test.js test/public-publisher.test.js test/public-recovery.test.js test/sepolia-deployment.test.js

bash "$HOME/Downloads/audit-read-rpc-profile-step/commit-local.sh"
```

The installer checks exact reviewed source prerequisites and refuses unexpected,
partial, linked, staged or mismatched source. It updates only three public RPC
source files and adds the listed profile code, tests and runbook. Commit is a
separate explicit local action; it never pushes or connects a dataset.

## Create the private read profile

After the local source commit, copy the QuickNode **Ethereum Sepolia HTTPS** URL
and run:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/prepare_audit_read_rpc.py \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --profile-file "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-v1/profile.json"
```

Paste the URL at the hidden prompt. No URL or token is placed in the command,
shell history or output. The new directory is owner-only and the new profile is
0600 outside Git. Creation is exclusive; an existing profile is never overwritten.
Save the printed SHA256. This operation makes no RPC request and issues no permit.
Only the SHA256 and nonsecret status output may be shared for troubleshooting.

## Run the full gate on the Mac

Keep PostgreSQL, MongoDB, both original Fabric peers and the orderer running.
Replace `PRINTED_PROFILE_SHA256` with the exact preparation output:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m app.identity.check_audit_gate_read_rpc \
  --read-profile "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-v1/profile.json" \
  --expected-read-profile-sha256 PRINTED_PROFILE_SHA256 \
  --key-file "$HOME/Developer/police-personnel-integrity/backend/.secrets/identity-keys.json" \
  --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
  --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
  --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
  --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
  --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
  --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
  --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
  --network-root "$HOME/ResearchKeys/police-personnel-integrity/fabric-local-v1" \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --backup-wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1-backup" \
  --fabric-output-root "$HOME/ResearchEvidence/police-personnel-integrity/research-fabric-anchor-attempts" \
  --publication-fee-budget-eth 2.30 \
  --output-root "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts"
```

2.30 is the previously reviewed cumulative original journal budget. This launcher
can only reconcile: it cannot submit or fund a transaction. Fresh local evidence
receipts and normal process locks are written by the existing gate. Source stores
and blockchain commitments remain unchanged.

Success requires complete original source reconciliation, 68 Fabric transactions
with both organizations, deployment verification, 68 original public receipts,
all 6596 commitments through both independent providers at one common finalized
block, final receipt/block checks and the final fresh live fingerprint.
Only the final READY result establishes current technical audit readiness.

## Scope and recovery

The 10-call candidate probe establishes limited historical access only. Fixture
tests use disposable Git repositories, invented commitments and explicit original
pin substitutions. They do not establish original-dataset or live chain readiness.

If the endpoint fails, retain all source data, original journals and ledgers.
Resolve the reported read issue and rerun this launcher with fresh evidence checks.
It does not resume partially verified public coverage or replay a cached gate.
Any new source commit requires preparation of a new private profile in a new
owner-only directory; profiles never silently advance to another revision.

This update provides technical read verification. Data-use authorization,
classification, current scoped membership, real accounts/disclosures, operational
recording/findings witnesses and frontend activation remain separate prerequisites.
No police personnel information becomes available through this update alone.
