# Protected officer commitments — captured evidence v1

This step generates the initial commitment version for all 6,596 officers. It consumes the passed court-aware bundle attempt and its passed destination-binding attempt. It never opens a database connection, submits a transaction, grants access, runs an audit, or changes evidence. Classification remains UNASSESSED.

## Covered evidence

Each source-row HMAC covers the complete recovered source catalog entry: ordered original columns and values, source provenance, assertion and delivery identifiers, uncertainty, candidate officer/role links, reported court participants where present, and the exact stored destination fingerprints. Membership is candidate evidence, not an accepted historical identity or role.

Each officer HMAC covers the version-2 bundle manifest, the commitments of all its referenced source rows, candidate roles, officer-level destination fingerprints, a shared-context commitment, and the protocol context. A shared operation contributes to every reported candidate participant's bundle. This does not duplicate or accept the operation's source evidence.

The shared-context HMAC covers shared SQL records and all unassigned source-row commitments, including the 1,214 station reference rows. The all-source coverage HMAC covers the complete 167,865-row catalog. The batch HMAC covers all officer publication records, shared-context and coverage HMACs. Its supplementary Merkle tree contains 6,596 officer leaves and one batch leaf.

The captured SQL scope is exactly 35 tables / 794,200 records; MongoDB scope is 17 collections / 154,673 documents. Tables outside the destination binder's explicit scope, application roles, policies, future audit results and future source versions are not silently included. This is a captured snapshot, not a simultaneous distributed-database snapshot.

## Protocol

Policy: `OFFICER_PROTECTED_COMMITMENT_V1`; initial commitment version: integer `1`. Bundle version `2` and commitment version `1` are different version domains.

Two independent random 32-byte keys are required: content commitment and publication handle. They must differ from every configured identity encryption/lookup key. Keys stay off-chain and outside Git, with separate owner-only backup files. They must be retained to verify historical commitments. A new key version requires a future explicit protocol change; this implementation never rotates or overwrites keys.

Content commitments use HMAC-SHA256 over UTF-8 canonical JSON of `[policy, key_version, domain, payload]`. Publication handles use the separate publication key and the same framing. JSON uses sorted object keys, compact separators, preserved Unicode text and no non-finite numbers. No text normalization or trimming occurs. Candidate edge sets and destination inventories are deterministically ordered; original column/value order and reported participant order remain significant.

Domains are `SOURCE_ROW`, `SHARED_CONTEXT`, `OFFICER_BUNDLE`, `ALL_SOURCE_COVERAGE`, `BATCH`, `OFFICER_PUBLICATION`, and `BATCH_PUBLICATION`. Context covers the original snapshot, policies, binding revision/capture time and source attempt, generator Git revision, destination scope, commitment and key versions. The same captured inputs, keys and generator revision produce identical publication payloads; randomized artifact encryption is outside the commitment preimage. A fresh capture has a new context and is a different version.

Publication handles expose neither NICs nor officer UUIDs. They remain stable for this snapshot; future snapshots use a different handle context. HMAC is a protected keyed commitment, not a public plain hash of low-entropy personal data. Checking contents requires the private keys and retained artifacts. A blockchain proves recording/integrity properties; it does not prove source truth, authority or completeness outside the declared scope.

Merkle leaves are `SHA256(0x00 || canonical(leaf))`, with ordered officer records sorted by publication handle followed by the typed batch leaf. Parents are `SHA256(0x01 || left || right)`; an odd last node duplicates itself. The root supplements individual records: the agreed future Fabric/public-network integration must record the **same 6,596 individual commitment values** on both ledgers. A root alone does not fulfill that requirement.

## Artifacts

Every generation creates a new private attempt directory. No output is overwritten:

- `commitments.encrypted.json`: identity-key-encrypted officer/handle mapping, per-row commitment index, context and input-attempt references. Both identity key copies must recover it.
- `public-commitments.json`: publication-only payload with opaque handles and commitments. No NICs, UUIDs, source text, source file names, private keys or per-officer evidence counts. Keep it outside Git pending anchoring review; this step does not publish it.
- `STARTED.json` and `PASSED.json`: aggregate status and canonical public-payload SHA-256. A failed attempt is not publication-ready.

Retain both input attempts as well as keys and this output. The output mapping does not replace the original encrypted source/binding artifacts. Encryption protects their contents; HMACs bind those contents and associations. A change to one private promotion changes its officer's commitment; a shared operation change affects all its candidate participants; a shared reference change affects the shared context and officer commitments.

## Run after focused tests and committing source

From repository root, commit the four installed files, then return to `backend`:

```bash
git add backend/app/identity/protected_commitment.py \
    backend/app/identity/generate_protected_commitments.py \
    backend/tests/test_protected_commitment.py \
    docs/protected-commitment-v1.md
git diff --cached --check &&
git commit -m "Add protected officer commitments with shared evidence coverage" &&
git push &&
git status --short --branch
cd backend
```

Create dedicated keys once. This creates two new private files; it refuses existing paths. If a backup save fails, preserve the successfully written primary and repair the backup separately; do not generate replacement keys over an existing primary.

```bash
uv run python -m app.identity.generate_protected_commitments \
    --initialize-keys \
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json"
```

Use the verified operator-supplied input attempts below. Keep their original directories unchanged.

```bash
commitment_args=(
    --key-file .secrets/identity-keys.json
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json"
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json"
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025"
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762"
)
uv run python -m app.identity.generate_protected_commitments "${commitment_args[@]}" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts"
```

Send only the aggregate final summary. Expected: 6,596 officers, 167,865 source rows, 794,200 SQL records and 154,673 Mongo documents. Do not share key files, encrypted/private mappings or source evidence.

Before changing the generator's Git revision, replay the saved result with the **actual newly printed attempt path**:

```bash
uv run python -m app.identity.generate_protected_commitments "${commitment_args[@]}" \
    --verify-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ACTUAL_ATTEMPT_UUID"
```

Replace `ACTUAL_ATTEMPT_UUID`; do not run the placeholder literally. Verification authenticates both encrypted key recoveries and compares the full regenerated private mapping, public payload and summary. It detects changed, missing or inconsistent saved artifacts. It does not establish that live databases still match the captured fingerprints. A later anchoring/audit gate must perform live comparison and verify ledger receipts before auditing this version.

## Validation

Focused tests cover original-content/provenance changes, candidate membership changes, altered SQL/Mongo fingerprints, shared and unassigned evidence, missing/extra/duplicate inventory entries, separate keys, private filesystem rules, encryption recovery/tampering, deterministic replay, publication privacy, Merkle framing and a synthetic 6,596-officer batch. Real artifacts must still be generated and replay-verified on the operator's Mac. No production keys or personnel values are used locally.
