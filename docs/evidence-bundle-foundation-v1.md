# Officer evidence-bundle foundation v1

Policy: OFFICER_EVIDENCE_BUNDLE_FOUNDATION_V1. Initial universe: all 6,596 officers from the completed BATCH-RAW-001 checkpoint. This is a read-only protected inventory foundation; no blockchain commitment or audit algorithm is implemented here.

## Membership and preservation

Every received source row occurs once in a source catalog. Catalogs preserve ordered columns and exact source strings, registered file and row provenance, imported assertion provenance and completed receipt references. All 19 files and 167,865 rows must be covered. Missing, repeated or incomplete receipts block success.

Each officer has a version-1 manifest containing references to catalog rows with explicit candidate roles. The existing dual-key NIC evidence verifier supplies candidates. Single NIC columns are inspected without historical identity acceptance. The reviewed flat-list parser inspects operation participants. Each officer must have exactly one personal-profile subject candidate. A shared operation may appear in several manifests while remaining one catalog record. Signing actors, subjects and participants retain distinct reported field roles; an actor association is not authority verification.

Court participate_officers_details has no accepted parser in this version. All such source cells remain encrypted in the shared catalog. No regex extraction or guessed participant identity is performed. Rows without any usable explicit candidate remain unassigned, fully covered by the source catalogs. Station reference rows remain catalog evidence and are not assigned to officers by present-day station codes. Future reviewed linkage changes create new manifest versions.

This is source-row coverage and conservative candidate membership, not a claim that complete historical membership has been resolved. Officer manifests do not yet cover all indirect court participation or accepted station identity. Bundle inventories reference original evidence, not reconstructed current state. Classification, dates, authority, effects and linkage remain unassessed.

## Collection and protection

The command first runs the full existing read-only Stage 2 review, including all eight encrypted PostgreSQL/MongoDB reconciliations. There is no skip, database-write or blockchain-write flag. It then recovers staging rows with both key copies inside a PostgreSQL repeatable-read/read-only transaction, validates provenance and exact receipt coverage and builds candidate edges. Final SQL/Mongo counts are checked again.

Source catalogs and the combined 6,596-officer manifest index are saved as 20 AES-GCM encrypted JSON envelopes using the existing reviewed IdentityCrypto facility. Both key copies must recover every generated artifact exactly before publication. Existing encryption keys are reused only for this encrypted foundation export; the forthcoming commitment protocol will require a distinct commitment-key purpose. Encryption context binds the policy, collection attempt metadata and artifact identity. Random nonces mean ciphertext differs between attempts; it is not a deterministic officer commitment.

The owner-only output directory must be outside Git and cannot traverse symlinks. Files are published exclusively and privately through save_receipt. Plaintext summary journals contain counts and code revision, not source values, officer UUIDs or candidate edges. The encrypted payload contains those sensitive references. A PASSED.json marker is written only after all 20 artifacts are complete. Interrupted/failed directories must not be treated as passed inventories. Retry creates a new attempt, preserving earlier output.

No distributed PostgreSQL/MongoDB snapshot is available. Run without concurrent writers. The previous full reconciliation and final count checks do not prove absence of same-count concurrent changes. Transformed destination ciphertext digests and version-specific destination manifests still need to be incorporated in the upcoming commitment protocol. This output alone is not ready for blockchain anchoring.

## Run after committing reviewed source

From backend:

```bash
uv run python -m app.identity.collect_evidence_bundles \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts"
```

The fresh full reconciliation can take time; each child reports progress. Save the final aggregate result, not source catalog plaintext. The collector stops on discrepancies and grants no new permissions or authenticated human disclosure.

## Blockchain contract for the next implementation

The agreed target is 6,596 protected per-officer commitments on Hyperledger Fabric and the same 6,596 individual commitments on the public test network proposed as Ethereum Sepolia. A Merkle root may supplement these individual entries, not replace them. Shared, unresolved and station-reference catalog commitments additionally protect evidence outside current officer associations. No plaintext identifiers, cells or keys go on either chain.

Before anchoring, specify deterministic commitment serialization, complete destination-version binding, opaque publication identifiers, distinct commitment keys, shared-catalog membership and privacy protections. Recovered content, provenance and uncertainty must all affect commitments. Version 1 is not silently overwritten: corrections append a new version. Audit execution must verify the exact anchored version; findings append separately. This foundation does not establish test-network permanence or production blockchain readiness.
