# Exact stored destination-version binding v1

This read-only step consumes a passed OFFICER_EVIDENCE_BUNDLE_FOUNDATION_V2 attempt and produces an encrypted binding artifact for the exact scoped stored versions. It does not generate officer commitments or write to blockchain.

## Input and reconciliation

All 20 encrypted input artifacts recover with both keys. The source snapshot must match the pinned batch/archive/confirmation, 6,596 unique officers and all 167,865 source rows. Source catalogs reconstruct the officer manifest candidate edges exactly; inconsistent membership is rejected. Input directories/files must be owner-only and cannot traverse symlinks. Existing court claims and earlier bundle artifacts remain unchanged.

A fresh complete Stage 2 reconciliation runs before binding. Within a read-only PostgreSQL repeatable-read transaction, each live staging source is recovered with both keys and compared to its encrypted catalog original columns/values and file/row provenance. The binder reads all columns of every SQL evidence table in the final received-batch count checkpoint, plus registered intake batch/files/raw rows. Selected table counts must match the checkpoint.

## Bound versions

Each SQL binding includes table name, full typed primary key, sorted column names and a fingerprint over every stored column. Type tags distinguish null/text/UUID/integer/boolean/date/timestamp/JSON. Aware timestamps normalize to UTC microseconds; naive timestamps, nonfinite numbers and unknown types fail. Binary columns contribute their exact byte length and SHA-256, covering ciphertext and BSON bytes without persisting a second ciphertext copy. Source assertion IDs, version/chain/supersession fields, key versions, transaction dates, classifications and receipt metadata are therefore included wherever stored in a scoped row.

All three assertion stores, identifier versions, protected profile/family destination versions, profile/family receipts, six delivery preparation/completion groups, officer identities, source systems and intake evidence are covered. Rows with a direct raw_record_id or source_assertion_id are grouped by original source row. Officer metadata without a source row is grouped by officer_uid. Batch/file/source-system metadata is retained in a shared binding section. Empty classification tables remain bound by scoped table count zero. This is an explicit received-batch evidence scope, not a claim to hash every database schema, role, audit log, reference policy file or registration decision table.

Every SQL preparation must contain BSON bytes whose digest matches its stored document_sha256. Every completion must reference that delivery and digest. The binder uses existing restricted technical Mongo readers for all 17 collections. Each Mongo document must have an expected collection/event/raw tuple and exact BSON digest matching the SQL preparation; missing, extra, duplicate and conflicting documents block success. No bootstrap account connects, and no database privileges are changed. Final counts run again before export.

All bindings, source snapshot and table counts are saved in destination-bindings.encrypted.json using the existing v2 authenticated envelope. Context additionally binds EVIDENCE_DESTINATION_BINDING_V1, source snapshot and collector revision. Both key copies must recover the output exactly. Only opaque counts are printed. A PASSED.json marker is written last; incomplete attempts do not establish success. Reruns create a new private attempt outside Git.

## Execution

Commit reviewed source first. From backend:

```bash
uv run python -m app.identity.bind_evidence_destinations \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts"
```

Run without other database writers. There is no distributed SQL/Mongo snapshot; counts alone cannot detect same-count concurrent changes. Stored SQL evidence is read in one snapshot and Mongo documents are checked against its preparations, but operational quiescence remains required. Verification for a later audit must recheck bindings against the anchored versions.

## Following commitment work

SHA-256 row/document fingerprints here are private encrypted manifest components, not officer blockchain commitments. The next protected commitment protocol must combine source catalogs, candidate membership, these destination bindings and the explicit shared/reference scope; use a distinct commitment key purpose and opaque publication identifiers. Each of 6,596 officers will have matching protected commitments on Fabric and the public test network. Shared/reference bindings remain additionally protected. Audit execution and accepted historical identity/authority remain pending.
