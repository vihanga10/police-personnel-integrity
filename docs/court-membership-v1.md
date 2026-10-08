# Court candidate membership and bundle collection v2

The reviewed 9,538 court source cells contain 25,676 NIC-shaped entries with grammar NIC (text), separated by semicolons. The bounded parser requires the whole cell to match that format before invoking identity lookup. It preserves exact entry substrings, participant positions, duplicate reported participants and parenthesized text. Nested parentheses, blank descriptions, partial/invalid cells and unreviewed separators are not guessed. Source originals remain protected regardless of parser outcome.

The existing inspected_link verifier uses both key copies and the NIC evidence binding to resolve exact candidates. Multiple candidates, unusable identifiers and missing evidence retain null officer_uid and their original verifier status. Matching identity evidence does not establish historical participation, rank, role, authority or descriptor meaning. Reported participant associations are explicitly CANDIDATE_NOT_ACCEPTED. No court is assigned a fabricated sole subject.

This adds new evidence_bundle_v2 and collect_evidence_bundles_v2 modules, leaving v1 recovery and earlier encrypted attempts intact. Version-2 artifacts use a new envelope policy and bundle_version=2. Each court catalog row retains all ordered participant claims; manifests reference shared court rows with the reported_court_participant candidate role. Repeated entries remain in the catalog even when the manifest edge is deduplicated. Station references remain shared catalog evidence.

The new collector repeats full read-only Stage 2 reconciliation, exact source recovery/provenance/receipt coverage and final counts. Export additionally requires all 9,538 cells to parse and the reviewed 25,676 entry count to match. Unresolved identity candidates do not block export: they are preserved and summarized. If the source grammar/count differs, the collector stops before exporting inventories and requires review. Partial/STOPPED attempts are not complete evidence.

All 19 source catalogs and 6,596 officer manifests remain encrypted in 20 artifacts, verified with primary and backup keys. No identifiers, descriptors or UUID edges are printed. Aggregate output includes candidate counts and court rows with/without candidates; do not assume all court identities resolve before seeing the result. Output directories remain private and outside Git. No database modifications, blockchain commitments, audit execution or permission changes occur.

Run tests, commit reviewed code, then from backend:

```bash
uv run python -m app.identity.collect_evidence_bundles_v2 \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --credential-root "$HOME/ResearchKeys/police-personnel-integrity" \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts"
```

Keep concurrent database writers stopped. This is not a distributed snapshot. The foundation still requires version-specific transformed-destination bindings and the distinct protected-commitment protocol before anchoring. It is not accepted historical membership or source truth. The intended anchoring remains 6,596 matching officer commitments on Fabric and the public test network, supplemented by shared/reference commitments.
