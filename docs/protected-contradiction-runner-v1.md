# Protected observed contradiction runner V1

The trusted backend entry `run_contradiction_query` performs full original anchored snapshot replay using the existing live-readiness loader, requires the configured mutual-TLS witness transport with matching repository/scope/key pins, and calls an internal loaded comparison boundary. `run_loaded_comparison` is for trusted backend code and isolated fixtures only. Neither function is an HTTP endpoint or a CLI; request-provided snapshots, registries, keys, transports and output paths must never be accepted as trusted configuration.

The runner independently replays encrypted signed journal/checkpoint/registry history against a fresh witness tip, checks baseline claims against the original source catalog and destination bindings, and applies `REPORTED_BITEMPORAL_CONTRADICTIONS_V2` to that same history. It requires matching query digests between comparison and observed reconstruction. A second witness/history/source/permit check occurs immediately before exclusive publication. Freshness is established at those checks; later witness advances do not invalidate an earlier historical receipt or establish permanent latestness.

Output is an encrypted immutable comparison receipt with a distinct artifact binding, original publication/context, journal anchor, registry tip, checkpoint pins, observed coverage, reported comparisons, reasons, exclusions, and source/version/receipt provenance. Both primary and backup decryptions must recover the exact result before publication. A private directory outside the repository and protected journal/registry stores is required; exclusive hard-link publication refuses replacement. The console summary contains no officer IDs, evidence values or file paths. Temporary files are cleaned after failure. A directory-fsync failure after publication may leave a complete encrypted artifact with uncertain crash durability: inspect it through a trusted recovery procedure before retrying, never overwrite an existing destination.

There are no observation, checkpoint, registry or witness-advance writes in this runner. Witness head reads are required. This adapter deliberately follows the existing protected query implementation rather than modifying its API; dependency fingerprints pin the inspected gate implementation. Future changes to common gate logic must be reviewed for both runners.

## Meaning and limits

- `authenticated_journal_replay=true` authenticates the selected recorded history at this runner's validation instants. The embedded pure policies retain `receipt_authenticity_claim=false`; typed history alone is not authentication.
- Observed journal coverage only; no invented historical recording dates, source-change completeness claim, independent source custody claim or accepted personnel truth.
- A reported contradiction candidate is evidence disagreement under the policy, not a confirmed false record. Missing applicability, unit identity, source/date semantics and lexical equivalence remain unresolved.
- `accepted_state=null`, `accepted_contradiction=false`, `findings_anchored=false`.
- This receipt is not a findings ledger, authorized correction decision, findings-chain commitment or production research result. Those integrations and independent evaluation remain pending.

## Local validation

New isolated tests cover encrypted publication and recovery, redaction, unchanged stores, correction and withdrawal history, invalid queries, baseline/source mismatch, key/permit changes, uncheckpointed history, rollback, unavailable witness, midflight changes, private paths, publication races, malformed authenticated provenance, query-digest mismatch and actual loopback mutual TLS with a synthetic anchored-loader boundary. Controlled intake fixtures create a reported candidate and preserve earlier comparison digests after correction/withdrawal. Existing query, contradiction, signed-history and transport regression suites are included.

No production witness service, keys, schema, intake hook, research run or blockchain transaction is installed/enabled. RPC 1 remains deferred. Full live anchored replay and research readiness are not established by fixture tests.
