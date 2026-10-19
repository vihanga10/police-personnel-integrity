# Anchored research algorithms v1

## Scope and current checkpoint

The operator committed the temporal authority/delegation foundation as `ba3d2f3` after 221 focused tests passed. This step adds the reported action adapter, temporal contradiction detector, authenticated snapshot loader and combined encrypted runner. Internal membership uses `officer_uid`. The lifetime meaning of `police_id` remains unresolved and is not an identity shortcut.

The existing reported reconstruction is reused, including v2 police-number comparison within reported number types. Existing archived results and the initial commitments are unchanged. Algorithm versions may change later; new runs record the current code revision and policies instead of overwriting old results.

| Component | Implemented behavior | Remaining evidence limitation |
| --- | --- | --- |
| Historical reconstruction | Reported rank, posting, number, status and restrictions at a selected date | Snapshots, missing dates, cancellations, station identity and source completeness remain explicit uncertainty |
| Temporal authority/delegation | Pure `evaluate` supports VALID, INVALID and CANNOT_VERIFY using supplied assessed facts, rules and delegation paths | Research governing instruments and accepted action-date actor states have not been supplied/assessed |
| Reported action adapter | Enumerates supported action fields, retains actor candidates, dates, full source references and destination digests | Candidates, signatures, titles and quoted delegation references do not establish authority |
| Temporal contradictions | Compares aligned claims within the same dimension and reported time scope | Produces candidates or unresolved comparisons, never accepted misconduct/source-truth findings |
| Combined runner | Authenticates the exact anchored snapshot and fresh permit, runs all officers or a private NIC-selected officer, saves encrypted outputs | Real execution and coverage/performance need verification on the operator's Mac |

This is backend algorithm implementation, not completion of all Stage 3 work. Assessed governing-rule intake and action-specific authority evaluation integration, append-only findings/corrections storage, findings anchoring, authenticated UI and final research evaluation remain pending. The source adapter intentionally returns CANNOT_VERIFY until identity, action-date semantics, actor state, scope and governing evidence are assessed. It does not assign legal powers from a rank/title or fabricate delegation evidence.

## Snapshot and authorization

Before interpreting claims, the loader verifies primary/backup identity-key recovery, dedicated commitment-key separation, the encrypted bundle and destination bindings, and all original officer/shared commitments using their original generator revision. It requires the exact pinned publication and a fresh encrypted dual-chain audit permit bound to the current source revision and chosen attempts. A matching aggregate count alone cannot pass this check.

`AlgorithmPermit` validates the original Merkle plan once on entry. Every work/output boundary then authenticates both copies of the unchanged permit and hashes the entire publication, checking its unchanged digest and original expiry. This avoids rebuilding the complete Merkle tree for each officer. Full gate validation runs again before completion. It does not extend the ten-minute deadline or replace fresh live evidence/chain checks. If loading or processing consumes the permit window, the run stops and a new permit is required.

No newly collected evidence is added to the anchored snapshot. Source changes require the existing version/commitment workflow before a new research run. Private NIC selection uses the existing SQL verifier and is a candidate selection, not historical identity acceptance. No NIC is accepted through command-line arguments.

## Reported actions covered

| File | Reported action fields reviewed |
| --- | --- |
| promotion_history.csv | Promotion authority and signed date |
| transfer_history.csv | Transfer authority and signed date |
| officer_restrictions.csv | Restriction recorder/removal recorder and recording dates |
| restriction_overrides.csv | Override authority and date |
| operations.csv | Reported commanding officer and operation date |
| officer_family_details.csv | Recording officer and certification signed date |
| public_complaints.csv | Investigating officer/start date and reported NPC decision date |
| officer_duty_periods.csv | Recording authority/date of entry |
| officer_firearms_expertise.csv | Half-year supervisors/practice dates and undated annual supervisor |
| good_conduct_register.csv | Recommendation, sanction and approval fields |
| bad_conduct_register.csv | Punishment and appeal authority/date fields |

These are reported associations, not accepted decisions/signatures or legal action-date definitions. Where a route has no day-level date, the date remains missing. An absent optional slot is not fabricated into a missing action. A dated future action is excluded by the query cutoff, while its source remains preserved. An undated action remains review evidence.

The adapter never treats the subject NIC as the signing actor. It uses only the corresponding actor-field candidate edge. Unresolved and ambiguous actors are retained, including actions without an officer assignment in all-officer mode. Free-text names/titles are not guessed into UUIDs. PF complaint references to NPC remain PF-reported evidence, not an independently received NPC dataset.

Sources without these action fields (including reference files, education and court-participant evidence) remain covered by the original anchored catalog but are not invented authority actions. Court participant membership is not proof of a court decision maker. `action_inventory_rows` counts captured rows in scope; `authority_action_records` counts emitted action slots. They are different measures.

## Contradiction rules

* Equal aligned values are not disagreements.
* Different reported police-number types are not merged. Missing types/values stay unresolved.
* Different rank-event dates normally describe transitions. Different rank reports on the same date are candidates.
* Different aligned interval values with nonzero reported overlap are candidates. Disjoint intervals are skipped; a shared endpoint remains unresolved because endpoint semantics are unassessed.
* Snapshots, missing/invalid dates, review flags and unmatched field shapes produce unresolved comparisons.
* Different restriction IDs can coexist; a restriction and an override are not automatically contradictory.
* Same/different supplying-source labels are preserved without claiming independence or selecting a preferred source.

The requested date is a cutoff, not proof that every historical claim applied on that day. Earlier disagreements may remain relevant to explaining the reported history. Cancellation/authority/identity observations are not silently discarded.

## Output and failures

Each run creates a new owner-only directory. Officer chunks contain the internal UID, reconstructed claim groups and contradiction comparisons with both source references/destination fingerprints. Action chunks contain reported actor candidates and original source fields. All such detail is encrypted and recovered with primary and backup keys before writing. Only counts, policy/context and unresolved reasons appear in the terminal summary. An encrypted completion inventory authenticates every output chunk fingerprint; the plaintext summary alone is not a trusted result artifact.

A failure or expiry after an artifact is written leaves private partial files and `STOPPED.json`; it never issues `PASSED.json`. Existing evidence and blockchain records remain untouched. This runner has no findings-table inserts, correction writes, RPC calls, signing or blockchain submissions. Its pure algorithms can return reports but do not upgrade classification or authorize disclosure.

## Installation and checks

Install only after the committed authority foundation, on a clean `feat/identity-resolution` branch. The installer checks exact dependencies and package fingerprints before writing any source, refuses an existing new target and keeps a source-only backup. It does not connect to databases, use keys or run research algorithms.

From the repository root:

```bash
python3 "$HOME/Downloads/research-algorithms-step/install.py" --repository "$PWD"
git diff --check
cd backend
uv run python -m pytest -q --tb=short \
    tests/test_research_algorithms.py \
    tests/test_temporal_contradictions.py \
    tests/test_reported_authority_actions.py \
    tests/test_temporal_authority.py \
    tests/test_police_number_refinement.py \
    tests/test_historical_explanation.py \
    tests/test_historical_reconstruction.py \
    tests/test_audit_gate.py
```

Tests use controlled synthetic fixtures, real local AEAD/permit verification, mocked heavy research collection boundaries and pure rule evaluation. They do not verify research legal truth, the user's database contents or actual performance on the Mac. The full-universe fixture exercises all 6,596 synthetic officers and 66 encrypted officer chunks.

After passing checks, review and commit the new source and this document. Then refresh the existing audit gate against the complete live evidence and both chains. Use its NEW READY attempt directory below; do not reuse an old permit or edit its expiry.

## Research runner

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"

uv run python -m app.identity.run_research_algorithms \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
    --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
    --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
    --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
    --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
    --audit-gate-attempt "$HOME/ResearchEvidence/police-personnel-integrity/audit-gate-attempts/REPLACE_WITH_NEW_READY_ATTEMPT" \
    --on 2024-12-31 \
    --output-root "$HOME/ResearchEvidence/police-personnel-integrity/research-algorithm-attempts"
```

This defaults to all 6,596 officers. Add `--select-nic` for one hidden-prompt candidate. Any ISO calendar date is selectable; missing historical coverage remains uncertain. First send the aggregate result and attempt directory, not a NIC, readable encrypted payload, credentials or key material. A PASSED processing result is not an accepted historical state or a verified authority decision.
