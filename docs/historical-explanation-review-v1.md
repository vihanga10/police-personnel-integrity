# Protected saved reconstruction explanation review v1

This step reviews a completed encrypted reconstruction for its already selected
officer(s), date and captured snapshot. It does not accept a new date or NIC,
perform a new research audit, issue a permit or assert current live readiness.
A fresh gate is still required for a new reconstruction query.

## Verification

The reviewer authenticates the original bundle and destination artifacts using
primary and backup keys, validates complete coverage, reproduces the exact
original protected publication using its original generator revision, and checks
the saved encrypted commitments. An unchanged plaintext summary or matching row
count alone is insufficient.

It requires the reconstruction's completed PASSED summary, supported policy and
exact chosen evidence-attempt IDs/destination-artifact SHA. It rejects STOPPED
runs, missing/extra chunks, wrong chunk bindings, unexpected selection metadata,
repeated/missing officers and mismatched date/capture context. Every encrypted
chunk must recover identically with both keys.

Each saved projection is then compared with an exact replay from the authenticated
source originals and destination bindings, using the unchanged reconstruction
policy. Candidate values, evidence references, dates, reasons, status and ordering
must match; altered saved content cannot receive a completed review. Single-officer
selection must retain one anchored PF subject profile. Live NIC selection is not
repeated and historical eligibility remains UNASSESSED.

This is content/replay verification of a completed archive. It does not independently
prove that the old run finished within its permit window, renew an expired permit,
or turn a saved READY/PASSED label into current audit authorization. Private key
holders retain the ability to create encrypted artifacts; this is not institutional
sign-off or authenticated human disclosure.

## Explanations

Detailed per-officer explanations remain encrypted. Terminal output and the private
aggregate summary contain only fixed policy codes/descriptions and counts:

- Candidate/supporting/review/future/expired claim counts.
- Source-file and claim-mode counts; candidate/supporting duplicates counted once
  in unique evidence counts, while group counts preserve their separate roles.
- Missing/invalid dates, snapshot observations and semantic review blockers.
- Reasons for latest-event hypotheses, unknown interval bounds and competing reports.
- Police-number observations: number of distinct exact reported type labels,
  types with several exact reported numbers, and candidates with missing type text.
  Neither the number values nor their type labels are output. Different types are
  observations requiring interpretation, never an automatic conflict resolution.

The saved reconstruction status is preserved. No correction, accepted rank/posting,
restriction effect, authority verdict or append-only finding is created here.
Original NICs, names, UUIDs, source row IDs and personnel values are never printed.
Unknown reason/issue/source strings fail closed rather than leak arbitrary text.

## Operator sequence

Install and run the focused tests. Commit reviewed source before the saved-result
review. The synthetic fixtures do not exercise a real database or research archive;
real archive review remains to be verified on the Mac.

After commit, review the completed first single-officer result:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"

uv run python -m app.identity.review_history_explanations \
  --key-file .secrets/identity-keys.json \
  --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
  --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
  --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
  --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
  --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
  --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
  --reconstruction-attempt "$HOME/ResearchEvidence/police-personnel-integrity/historical-reconstruction-attempts/ae2a6727-6b11-4c19-989c-ca1cee002687" \
  --output-root "$HOME/ResearchEvidence/police-personnel-integrity/historical-explanation-attempts"
```

Send only the aggregate output. Outputs are owner-only, encrypted/private and kept
outside Git. No live database/RPC connection, blockchain transaction or existing
artifact modification occurs. A failed review preserves the original result.
Classification remains UNASSESSED; Stage 3 remains in progress.
