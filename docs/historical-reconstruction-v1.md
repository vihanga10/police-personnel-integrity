# Reported historical reconstruction v1

The pure algorithm projects reported rank, posting, police number, service status
and restrictions at a requested date. It returns REPORTED_CANDIDATES,
CONFLICTING_REPORTS or CANNOT_VERIFY. `accepted_state` is always null. Successful
execution means the protected processing workflow completed, not that each
historical question was answered or any action was valid.

## Rules and limitations

| Evidence | Treatment |
| --- | --- |
| Promotion / transfer rank | Latest dated reported `to_rank` candidates, with carry-forward explicitly a hypothesis. All predecessors and same-day ties retained. |
| Posting | Reported first/current/arrival/unit fields retained for review. No accepted station identity or automatic posting interval inferred. |
| SRB police numbers | Candidate inclusion within reported start/end bounds. End day treated inclusively for candidates only. Blank end never proves continuing validity. Number type retained; overlapping different types may require review rather than imply an error. |
| Restrictions | Concurrent reported intervals retained as a set; no restriction effects, removals or overrides accepted as legally valid. |
| HR service status / current labels | Snapshot observations retained for review, never backdated from enlistment, retirement or posting dates. |
| Cancelled transfer / unclear flag | Retained for review; never automatically applied or undone. |
| Demotion | Floor rank retained for review, never treated as resulting rank. |
| Missing / invalid dates | Unplaced review evidence, never guessed or coerced. |

Missing initial records, missing state values, uncertain cancellation/override
semantics and current snapshot labels can produce CANNOT_VERIFY even when dated
candidates exist. The answer retains those candidates and review evidence.
Conflicting dated candidates are exposed without selecting a preferred source.
Absence of restrictions never establishes that an officer was unrestricted.
Future queries beyond capture remain CANNOT_VERIFY.

The knowledge dimension is this authenticated captured snapshot only. A source's
reported recording date is not the database transaction timestamp. The algorithm
rejects earlier/later `known_at` requests because an accepted bitemporal history
has not been established. Source row/provenance/assertion references and complete
destination-binding fingerprints remain attached. Actor-only memberships never
become subject state. Other anchored sources remain preserved without being
misinterpreted as temporal state evidence.

## Research execution boundary

`app.identity.reconstruct_history` loads owner-only encrypted snapshots and both
key copies, checks complete catalog/destination coverage, reproduces the exact
original anchored publication using the original generator revision, and verifies
the saved encrypted commitments. It requires a fresh encrypted audit permit bound
to the current code revision, selected attempt IDs and destination artifact SHA.
It checks expiry before/after each officer projection, before saving each output
chunk and before issuing PASSED. Default all-officer processing makes no DB or RPC
connection or chain write. Optional `--select-nic` adds a restricted read-only
SQL snapshot to verify encrypted NIC evidence; it makes no database or chain writes.

By default, all 6,596 officers are covered in encrypted chunks of at most 100 results.
With `--select-nic`, only one exact verified candidate officer is projected after
the full original batch has still been validated. See
`single-officer-historical-selection-v1.md` for private NIC input and selection rules.
Original text, dates, candidate UUIDs and provenance are never printed. Only
aggregate status counts are printed. Output is private, outside Git; primary
and backup recovery are checked before each artifact is saved. A stopped run
may preserve partial encrypted artifacts but never issues a completed result.
Do not treat partial artifacts as a completed audit or delete original journals.
This runner produces reported reconstructions, not append-only audit findings;
findings storage and authority decisions remain future work.

## Installation and validation

Run the focused tests first. Commit the installed source before refreshing the
audit gate. No research execution or new permit is needed for the synthetic tests.
An old gate bound to a prior source revision cannot authorize this runner.

For a later operator-selected research date, pass:

```
uv run python -m app.identity.reconstruct_history \
  --key-file .secrets/identity-keys.json \
  --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
  --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
  --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
  --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
  --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
  --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
  --audit-gate-attempt "$history_gate_attempt" \
  --on "$history_query_date" \
  --output-root "$HOME/ResearchEvidence/police-personnel-integrity/historical-reconstruction-attempts"
```

Set `history_gate_attempt` to the new READY attempt directory and
`history_query_date` to the date required by the research question (YYYY-MM-DD).
No default research date is invented. Refresh the existing `check_audit_gate`
runner after the source commit; run reconstruction within its ten-minute window.
Real snapshot execution and performance on the Mac remain unverified until the
operator runs them. No source truth or accuracy score is claimed by fixture tests.
