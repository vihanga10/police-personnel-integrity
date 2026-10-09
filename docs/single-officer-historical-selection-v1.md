# Private single-officer historical selection v1

This step adds `--select-nic` to the existing reconstruction runner. Without this
flag, the runner still processes all 6,596 officers. `--on YYYY-MM-DD` remains
required and can differ for each query. The first agreed date is 2024-12-31.

## Selection and integrity rules

1. Authenticate the encrypted captured source and destination artifacts, reproduce
   the full original anchored publication, and verify all 6,596 commitments.
2. Require the fresh encrypted audit permit bound to the current source revision
   and the exact selected evidence attempts. A plaintext READY file is insufficient.
3. Prompt for the NIC without echo. Refuse an echoing fallback. The CLI has no
   `--nic` value option, preventing NICs from entering command history/arguments.
4. Recheck permit expiry after the prompt and before opening SQL.
5. Use the existing `inspected_link` verifier under the restricted local SQL login
   in a REPEATABLE READ, READ ONLY transaction. It requires one candidate and checks
   the encrypted identifier/assertion recovery with primary and backup keys.
6. Compare the query against the anchored PF profile NIC using protected HMAC
   lookup. Exactly one profile subject must agree with the live candidate and
   belong to the anchored officer universe. An alias outside this captured profile
   is refused until an appropriate versioned selection rule is reviewed.
7. Process only that candidate officer using the existing reconstruction rules.
   Recheck the permit after selection and throughout projection/output completion.

The conservative normalization profile trims surrounding whitespace only. It
never equates old/new NIC formats, changes case, removes punctuation or guesses
identity. Missing, ambiguous, conflicting or unverified matches stop the run.
Even an exact match remains a candidate: historical identity and temporal NIC
eligibility remain UNASSESSED at the requested date.

All officer identity/provenance and selection details are retained only in the
owner-only encrypted output. The entered NIC is not separately saved as a query,
lookup hash or plaintext journal value; original NIC source evidence remains in
its existing encrypted artifacts. The terminal prints aggregate states and
progress only, never the NIC, officer UUID, name or reconstructed personal values.
Selection repr also omits UUID and source references.

Single-officer mode adds a read-only PostgreSQL connection for NIC verification.
It performs no SQL/MongoDB writes, blockchain submissions or changes to evidence.
If interrupted/expired, private partial output may remain but no completed result
is issued. Each invocation creates its own attempt; earlier evidence is preserved.

This is an operator-side research tool using private keys and the restricted SQL
account, not an authenticated end-user search interface. Name/police-number search,
human disclosure and scoped UI authorization remain pending. Do not expose this
command as a public endpoint. A fresh permit authorizes protected research
processing, not readable disclosure or accepted identity/state/authority claims.

## Installation and operator verification

Run the focused tests and commit reviewed source first. The tests use made-up
identifiers/fake SQL connections; real NIC selection remains unverified until
run on the Mac. Refresh `check_audit_gate` after the new source commit. Use its
new READY attempt within the ten-minute permit window; an older permit bound to
`af3161e` cannot authorize the newly committed source.

For a single officer, set `history_gate_attempt` to that new gate directory, then:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"

uv run python -m app.identity.reconstruct_history \
  --key-file .secrets/identity-keys.json \
  --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
  --commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1/keys.json" \
  --backup-commitment-key-file "$HOME/ResearchKeys/police-personnel-integrity/commitment-v1-backup/keys.json" \
  --bundle-attempt "$HOME/ResearchEvidence/police-personnel-integrity/evidence-bundle-attempts/f2f04bd3-673e-4dad-8f7a-7f4b60290025" \
  --binding-attempt "$HOME/ResearchEvidence/police-personnel-integrity/destination-binding-attempts/621e6c66-7009-4ac0-a793-a69da6c67762" \
  --commitment-attempt "$HOME/ResearchEvidence/police-personnel-integrity/protected-commitment-attempts/ea037905-647d-419e-b250-f688fd246a50" \
  --audit-gate-attempt "$history_gate_attempt" \
  --on 2024-12-31 \
  --select-nic \
  --output-root "$HOME/ResearchEvidence/police-personnel-integrity/historical-reconstruction-attempts"
```

Enter the NIC at the hidden prompt. Do not post it in chat, screenshots or logs.
Use another ISO date in `--on` for a different historical question. Omitting
`--select-nic` retains the existing full-universe mode. Complete success is
`Reported historical reconstruction: PASSED`, with one officer and one encrypted
artifact in the private summary. Individual answers may still be CANNOT_VERIFY
or CONFLICTING_REPORTS. No accepted state, audit finding or authority verdict is
created by this step. Stage 3 remains in progress; classification UNASSESSED.
