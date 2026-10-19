# Court participant structure review v1

This read-only review investigates participate_officers_details in all 9,538 registered PF court rows. Earlier flat-list shape counts do not define the participant grammar. The tool reports aggregate bracket/quote balance, top-level separators, NIC-shaped token positions and approved structural labels. It never prints original cells, names, NICs, court identifiers or arbitrary label text. All source rows recover with both keys and must match the pinned archive, confirmation, routing, file and row metadata.

Grammar signatures contain only TEXT, NIC and approved punctuation. NIC syntax observations do not establish normalized identity, historical eligibility, participant roles, authority or accepted linkage. Complex, unbalanced, missing, oversized and mixed-separator values remain review observations. No participant links are generated yet: the aggregate results guide a bounded parser for the actual received format.

No current bundle file is overwritten, no PostgreSQL/MongoDB evidence is modified and no commitment is generated. Station reference rows remain shared reference catalog evidence. The next reviewed parser will use the existing NIC evidence verifier and preserve row/participant position and reported roles as candidate evidence, with unresolved entries retained. Avoid splitting nested court data using the previous generic flat-list parser.

Run focused tests, then from backend:

```bash
uv run python -m app.identity.inspect_court_participants \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

Share only the aggregate result. This review is not complete officer membership or blockchain readiness. Keep existing foundation attempt e09632a7-0b68-472f-800a-cd879728e158 and its encrypted artifacts unchanged.
