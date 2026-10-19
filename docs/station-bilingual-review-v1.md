# Read-only bilingual station structure review v1

The preceding vocabulary review recovered 607 rows from each reference file.
All Sinhala-list station, division and province labels contained mixed scripts.
All 607 station labels remained unmatched against both master name fields under
exact trimming, NFC and whitespace normalization. This motivates inspecting
label structure; it does not establish why labels differ or which mapping is valid.

This step recognizes exactly two components separated by a terminal parenthesis
pair, one slash, one pipe, or one whitespace-surrounded hyphen/en/em dash. One
component must contain Latin letters only and the other Sinhala letters only.
Either order is supported. Punctuation, digits and format characters remain in
the components. Nested/multiple brackets, repeated delimiters, same-script
components and inseparable mixed text retain a structural-review observation.
Unsupported structures remain unresolved rather than guessed.

For each prior comparison mode, Latin station components are compared with
station_name and Sinhala components with station_name_si. Candidate sets retain
every master row. Their intersection is reported as unique, multiple, disjoint,
one-sided or absent. Even a unique intersection is an unaccepted candidate.
Only unique joint candidates receive a reported-text province/division comparison
using the Latin context component. Master Sinhala hierarchy fields are absent;
no Sinhala hierarchy verification is invented. Context does not override disjoint
or ambiguous station candidates. Coordinates and row order are not used to join.

The inspector repeats the prior read-only snapshot, pinned intake/source checks,
original header order, routing contract, sequence, provenance, count and dual-key
recovery checks. It emits fixed field names and aggregate counts only. Original
and extracted labels stay in memory; no plaintext output file, migration, Mongo
connection, personnel import, source correction or classification change occurs.

Run from backend:

```bash
uv run python -m app.identity.inspect_station_bilingual \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

PASSED means protected-source inspection succeeded, not that label candidates
are accepted station identities, independent corroboration, valid historical
periods, accurate translation or import readiness. Reference planners/storage
remain pending. Classification stays UNASSESSED; Stage 2 remains in progress.
