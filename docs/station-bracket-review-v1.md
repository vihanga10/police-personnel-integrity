# Read-only station bracket review v1

The preceding bilingual review found 605 unique joint station-name candidates,
all with matching reported Latin division/province text. Two labels remained
BRACKET_STRUCTURE_REVIEW. No mapping was accepted or stored.

This review recovers both registered reference files, then selects only labels
with that prior structural-review state. It reports parenthesis balance, maximum
nesting depth, top-level group count, and component script shapes as counts.
For balanced text ending in a top-level parenthesis group, it retains the entire
prefix and the entire group's contents. Internal qualifiers and brackets remain
intact. It does not assume these two parts are translations or languages.

Two separate hypotheses compare prefix/terminal with master station_name and
station_name_si, in both orientations. Each uses exact trimming, NFC trimming,
and NFC with whitespace normalization. Unique, ambiguous, disjoint, one-sided
and absent joint candidates remain observations. Context is reported only for
unique joint candidates, using the prior Latin division/province component rule.
Context, coordinates, source-row position and station codes never override
disjoint or ambiguous name candidates. No qualifier is dropped to create a match.

Unbalanced brackets, other bracket types, empty parts and text after the terminal
group remain unresolved. Unsupported structures are not corrected. Even a unique
candidate does not establish permanent station identity, historical scope,
independent corroboration, translation accuracy or accepted linkage.

The inspector uses the existing pinned intake/source/routing and read-only
repeatable-read checks, original header order, source provenance, sequential row
coverage, registered counts and separate primary/backup recovery. Output contains
fixed metadata and aggregate counts only. No original label, extracted text,
station code or personnel value is emitted or saved as plaintext. No Mongo
connection, migration, import, classification change or source update occurs.

Run from backend:

```bash
uv run python -m app.identity.inspect_station_brackets \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

The selected count is measured, not forced to two. PASSED means source inspection
succeeded even if unresolved structures remain. Reference planners can preserve
that backlog. Classification stays UNASSESSED; Stage 2 remains in progress.
