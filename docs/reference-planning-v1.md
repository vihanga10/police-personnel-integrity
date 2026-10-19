# Protected station reference planning v1

The reviewed source snapshots contain 607 master rows and 607 Sinhala-list rows.
Previous inspection found 605 unique joint bilingual station-name candidates;
reported Latin province/division context agreed for those candidates. Two labels
with multiple bracket groups remain unresolved. These counts are observations,
not accepted station identity, independent corroboration or historical scope.

This step plans both files without writing a database or connecting to MongoDB.
All thirteen master fields and all five Sinhala-list fields are preserved once,
in their original order, with exact source text and the committed field-routing
mapping. The original `Province ` header retains its trailing space. Destination
collections remain the planned station_reference_records and
station_sinhala_reference_records; this package does not install those collections.

Station codes remain source-scoped text; leading zeros are preserved. Missing
required code/name fields, repeated source codes, repeated Sinhala master labels,
NUL text and nonempty malformed/out-of-range coordinates retain review issues.
Missing coordinates remain missing. Numeric range observations do not establish
coordinate reference system or location accuracy. Reported hierarchy flags,
district provenance and confidence remain claims with unassessed meaning.

A recovered master snapshot supplies candidate raw-record IDs. For supported
bilingual structures the planner retains Latin candidates, Sinhala candidates,
their intersection and reported hierarchy context separately for exact trimming,
NFC trimming and NFC/whitespace comparisons. Repeated, disjoint, one-sided and
absent candidates remain review evidence. Master Sinhala-name collisions remain
explicit even when the Latin name yields one joint candidate. The conservative
bilingual rule is retained; the two bracket labels are not guessed or corrected.
A planner does not require every uncertainty to be resolved to preserve evidence.

Every plan retains UNASSESSED classification, unknown valid periods, no accepted
station UID, no authority result and linkage_accepted=false. Structural review
is separate from these universal semantic uncertainties. A row without structural
review is not verified source truth or import readiness.

Authenticated encrypted plan envelopes bind policy, file, raw-record ID, intake
batch/archive/confirmation, source file ID/checksum/row number and recovered master
file ID/checksum/count. Schema, field routing, original text, candidate intersection,
review flags and forbidden semantic promotions are checked on sealing and opening.
Candidate authenticity does not independently accept reference linkage: the CLI
first constructs candidates from the dual-key-verified master snapshot.

The CLI checks the pinned intake/source confirmation and full nineteen-file
membership, routing preservation, exact original header order, row provenance,
sequence and registered count under a PostgreSQL read-only repeatable-read
transaction. Each newly sealed plan is opened with primary and backup keys and
compared with the original plan and all original cell values. Envelopes remain
in memory; none are persisted in this step. Aggregate output contains fixed
field names, review/uncertainty counts and candidate states only.

Run from backend:

```bash
uv run python -m app.identity.inspect_reference_plans \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

No personnel evidence, source labels, accepted mappings, human access grants or
classification records are changed. Protected reference storage, delivery recovery,
guarded import/reconciliation and the final Stage 2 review remain pending.
