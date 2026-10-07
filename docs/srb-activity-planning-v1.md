# SRB activity planning v1

## Scope and prerequisites

Previous inspection checkpoint 62cba24 and vocabulary checkpoint 88e1141 establish
3,138 duty rows, 30,348 firearms rows, 2,779 good-conduct rows and 370 bad-conduct
rows: 36,635 records and 122 source columns across four schemas. This package
performs no import, Mongo setup or SQL migration.

## Parsing and preservation

The pure planner checks exact original fields and preserves every original cell.
Strict ISO calendar dates become typed reported dates; they do not become accepted
validity intervals. Recorded actor fields require exact NIC candidates when supplied.
Observed rank abbreviations ASP/CI/IP/SP/SSP/DIG/SDIG are mapped only in recording
and supervisor rank fields, with CI normalized to the existing CIP source claim code.
No global rank vocabulary is modified and no role or permission follows from a rank.
Other rank fields use the existing full-label vocabulary.

TRUE/FALSE accused flags and disciplinary flags become reported booleans; they
are not counts or verification results. Money/points are finite nonnegative Decimal
claims; co-recipient counts and performance year are integer claims. Their units,
scoring policy, year applicability and economic/legal effect remain unassessed.
Arbitrary category/unit/status labels remain reported_label objects with code=None.
Source-qualified document/operation/court/complaint/transfer references remain
unlinked claims at this planning step and must be assessed before accepted effects.

Explicit duty/performance station code-name pairs must match a unique registered
station source candidate. That match does not prove historical station applicability.
Snapshot fields are not taken as current assignments or authorization scopes.

H2 core missingness is assessed independently from signature presence: all core
missing remains unknown, partial core is a structural review issue, and a signature
without core evidence also requires review. A missing H2 score is never filled
with zero. Missing signatures are observations, not automatic authenticity results.
Reported total arithmetic is observed without correcting scores or determining
competency. Missing punishment dates and missing delegation instruments do not
establish absence of punishment/authority. Negative interval ordering is flagged;
no replacement dates are generated.

## Status vocabulary review

The runner also counts firearms record_status text containing only predefined
status words (e.g. H1/H2/YEAR/COMPLETE/RECORDED). This expands observation without
adding accepted status mappings. Arbitrary text becomes UNREVIEWED_STATUS_TEXT.
If that label remains, vocabulary meaning still requires source-based review.
Even a recognized spelling does not establish completion or lawful assessment.

## Read-only execution and encryption recovery

The runner verifies pinned archive/confirmation hashes, reported SRB source,
received headers/counts, contiguous row sequence, row/file bindings, unique source
IDs, exact encrypted subject NIC evidence, supplied actor candidates and station
source evidence. Primary and backup keys recover identical originals and encrypted
plans. Context binds source filename, raw_record_id, officer_uid and policy versions.
All fields and references are inside encrypted in-memory plan envelopes. No plaintext
plan is saved. Output contains aggregate statuses/issues/observations only.
The PostgreSQL application account uses a repeatable read, read-only transaction.
No Mongo connection, database writes, classification changes or user disclosure.

All plans carry classification UNASSESSED, authority NOT_RUN/result=None,
valid_from=None, valid_to=None, reconstructed_state=None. Full human authorization,
historical authority/delegation, accepted periods and conduct effects remain pending.
Planning success is not import readiness. Any structural issues need separate
assessment and must not be erased to qualify records for later delivery.

## Run from backend

```bash
uv run python -m app.identity.inspect_srb_activity_plans \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

Review all four aggregate reports, status vocabulary and structural-review counts
before designing guarded activity storage/delivery/import. Stage 2 remains in progress.

## Validation

89 focused tests and 25 subtests passed locally. Includes all-field preservation,
field-scoped rank aliases, boolean claims, finite numeric parsing, missing/partial
H2, signature context, actor/station candidates, reversed dates, protected status
output, encryption bindings and a complete four-source runner exercise with mocked
read-only SQL and real ephemeral encryption. No actual local research database
inspection or new activity import has been claimed; operator batch planning is next.
