# Targeted SRB activity vocabulary review v1

## Purpose and scope

Prerequisite checkpoint 62cba24: four activity sources inspected successfully,
52 tests passed on the operator Mac; duties=3,138, firearms=30,348, good conduct=2,779,
bad conduct=370. All source subject NICs had exact evidence candidates and no
missing/repeated source keys. These were observations, not accepted history.

This step revisits the three sources containing the targeted vocabulary/H2
questions (36,265 rows). The 370 bad-conduct rows are not repeated because that
source did not contain these specific questions; they remain in the full activity
planner scope of 36,635 rows.

## Conservative observations

- Duty authority and firearms supervisor ranks: exact existing rank labels and
  predefined candidate tokens such as ASP/SP/SSP are counted. Tokens are not added
  to the accepted rank map by this inspector. All other text becomes UNREVIEWED_TEXT.
- accused_arrested/accused_convicted: predefined boolean-like spellings retain
  their exact trimmed text labels. No automatic boolean or integer conversion.
- Firearms H2: eight core cells are observed as ALL_CORE_MISSING, ALL_CORE_PRESENT
  or PARTIAL_CORE; the signature is counted separately. Each block shape is also
  paired with a predefined record-status label, with arbitrary statuses suppressed.
- Totals: explicitly reported finite numeric values are compared. When every H2
  core cell is missing, year total is compared to H1 as an observation only; H2
  is never set to zero. Missing/invalid numeric inputs remain uncomparable.

Unknown vocabulary is not echoed, including names accidentally present in label
columns. If UNREVIEWED_TEXT/OTHER_TEXT remains, subsequent review must establish
that vocabulary before accepting mappings. Labels, missing blocks, signature
presence and arithmetic matches do not establish authority, authentic signatures,
competency, completion, lawful findings or current/historical unit assignment.

## Data access and checks

The inspector validates BATCH-RAW-001 archive/confirmation, supplying SRB source,
exact received headers and observed counts, source-key uniqueness, row/file
provenance, contiguous row sequence and primary/backup decryption equality.
The SQL application account operates in a repeatable read read-only transaction.
No Mongo connection, evidence writes, plaintext files or classification changes.
Only aggregate counts and exception types are printed. New code includes comments.
49 focused tests passed locally; actual source vocabulary must be checked on the Mac.

## Run from backend

```bash
uv run python -m app.identity.inspect_srb_activity_vocabulary \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

Inspect aggregate output before implementing planners and import contracts.
Stage 2 remains in progress; no activity evidence import is performed by this package.
