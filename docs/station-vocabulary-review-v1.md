# Station/Sinhala vocabulary review v1

The source-coverage checkpoint recovered all nineteen registered files and
verified SQL receipts for 166,651 personnel rows. Both reference files remain
in encrypted staging. The 607 Sinhala labels had no exact trimmed match against
station_master.station_name_si; that result does not establish incorrect data.

This inspector recovers the two reference files with separate primary and backup
keys within a PostgreSQL read-only repeatable-read transaction. It checks the
pinned batch archive and supplying-source confirmation, complete file membership,
original header order, routing preservation, source-row sequence, provenance and
registered counts. The reviewed master count is 607; Sinhala coverage follows
its verified registration. No migration, Mongo connection or import is performed.

The report contains fixed field names and aggregate counts only:

* Sinhala, Latin, mixed, other-script and missing label shapes.
* Outer/internal whitespace, Unicode NFC differences and control/format presence.
* Distinct and repeated label observations under each comparison method.
* Sinhala list candidates against both master name fields, separately using
  exact trimmed text, NFC plus trimming, and NFC plus collapsed whitespace.
* Reported province/division agreement for unique candidates only.
* Coordinate format/range observations without a CRS or accuracy claim.

Original labels and codes are unchanged. No case folding, punctuation removal,
transliteration, coordinate proximity join or fuzzy match is applied. Multiple
matching master rows stay ambiguous even if their codes or context happen to
agree. A normalized unique match is a review candidate, not accepted linkage.
Missing or unmatched labels are reported; they do not make a successful
inspection an import-readiness or source-truth decision.

All original station fields remain in protected staging, including district,
province-of-district, reported confidence and hierarchy flags. This step does
not validate those flags, resolve historical station identities or select a
correction. Complaint, NPC and HRC reference issues remain a separate backlog.

Run from backend:

```bash
uv run python -m app.identity.inspect_station_vocabulary \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

Classification remains UNASSESSED. Reference planners/storage and the final
Stage 2 gate remain pending. Human authorization and disclosure are unchanged.
