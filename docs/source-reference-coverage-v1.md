# Read-only source and reference coverage v1

## Purpose

Inventory all nineteen registered BATCH-RAW-001 source files before the final
Stage 2 review. The seventeen personnel files contain 166,651 original rows,
including one source assertion/receipt coverage path for each imported business
row. Identifier registration assertions are separate evidence and are excluded
from that business-row total. The two station reference files remain encrypted
in staging; normalized station/Sinhala reference storage is pending.

This report is not the Stage 2 completion gate. SQL completion receipts do not
prove current Mongo ciphertext recovery. Each importer's actual encrypted
reconciliation remains separate. The tool connects only to PostgreSQL using the
application account in a REPEATABLE READ, READ ONLY transaction; it neither reads
the migration version table nor impersonates another account.

## Checks

- Require the pinned archive and confirmation fingerprints and exact nineteen-file
  supplying-source membership. The received mapping reports PF, POLICE_HR_IS and
  SRB; references to NPC/HRC do not establish independently received data.
- Match each registered header's complete field set with preserved field routing;
  reject duplicate headers/routing fields. Preserve original header spelling,
  including the Sinhala file's trailing-space Province header.
- Recover every staged row with primary/backup keys, verify exact original header,
  file metadata, row sequence and registered count. Station master is the reviewed
  607-row snapshot. Sinhala count comes from its verified registration, without
  assuming it must have the same count as station master.
- Read opaque SQL receipt/preparation/completion metadata, excluding stored
  ciphertext/BSON payloads. Check confirmations and completion digests.
- Require every relevant business assertion to have a receipt/preparation, reject
  orphans and receipts outside the received batch. Check assertion source type,
  supplying source, raw-row ID, file hash, row number, import file and batch.
- Compare exact source row IDs with receipt row IDs. Report missing, incomplete,
  unexpected and duplicated rows. Equal counts cannot conceal substituted rows.
- Keep reference-only staging distinct from imported personnel coverage. No
  personnel assertion or receipt is invented for a station reference row.

The report does not newly authenticate stored destination payloads, historical
eligibility, action authority, temporal linkage or classification. The previously
completed importer reconciliation checkpoints retain their stated scope.

## Protected reported-reference observations

Exact-trim reported key indexes are keyed HMACs held in memory only. IDs retain
leading zeroes and case; no casting, fuzzy matching or source correction occurs.
Only fixed filenames/field labels, known observation labels and aggregate counts
are printed. Reference values, officer identifiers and row-level outputs never
leave the process. No report file, plaintext plan or classification is saved.

Candidate key comparisons cover operation/complaint/court links; complaint
transfer and punishment references; transfer complaints; restriction-override
restriction/transfer links; good-conduct operation/court links; bad-conduct
complaint/hardship-transfer links; and demotion punishment references. Repeated
keys retain ambiguity. Where both source and target have a reported subject NIC,
normalized source-claim tokens are compared. SAME_REPORTED_SUBJECT is not accepted
historical identity or authorization; DIFFERENT_REPORTED_SUBJECT is not a final
contradiction finding.

Complaint linked_case_no is provisionally compared with operations.operation_no.
Complaint punishment links are provisionally compared with the SRB bad-conduct
punishment catalog, not automatically with every demotion claim. Other possible
reference meanings remain unassessed. NPC/HRC reference presence is reported as
NO_RECEIVED_TARGET_CATALOG; no external record or independent source is fabricated.

Source-scoped station-code comparisons cover service, transfer, restrictions,
duties, firearms, operations and complaints. Sinhala names are compared exactly
with station_master.station_name_si as candidate vocabulary only. A name match
never merges stations or grants historical applicability. Coordinates receive
numeric range observations, without confirming their reference system or
correcting them. Hierarchy validity, historical unit identity and multilingual
station linkage still require separate reviewed planning.

## Running

Install and run focused tests, then:

uv run python -m app.identity.inspect_source_coverage --key-file .secrets/identity-keys.json --backup-key-file /private/path/to/backup.json

The tool uses the repository's pinned intake confirmation and field routing.
It reports Personnel SQL receipt coverage PASSED only if all seventeen business
files have exact complete row coverage with no duplicates/extras. Reference
storage remains PENDING even if personnel receipt coverage passes. Unresolved
reference candidates are observations, not deleted/quarantined records or
accepted links. No writes, Mongo connection, personnel values or classification
changes. Stage 2 remains in progress.
