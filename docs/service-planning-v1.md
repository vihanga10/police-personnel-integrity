# HR service evidence planning v1

Status: read-only transformation planner, not a MongoDB importer.
Source: reported supplying source POLICE_HR_IS, confirmed within BATCH-RAW-001.

## Observed source inspection

6596 rows, 32 fields; one distinct exact NIC candidate per row; no repeated source
service identifiers or repeated single-candidate officers. All seven date columns
contain ISO calendar dates in this received file. Snapshot applicability remains
unknown. These observations do not establish source truth or present eligibility.
Current-unit snapshot claims include CID 150 and CCIB 149. They do not appoint a
responsible SDIG, prove active authorization, or classify historical records.

Missing values: current division 333; current station/name code 334 each; entry
unit type/name 267 each. Do not fill them from another field or treat them as
proof of non-applicability. Preserve the original empty values.

## Mapping rules

`HR_SERVICE_VALUES_V1` maps observed labels exactly after outer whitespace trim.
Constable classes 1-4 and sergeant classes 1-2 retain separate codes. Unspecified
entry Police Constable remains PC without an invented class. Unknown labels are
review issues; CCID is not silently treated as CCIB. No rank or location grants
access. Enrollment and service-status codes preserve source distinctions.

Rank category is retained separately. The expected-category comparison is a
versioned DATASET CONSISTENCY rule: ASP/SP junior, SSP/DIG/SDIG senior, other
observed ranks non-gazetted. This does not assert a legal gazetted definition,
legal signing powers or operational authorization. Those require dated authority
and delegation evidence in the research's later verification stage.

All 32 fields retain their source values and logical routing targets. NIC linkage
uses the established officer UID after exact stored identifier, HMAC, encrypted
supporting assertion and independent backup-file recovery checks. Disputed,
closed or non-registered evidence does not become usable intake linkage support.
Unknown historical identifier eligibility remains explicitly unassessed.

Police numbers, recruitment references, service identifiers and reported derived
values remain text, preserving leading zeros. Service-years/time-left units,
rounding and reference dates are not guessed. ISO parsing proves only calendar
syntax. Reported dates do not become current rank/status effective dates.
Retirement date does not change an Active record to Retired; actual-versus-planned
retirement semantics remain unknown. Confirmation before appointment and first
posting before enlistment are flagged source consistency issues; dates are not
silently corrected or discarded.

Station names and codes must form an exact unique pair in the registered source
station snapshot. Conflicting or unresolved pairs require review. Successful
matches retain station source-row references and unknown historical applicability.
Division/province applicability remains unassessed. Unit names remain explicitly
UNRESOLVED reported labels; no unit UID is fabricated.

## Security and persistence boundaries

Plans stay in memory and are exercised through authenticated encryption with
purpose/policy, officer UID and raw-row bindings. Date/UUID types, exact originals,
issues, source/station/identifier provenance and unknown applicability are retained
inside the encrypted envelope. Primary and separate backup key files must recover
the same evidence. Neither plaintext nor ciphertext plans are saved by the CLI.
Only aggregate metadata and issue/vocabulary counts are printed.

Classification remains UNASSESSED. CID/CCIB source claims are input evidence for
later conservative protection decisions, not permission grants. Historical
classification must remain protected after transfer; ordinary classification
cannot be inferred from a current ordinary-unit label alone. This planner creates
no classification rows, MongoDB connection, collections, personnel event, audit
finding, user account, approval or blockchain commitment.

A successful planning/recovery exercise does not mean import-ready, verified
current state, authority-valid, independently corroborated or fully authorized.
Rows with field/consistency issues must remain reviewable. Unresolved reference
and time semantics must be retained by any eventual asserted-evidence import.

Next batch: protected research MongoDB schema, append-only intake account/records,
source-qualified event identities, cross-store source assertions and resumable
import/reconciliation. Preserve all remaining source-file, RBAC/ABAC, access-log,
correction, temporal reconstruction, authority/delegation, contradiction finding,
anchoring, application UI and research evaluation requirements. Stage 2 remains
in progress; Stage 3 is not complete.
