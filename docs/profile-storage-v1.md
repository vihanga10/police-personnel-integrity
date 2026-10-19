# PF profile storage and controlled development intake

Status: implemented in this batch; database verification and rollout pending.
Stage 2 remains in progress. Stage 3 is not complete.

## Storage contract

The logical routing contract remains intact. `physical_storage_column` in
`field-routing.json` specifies the actual protected storage container. Existing
logical field names remain available inside encrypted payloads. The four
identifier fields retain their existing storage and registration decisions.

| Destination | Personnel values |
|---|---|
| Officer name version | Officer's full name and initials, permitted by the agreed policy |
| Demographic version | Encrypted birth date/place, gender, nationality, religion, marital status |
| Address version | Encrypted address and source-scoped station reference |
| Family relation | Encrypted parent name and any future relationship payload values |
| Physical profile | Encrypted measurements and measurement dates |
| Previous employment | Encrypted employer and any future employment payload values |
| Restricted profile | Encrypted blood group, identifying marks and medical remarks |
| Contact version | Encrypted normalized contact; keyed lookup digest |
| Source assertion | Encrypted originals, parsed values, warnings and reference provenance |
| Profile receipt | Encrypted destination references, plan and import binding |

Opaque IDs, chain/version numbers, transaction timestamps, routing categories
(`PRESENT`, `FATHER`, `EMAIL`, `MOBILE`), key versions and protected lookup digests
remain internal database metadata. They must not be returned as unrestricted
personnel details. Future application authorization must control metadata and
personnel-value access together. Encryption at rest does not authenticate a user
or authorize a view. Server/service credentials can decrypt and must remain
unavailable to application users.

All effective dates in this PF import are unknown. `valid_from`/`valid_to` remain
NULL, and the encrypted payload retains null effective/measurement dates. The
six converted tables prohibit plaintext effective dates; future known dates must
be stored inside the encrypted version payload. Transaction time records intake,
not historical truth. Reported age is retained as source evidence and is not used
to invent a snapshot date or change a birth date. Measurement plausibility and
source-scoped station historical applicability remain unassessed.

## Migration boundaries

Migration `e62c9a01bd47` follows `c91a4b7e2036`. It locks and requires all six
converted destinations to be empty before dropping their unused plaintext-value
columns. It does not rewrite populated officer, identifier, assertion or staging
evidence. Existing closure/version-chain guards remain active. It creates an
append-only receipt table in `staging`, validates receipt provenance on insert,
and grants the application account SELECT/INSERT only. The table rejects
UPDATE/DELETE/TRUNCATE. There is no automatic downgrade that discards data.

The synthetic rollback checker uses ephemeral keys; it must run before applying
this migration. It checks model/schema agreement, encrypted writer/replay,
source binding, immutable updates, unknown-date constraints, permissions and
transaction rollback. No existing personnel values are decrypted by this check.

Next-of-kin and family civil-event models are outside this PF batch. Their
currently empty destinations must be protected before importing those datasets.
No MongoDB collections or service/operational records are changed by this batch.

## Import invariants

The development CLI requires committed code, the registered archive and source
confirmation fingerprints, matching row membership/headers, established officer
registration decisions, explicit LK telephone context, separate primary/backup
key files and a private evidence directory outside the repository. Every planned
row is checked before writes, including existing receipts on a resumed run.

One database transaction writes a source assertion, its destination versions and
its receipt. A registration advisory lock serializes cooperating writers. Receipt
uniqueness prevents duplicate source-row imports. Retries decrypt and compare
saved evidence, officer/source bindings, destination coverage, values, HMACs and
backup-key recovery. A changed source plan or registration decision stops the
run for explicit review. This initial writer does not implement corrections or
silently replace an existing version.

The optional writer commits each successful row independently. An interrupted
batch can therefore have completed rows; it must be rerun and reconciled. Durable
metadata-only attempt events record preflight, each row's start/completion and
failure uncertainty. A failed success-journal write after a database commit is
resolved from the persisted encrypted receipt, not treated as a rollback.

## Security and research boundaries

Classification remains UNASSESSED, with no user-facing disclosure enabled.
The absence of a classification must never grant ordinary viewing access.
These are local development commands, not authenticated HQ Admin endpoints.
Only HQ Admin may import/enter records in the eventual application. The existing
restricted development database account is not a human role or proof of login.

This receipt/journal is import evidence, not the completed user access-audit
system. Still pending: identity/session management; agreed RBAC/ABAC including
IGP, explicitly appointed unit SDIGs, scoped supervisors/OICs and approved HQ
Admin restricted access; personnel classifications from service evidence;
protected histories after transfer; corrections and approvals; view/export/log
permissions; tamper-evident access and finding logs; MongoDB event protection;
source attestations and authority/delegation; temporal integrity algorithms;
append-only findings/reassessment; blockchain commitments and verification;
application UI; end-to-end security/recovery and research evaluation.

Maintain all of these requirements in the implementation tracker. A passing PF
import does not complete Stage 2 or Stage 3 and does not establish source truth,
independent corroboration, authorization or blockchain anchoring.
