# Local Mongo storage foundation v1

This is an additional research database, `police_operations`, on a dedicated
Docker instance at `127.0.0.1:27018`. PostgreSQL `police_identity` remains the
identity/profile/evidence reference store. No existing Atlas cluster is involved.
This step creates an empty `service_status_events` collection; it imports no
personnel documents and does not change PostgreSQL.

## Controls implemented here

- Pinned official image `mongo:8.0.32-noble`, with a dedicated persistent volume.
- Loopback-only published port; authenticated bootstrap and application accounts.
- Bootstrap password mounted as a Docker secret file, not a password environment
  value. Password files live outside the Git repository with private permissions.
- The bootstrap account is privileged and is used only for setup/checks. The
  backend must use `police_operations_app`, never bootstrap credentials.
- The custom application role grants only `find` and `insert` on this collection.
  It grants no update, delete, drop, index/schema administration, account
  administration or document-validation bypass permissions.
- A strict validator permits only opaque internal IDs, source references,
  policy/version metadata, recorded timestamp and binary encrypted payload.
  No plaintext name, NIC, unit, rank or personnel-value fields are accepted.
- Source-row plus writer-policy uniqueness prevents duplicate initial imports.
  This collection contains source evidence, not an automatically verified current
  service state. Corrections must later append separate evidence with new source
  references; existing documents must not be changed.
- Initial classification is always `UNASSESSED`. Later authoritative assessment
  will be append-only classification evidence, not an update to these documents.
- Ciphertext binding includes event/officer/assertion/source/policy/classification
  references. The future writer must use authenticated encryption and verify
  recovery before inserting. Binary shape/length validation alone cannot prove
  that content is encrypted or that PostgreSQL references are valid.

## Verification

Local unit tests verify encrypted content cannot be rebound to another event,
officer or source and that insecure credential files are refused. They do not
replace the real Mongo server smoke check.

`setup_mongo` requires an empty research collection and refuses mismatched
existing schema, indexes, users or roles. It does not rewrite existing state.
If interrupted setup leaves incomplete indexes, stop and review the cause;
there is no destructive reset or force option.

`check_mongo` verifies the real research account's exact role assignment and
denials using nonmatching synthetic IDs. It also creates a unique isolated
`police_storage_smoke_<random>` database with an equivalent temporary role to
verify insert/read, authenticated recovery, schema rejection, duplicate
rejection and denied mutation/administration. It removes only its synthetic
database/users/roles. It never deletes research evidence or the research volume.
If a check fails, stop before importing service evidence.

## Operational boundaries and remaining work

This is database-account access control, not the human RBAC/ABAC implementation.
No IGP/SDIG/HQ Admin/OIC disclosure path is enabled. Record classification,
scope, approval, expiry/revocation and deny-by-default decisions remain required.
The application account can read ciphertext; access to decryption keys must
remain separate from database viewer access.

The instance is standalone. SQL and Mongo writes are not one atomic transaction.
The service import step must implement explicit cross-store coordination,
idempotent receipts and reconciliation before it is allowed to write personnel
evidence. Snapshot/effective-date uncertainties from service planning remain.

Keep private credential backups separately using the project's protected backup
process. Never commit, upload, print or paste password files. Changing init
password files does not rotate users on an already initialized Docker volume.
Do not run `docker compose down -v` or delete this research volume. A persistent
volume is not a backup; backup/restore verification remains a later requirement.
Loopback is a local development boundary; remote deployment requires transport
encryption and deployment-specific hardening. Privileged operators can still
alter a database; append-only app permissions are not blockchain tamper evidence.

The research database can be inspected graphically with MongoDB Compass at
`127.0.0.1:27018`, database/authentication database `police_operations`, username
`police_operations_app`. Enter the password privately from the credential file.
No URI with a password should be copied into source or terminal history.
The collection starts empty; future protected payloads will appear as binary
ciphertext. Authorized readable officer views belong in the application.

Primary references: https://hub.docker.com/_/mongo ;
https://raw.githubusercontent.com/docker-library/official-images/master/library/mongo ;
https://www.mongodb.com/docs/v8.0/reference/privilege-actions/ ;
https://www.mongodb.com/docs/manual/core/schema-validation/ .

Stage 2 remains in progress. This foundation does not complete classification,
human authorization, service import or Stage 3.
