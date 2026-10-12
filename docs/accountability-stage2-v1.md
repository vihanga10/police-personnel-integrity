# Stage 2: accountability and access logs

This addition records application API attempts and server outcomes in a separate
encrypted local SQLite journal. It does not alter original personnel records,
research findings, evidence commitments, Fabric transactions, Sepolia journals,
or independently anchor access logs. Generated records remain generated research
records; realistic access controls do not establish actual police deployment.

## Recorded information

Each HTTP API attempt gets a server-generated request UUID, a RECEIVED event,
and a COMPLETED event before the response is released. Events include UTC time,
action category, method, attributable account/user ID, username, current stored
role/scope/account version, authentication state, permitted-format requested
officer/finding/operation UUIDs, bounded returned-officer UUIDs for successful searches, server status, outcome and fixed reason code.
Session expiry, inactive/expired grants and changed account versions are labelled
when a retained session can be resolved. Otherwise attribution remains unknown.
An attempted login is not proof of authentication; successful login resolves the
new server session. Requested UUIDs are client attempts, not accepted membership.
The peer address is stored as a keyed reference, not raw IP. No forwarded header
is trusted by the loopback launcher.

Raw passwords, cookies, tokens, CSRF values, usernames that cannot be matched to
an existing account, query strings, free-form reasons, NIC/name search text,
officer data, raw paths, user-agent text and private keys are excluded. API input
and output may be held temporarily in bounded process memory while processing;
they are not written to the accountability journal. There are no log mutations,
deletion endpoints, CSV exports or account/role overrides exposed through HTTP.
Static successful asset requests are not journaled; the tracked boundary is API
requests and the accountability page, including rejected API boundary requests.

## Integrity and failures

Entries use a dedicated AES-256-GCM key, contiguous sequence numbers and a keyed
MAC over sequence, previous digest and encrypted bytes. SQLite triggers reject
ordinary edits/deletions. A separate authenticated, atomically replaced checkpoint
detects missing/truncated tails when its newer checkpoint remains available.
Writes use a thread/process lock, SQLite commit, full synchronous mode and fsync.
Both stores and keys must be private and separate from access/workspace storage.

The full local journal and checkpoint are verified at startup, append and read.
A valid committed suffix ahead of the checkpoint may advance the checkpoint
after verifying its entire chain. A checkpoint ahead of the database or a changed
checkpoint MAC fails closed. Concurrent appends are serialized. Restoring BOTH
the database and checkpoint to an older matching version is not detected by
these local checks; independent witnessing/anchoring would be required. Someone
controlling the signing/encryption keys is outside the integrity guarantees.

If pre-request logging fails, the application action is not dispatched. If final
logging fails after a request has executed, HTTP 503 ACCOUNTABILITY_UNAVAILABLE
reports operation_outcome_unknown for POSTs. The action may already have occurred;
no rollback or automatic retry is claimed. Existing review operation IDs and
read-only recovery remain the required mechanism. RECEIVED without COMPLETED
is an interrupted/uncertain attempt, not a proved denial or success. ALLOWED is
the server response outcome, not proof that a person received/read the data.

## Explicit log-read permission

The log reader must have a current authenticated account PLUS a separately signed
READ_ACCESS_LOGS grant under PERSONNEL_ACCOUNTABILITY_V1. It binds user UUID,
current account version, issue/expiry (maximum 24 hours) and review reference to
an existing configured access authority. Being IGP, HQ Admin or DIG alone grants
no log-read permission. The Stage 2 operator explicitly provisions research.hq.
Log reads, permission denials, page access and administrative renewals are logged.
Reader grant replacement/expiry or account renewal immediately affects subsequent
log reads. Authorization is rechecked before returning inspected entries.

POST /api/accountability/logs and /legacy require the same HTTPS host/origin,
session cookie and CSRF protections. Reads are bounded to at most 100 events,
with an exclusive sequence cursor and allowlisted action/outcome filters. The
viewer uses 50-event pages and text-only DOM rendering. It clears private contents
on background/page leave, sign-out and permission/session denial, and rejects late
responses after clearing. Browser persistence and external dependencies are absent.
Time display uses Asia/Colombo; stored timestamps remain UTC.

## Legacy records

The original access audit and workspace event chains remain untouched. The
authorized viewer exposes bounded original access events through a separate
legacy source. Existing account identifiers can resolve their stable username;
roles/scopes at those old event times, requested targets, outcomes and request IDs
were not consistently captured and are labelled missing. No original event is
rewritten or retrospectively assigned a current role. Protected workspace/findings
events remain in their own stores, with new HTTP operation IDs providing correlation.

## Private provisioning and renewal

Stop the existing server before installation and administration. Commit the tested
source, then run scripts/provision_accountability.py provision with the Stage 1
private state root. It reuses existing account IDs, passwords, access/presentation
keys and TLS files. It adds a dedicated log key/backup, log store, explicit HQ reader
grant and accountability-config.json, then atomically adds accountability_config
to workspace-config.json. A partial private setup is preserved for review; never
delete existing application state or reset original source/chain journals.

Account renewal is now scripts/provision_accountability.py renew-accounts, which
advances existing account versions, preserves passwords/roles/scopes/inactive
status, renews the reader grant and logs the administrative attempts/outcomes.
Connected disclosure grants must also be reissued for the new account versions.
renew-reader changes only the reader grant while the underlying account remains
current. Administration requires a clean committed descendant of 0685028 and
the existing research operator signing key matching the configured public pin.
No legal custodian permission, personnel classification or historical authority
is created by these research account/log grants.

The source commit changes the code revision. The older audit read profile and
short-lived READY permit must not be reused for source execution under the new
revision. Prepare a fresh read profile and readiness attempt when Stage 3 source
configuration is ready; Stage 2 itself does not need a blockchain audit rerun.

## Validation

Backend coverage includes real signatures/encryption, attributable login success,
invalid/malformed/rate-limited login, scope/read denials, CSRF/origin/header checks,
expired sessions, reader expiry/version/signature denial, review/correction privacy,
bounded pagination, legacy limitations, concurrent appends, ciphertext checks,
tail/checkpoint integrity, key changes and logging failure semantics. DOM coverage
includes plaintext-safe rendering, Colombo time, explicit permission denial,
background clearing, late-response suppression, renewal/revocation clearing and
immediate sign-out clearing. Actual local HTTPS verifies configured Stage 1 to
Stage 2 provisioning, DIG denial, HQ inspection, secure cookies, request correlation,
legacy reading and renewal. All validation uses disposable generated identities;
it does not establish source accuracy, independent anchoring or real deployment.
