# Unit-scoped SDIG dashboards and TOTP

This update is for the generated research deployment after Priority 6. It does
not establish real police appointment authority. Account identity remains
separate from officer identity and rank.

## Accounts and membership

| Login | Scope after setup | Reviewed connected count |
|---|---|---:|
| research.sdig | CID | 150 |
| research.sdig.ccib | CCIB | 149 |
| research.sdig.criminal | Every Criminal Division | 705 |

The original ten accounts remain; the two additional accounts have new private
passwords. There are twelve accounts: eleven active and one inactive. Existing
non-SDIG scopes and HQ log-reader membership remain unchanged. The inactive
account remains denied. Existing passwords are preserved.

The operator validates the current signed full-profile generation and every
profile against its manifest, original source hash and directory. Each officer
must have exactly one service row. A unit membership label is added to a newly
signed directory generation while existing geographic memberships are retained.
The preview stops if CID/CCIB/Criminal Division counts differ from 150/149/705.
The mapping is an explicit permission for generated research records, not a
claim that an HR unit field grants legal police powers.

The SDIG accounts use UNIT instead of PROVINCE. All access paths use server-side
membership checks. Officers outside the account's unit are not included in
counts, searches or profile/history/review access. New unit disclosures retain
the existing HQ-assessed protection labels and clearance; withheld assessments
stop setup rather than being overridden. The separately signed research-review
policy appends a new version for the twelve-account set. No self-approval remains
mandatory. Previous review entries and policy versions are retained.

## Dashboard and interface

The SDIG landing page shows unit officer count, connected detail count, reported
Active count, divisions represented, and rank/service-status breakdowns. Counts
come from connected signed service records, not hard-coded browser numbers.
Statistics exclude protected fields without a valid detail grant. Directory,
account, profile-generation and disclosure changes invalidate an in-flight result.
These are reported facts from retained copies; refresh does not perform a live
database or chain audit.

The top bar says CID unit, CCIB unit or Criminal Divisions unit. The redundant
RESEARCH badge is removed; research origin remains stated in the application.
Dashboard appears above 01 · SELECT AN OFFICER. Search controls use consistent
48px targets and responsive grids. CID rows have a red dot plus a CID label;
colour is not their only identifier. Geographic simulation filters are hidden
for UNIT accounts. Name/NIC search, availability filtering and paging remain.
Dashboard statistics and pending responses clear at logout/background clearing.

## TOTP for every active account

TOTP uses RFC 6238, SHA-1, six digits, a 30-second step and a one-step clock window.
Each account has a different cryptographically random 160-bit seed. Seeds and
last accepted counters are AES-GCM protected inside the access store. The same
code/time step cannot establish another session. Password and TOTP checks are
performed before session creation, with existing login throttling. Codes and
seeds are not put into access logs, browser storage or the dashboard. Existing
sessions are revoked during migration; authenticated sessions remain fixed at
thirty minutes. Browser time is not used for verification: the Mac server clock
must be correct.

Setup writes owner-only `totp-enrollment-private.json` next to existing private
credentials. It contains authenticator secrets and otpauth URIs for the eleven
active accounts. This is sensitive enrollment/recovery material. Keep it local;
do not upload it, commit it or screenshot it. Use an authenticator app's manual
entry feature with account username, issuer Police Personnel Integrity, provided
secret, time-based mode, SHA1, six digits and thirty seconds. Registration of an
authenticator device is not verified by this local operator setup; the first
successful password-and-code login verifies possession of its configured seed.
For a demonstration, one phone may hold separately labelled entries. Actual
deployment should give each account holder their own enrollment material.

Opening an officer's profile does not link that person to the SDIG login. Changes
of post holder require separate individual account administration. This update
does not issue real police approval authority or publish any chain transaction.

## Installation and operation

1. Stop the existing HTTPS server with Ctrl+C. Keep the protected files intact.
2. Run the supplied `run-update.sh`. It checks exact source hashes, installs
   reviewed source, runs tests, commits those files, previews the connected data
   and applies the private setup. It stops at the first failure.
3. Enroll at least the account you will demonstrate in an authenticator app using
   its entry in `totp-enrollment-private.json`. Existing credentials.json contains
   the original passwords plus passwords for the two new accounts.
4. Restart the existing HTTPS server. Sign in using username, password and the
   current authenticator code. Open the unit dashboard and browse its officers.

Check each unit with its own login. CID must show 150, CCIB 149 and Criminal
Divisions 705. Check that CID cannot open a known CCIB officer by changing the URL.
HQ alone retains its configured log permission. Check desktop and mobile browser
layouts on the Mac. Graphical browser rendering was not established in the build
environment; DOM, HTTP and backend tests do not establish visual browser quality.

The existing account/disclosure authorization remains bounded to about 24 hours.
To renew later, stop the server and rerun `setup_unit_sdig_totp.py --preview` then
`--execute`; it preserves existing seeds, original passwords, account identities,
unit scopes and inactive status. Do not use the older ten-account renewal tool
after this twelve-account migration. New accepted account versions can make old
pending requests ineligible for further mutation; retained requests are not
rewritten to impersonate a new authorization version.

## Recovery and preservation

Accounts, signed directory, current disclosures, TOTP factors, research-review
policy and audit entries are committed in one attached SQLite transaction with
rollback journals and FULL synchronization. Operator-only execution requires
all stores on the same filesystem. Protected database backups and an encrypted
recovery job are retained under `unit-sdig-totp-attempts/<UUID>`.

Manifest, credentials, enrollment file and log-reader grants are finalized after
SQL commit using atomic replacement. If interrupted, preserve the printed attempt
directory and run `setup_unit_sdig_totp.py --recover <exact-directory>` with the
server stopped. Recovery checks committed versions and completes private files
without repeating account updates. Concurrent changes stop recovery. Never
delete an incomplete attempt or mix stores from different backups.

Original profile/history packets, raw data, findings, original chain configuration
and journals are not changed. Existing grants outside a new unit scope remain
retained but cannot authorize access under the new account version. Prior logs
remain; administration adds audit records. No full dataset import, original audit
permit renewal, RPC call, Fabric publication or Sepolia transaction occurs.
