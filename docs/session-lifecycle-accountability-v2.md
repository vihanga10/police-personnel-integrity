# Session ending and exact-search accountability

This update retains the previous full-details and 30-minute-session changes,
and completes the following new operational logging paths. It preserves all
existing protected log events and their original fields; old search terms or
session deadlines that were never recorded are not reconstructed.

## What authorized HQ can inspect

| Record | Meaning |
| --- | --- |
| LOGIN / COMPLETED / ALLOWED | Account, role/scope at login, session start and its fixed deadline. |
| OFFICER_SEARCH | Exact authenticated name/NIC search term, request time, outcome and returned officer UUIDs. |
| LOGOUT / MANUAL_LOGOUT | Server-confirmed manual logout and its observed completion time. |
| SESSION_EXPIRED | Server-derived authorization expiry at the original fixed deadline, independent of browser requests. |
| SESSION_INTERRUPTED | A replacement login or server restart/shutdown was observed; this is not an invented human logout. |
| CLIENT_PAGE_EXIT | An authenticated client reports leaving a page, including whether it entered the back/forward cache. Logout is unconfirmed. |

Existing officer views, historical queries, review/correction requests, access
log reads, denied requests and operator actions remain logged. The log viewer's
filters now include expiry, interruption and page-exit events. Lifecycle events
show both the session start/deadline and when the event was actually recorded.
An expiry discovered later is still attributed to its original deadline, with
its later observation time retained separately.

Exact search terms are encrypted with the existing independent accountability
key. They are returned only after the current account, CSRF and explicit
log-reader grant checks. The generated application grants this capability to
`research.hq`; a DIG login alone does not grant it. Passwords, session/CSRF tokens,
keys and full officer records are not copied into the logs. A session's audit
reference is a keyed digest, not a usable credential. Search attempts remain
labelled by their actual allowed/denied/failed outcome.

## Automatic expiry and recovery

The ASGI server lifespan starts one local worker, which checks tracked session
deadlines every five seconds. It records an encrypted terminal event under the
same locked, append-only hash-chain/checkpoint protocol used by existing logs.
Concurrent checks cannot create duplicate terminal events. The displayed expiry
is the fixed deadline, even if the worker observes it a few seconds later.
HTTP requests also check pending deadlines. An unavailable lifecycle journal
fails protected HTTP requests closed; it never silently permits unlogged work.

The browser's countdown now clears the screen at expiry without calling the
manual-logout endpoint. The server rejects expired credentials independently.
Manual logout remains a distinct confirmed request. No traffic from the user is
required for the expiry worker. A powered-off or crashed server cannot write
while offline: the next successful startup reconciles known deadlines and
marks unfinished sessions interrupted without guessing their human logout time.
Graceful server shutdown records its own interruption. Logs themselves are
never deleted by logout, expiry, restart, or leaving the page.

The worker does not renew evidence, alter datasets, run a blockchain audit or
submit a transaction. Full-source refresh and protected reviews retain their
existing requirements. Account/disclosure/log-reader grant expiry remains
separate from the fixed maximum login period.

## Browser closure: the truthful limit

Browsers have no guaranteed server notification for closing a tab, navigating,
losing connection, or abruptly powering off. The application sends a small,
same-origin CSRF-authenticated keepalive page-exit report where possible. It
clears private DOM content and does not revoke a shared session merely because
a user navigates from the officer page to the HQ log page. Accepted page-exit
reports are displayed as **logout unconfirmed**. Missing reports do not prove
that a browser stayed open. This update does not claim a guaranteed exact
browser-close timestamp or infer one from the last request.

## Install the corrected package

Stop the running HTTPS server with Ctrl+C. Extract the corrected ZIP into
Downloads and run:

```bash
bash "$HOME/Downloads/application-retained-details-session-v2/run-update.sh"
```

The installer accepts either the exact reviewed Stage 4 source at the d030ba3558
lineage or the complete retained-details v1 source update. It refuses partial,
modified, staged or linked source inputs. Tests and the source commit run before
private runtime actions. This installer does not touch private stores, grant
files, credentials, keys, source data or original transaction journals.

If retained-details v1 was **not** imported, follow
`docs/retained-details-session-v1.md` for the one-time source-bound retained
snapshot import at the new commit. Use a new private read-profile path ending
`audit-read-rpc-retained-details-v2/profile.json`; do not overwrite an older
private profile. If retained snapshots are already imported, they retain their
existing signatures and remain historical snapshots under current permissions;
a new import is not needed solely to enable the new session logging worker.
Fresh algorithm execution still needs a current source-bound permit and policy.

Restart the existing HTTPS launcher as before, sign in again and inspect access
logs using `research.hq`. New sessions will include start/deadline metadata.
Existing logs remain inspectable; no retrospective login/expiry/search detail is
invented. No account credential or existing log-reader permission is provisioned
or expanded by installing the source code.
