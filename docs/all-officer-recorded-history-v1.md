# Historical queries for every connected generated officer

This update enrolls every identity in the existing anchored generated batch in
the recorded-history UI. It requires the successful all-source-profile import
already performed on the Mac. It does not replace original source records,
corrections, findings, access logs, keys, network configuration or chain journals.

## What changes

| Before | After a successful new import |
|---|---|
| 6,596 full source profiles; 2 historical workspaces | 6,596 full profiles and 6,596 historical workspaces |
| Historical queries unavailable for other officers | Every permitted row opens a workspace with historical queries |
| Only the two existing journals have recorded knowledge times | Those two are preserved; the others receive genuine new recorded baselines |
| Rounded browser date controls could make a single-point baseline hard to select | “Use last recorded evidence” selects the exact timestamp, including microseconds |

IGP/HQ and the configured SDIG simulation account can see their complete granted
scope. DIG, SSP, SP and station accounts retain their original assigned scopes.
The inactive account remains inactive. Source-reported division and station remain
separate from simulated application access memberships.

## Two dates, with an example

**Effective on** asks which reports apply to a calendar date. **Known as of**
asks which evidence versions the system had recorded at a timestamp.

For example, a generated record may report a promotion effective in 2019. If
the recorder first observes that archived row today, the system can query the
2019 effective date using today's recorded evidence. It cannot claim it already
knew that evidence in 2019. It refuses a knowledge timestamp before the baseline.
CSV action dates, intake labels and filesystem times never become recording times.

The new baseline initially has one knowledge point: its actual recorded time.
The UI chooses that exact point automatically. Change **Effective on** to inspect
different years. If the knowledge field was edited, press **Use last recorded
evidence** to restore the supported point. The existing two histories retain their
earlier actual observations and any recorded correction/withdrawal lineage.

Every answer uses the existing bitemporal reconstruction and contradiction
algorithms, with reported candidates, unresolved or missing dates, retained past
endpoints, provenance and query/comparison digests. A blank finding list does not
mean agreement. Reported rank does not confer action authority. Accepted state,
complete capture of every real-world change, and historical police authority are
not established by these generated source reports.

## Install and connect

1. Stop the existing application using **Ctrl+C** in its server terminal.
   Keep the existing PostgreSQL, MongoDB and Fabric services running.
2. Extract `application-all-officer-history.zip` into Downloads.
3. Run:

```bash
bash "$HOME/Downloads/application-all-officer-history/run-complete.sh"
```

The script checks the exact reviewed source, installs only source changes, runs
tests, commits those changes locally, renews the same generated accounts for one
day, prepares a private read profile for the new commit, runs the full read-only
audit, and enrolls/imports histories only after **READY**. Paste the full tokenized
QuickNode Sepolia HTTPS URL at its hidden prompt. Do not paste that URL into chat.
The original `network.json` and original transaction journals stay unchanged.

The accounts keep their existing passwords, roles, IDs, scopes and inactive flag.
HQ's existing log-reader permission is renewed for the same identity only. Logs
remain stored. Renewal changes signed account versions and invalidates earlier
sessions; sign in again. A new account version does not silently renew Stage 4
review-request authority. Existing requests/findings remain stored, and their
original account-version and authority restrictions remain enforced.

The final JSON must include:

```json
{
  "status": "ALL_OFFICER_HISTORIES_IMPORTED",
  "directory_officers": 6596,
  "recorded_history_workspaces_connected": 6596,
  "all_recorded_history_workspaces_connected": true,
  "preserved_existing_histories": 2,
  "new_recorded_baselines": 6594,
  "source_or_chain_modified": false
}
```

Numbers are computed from the actual verified batch, not hardcoded into the
importer. If the existing preserved count differs, inspect it before describing
the result in the report. `run-complete.sh` then starts the existing HTTPS server;
use **https://127.0.0.1:8443**. The script does not start databases,
reset chain state, kill another server, or install a public deployment.

For separate source installation and connection, run `run-update.sh` followed by
`run-connect.sh`. Source installation itself performs no private-state renewal,
RPC call, database import or chain operation. The connection script explicitly
performs the private account renewal and witnessed generated-data enrollment.

## Verify on the Mac

1. Sign in as `research.igp` or `research.hq`. Open **Connected detail views in
   my scope**. All permitted rows should indicate **Historical queries connected**.
2. Open several officers beyond the original two. Full source rows and original
   reported posting should still be visible. Open **History**, choose an earlier
   effective date, leave the recorded knowledge point selected, and run the query.
3. Use a knowledge date before the new baseline: the backend must refuse it.
   Restore **Use last recorded evidence**, then rerun the same effective date.
4. Sign in as each DIG/station account and check its scoped rows. Directly asking
   for an officer outside the account's membership must remain denied.
5. Check HQ's retained access logs for searches, workspace views and historical
   queries. DIG has no access-log permission. Manual logout and the fixed
   30-minute session deadline continue to clear the screen while retaining logs.

Normal queries do **not** run the full audit or contact a public RPC. Historical
copies have no five-minute expiry. Login sessions remain fixed at 30 minutes;
administrative access grants are separately bounded. Updating original evidence,
changing recorded histories, or renewing administrative authorization is an
explicit operator operation, not a browser bypass.

## Safety, completeness and interrupted runs

The full original batch is replayed once. Subject claims and full records are
indexed once rather than scanning all 167,865 rows separately for each officer.
The adapter uses the unchanged historical source schemas and original destination
bindings. Recording-actor mentions never become another officer's subject rows.

Each new officer receives the original signed/encrypted baseline and checkpoint
formats, authenticated with primary and backup keys. An aggregate signed,
encrypted checkpoint-set manifest pins all new journals, full-record digests and
existing preserved packets. An independently keyed mTLS witness acknowledges the
exact complete set using nonce-bound compare-and-swap and fresh readback. It is
an owned loopback witness on the same computer, **not independently administered**.
This enrollment submits no blockchain transaction and creates no stored finding.

The existing two per-officer recording and findings witnesses are freshly read
and replayed. Their stored packets must match those journals and findings exactly;
an advanced, stale or conflicting old workspace stops the bulk import rather than
discarding a correction. New authority summaries use the existing unassessed
reported-action algorithm; they cannot issue a police review decision.

The new UI packets and disclosure grants are published together in one SQLite
transaction. Encrypted immutable set/packet recovery copies are retained. The
source/context/publication pins, current accounts, directory, witness tip and
fresh audit permit are checked before and immediately before transaction commit.
An interruption or expired permit rolls back UI publication. Previously connected
full-source profiles, workspaces, pending requests and audit events remain stored.

The audit permit remains its original ten-minute window; this code neither
extends nor replaces it. Claims are frozen during compilation; both permit
recovery keys are authenticated before each durable journal write. The complete
source/publication is rechecked at batch boundaries and before publication.

If a run stops, preserve **all** private state under `generated-connection-v1`.
Do not delete `all-history-v1`, reset journals, edit a checkpoint, replace the
original network configuration or remove stored accounts to bypass a failure.
Share only the last printed phase and the sanitized `STOPPED` JSON, not keys or
officer records. A lost witness acknowledgment can be recovered by a fresh HEAD
on the same manifest; a conflicting head never falls back or resets enrollment.

After a source-unchanged interruption, rerun `run-connect.sh`. It reuses the same
private read profile and actual recorded baselines while obtaining a fresh full
audit permit. Partial baseline/checkpoint publication has bounded exact recovery;
ambiguous files, partial witness provisioning, tampering, changed source revision,
changed source set or changed existing histories stop for inspection. A changed
code revision requires a new reviewed migration, not changing the pending job.

## Validation and remaining boundaries

The supplied tests use generated fixtures, real signing/encryption/recovery keys,
real loopback mTLS and real application HTTPS. They exercise all ten account
states, direct scope denial, CSRF, past effective dates, exact knowledge bounds,
corrections/withdrawals, retained findings, tampering, interrupted publication,
lost acknowledgment and resumption. The scale fixture records and queries 6,596
distinct original-format journals and atomically imports 6,596 UI workspaces.

This is not live verification of the Mac's original dataset, current RPC providers,
graphical browser rendering, independent deployment or new findings anchoring.
Those claims require their own actual evidence. Existing protected correction
formats remain compatible; this update does not provision a new findings/reviewer
runtime or live correction recording hook for all newly enrolled officers.
Runtime correction/review rollout and independently anchored findings remain
separate work. The research report should distinguish effective-date queries
over an observed baseline from evidence of genuinely earlier system knowledge.
