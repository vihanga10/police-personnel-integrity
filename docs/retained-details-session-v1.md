# Retained officer details and fixed 30-minute sessions

The generated research application now retains its signed, last verified officer
snapshots without the five-minute display expiry. The backend still enforces
current signed account/version, membership, classification, clearance and
request permissions. Account revocation or permission expiry can deny access;
that never deletes stored officer evidence. Original datasets, SQL/Mongo records,
recording journals, findings, corrections, logs and original anchors are unchanged.

Each login has a fixed maximum of 30 minutes from its creation. Activity,
refreshing the page and session polling do not restart it. The previous separate
10-minute idle timeout is removed. Clock rollback still denies authentication.
Current account expiry/revocation can end access earlier. Both application pages
show the remaining time and clear their private DOM at the deadline. The server
rejects protected requests at the same absolute deadline even if browser timers
are suspended or manipulated. Browser storage remains unused.

## Full details and coverage

For each **connected** officer, Overview now displays every column of each
original source row linked through the subject role `officer_nic_no`, grouped by
dataset, with a preserved source reference. It includes personal, service,
family, education and other subject records available in the verified catalog.
No missing value or accepted identity/state is invented. An officer mentioned
only as a recorder or approving authority does not gain ownership of another
officer's row. Scope and disclosure protection are checked before full records
are returned, and text is rendered without HTML execution.

The original directory has 6,596 officers; the current initial detail batch is
**two**. This patch does not create 6,596 recording/findings ledgers or claim that
all officer details are connected. Existing `--officer` selection supports an
explicit batch of up to 100 already anchored officer UUIDs. A wider operational
connection remains separate. Unsupported or excessively large payloads stop
rather than silently truncating fields.

These are **last verified source snapshots**, not a fresh live authority audit or
current accepted personnel state. The last observation time stays visible.
Automatic background verification is not implemented by this update. A changed
source/journal must be explicitly verified and re-imported; it does not become
visible by extending or deleting an expiry. Original five-minute operational
imports and bounded real-data policies remain accepted as their original domain;
only explicitly generated retained-directory/workspace signing domains remove
the display cutoff. Retained details are rechecked against the full original
replay during operational import. They cannot waive algorithm permits, private
witnesses or chain publication approvals.

## Install

Stop the running web server with Ctrl+C. Extract the package into Downloads:

```bash
bash "$HOME/Downloads/application-retained-details-session-v2/run-update.sh"
```

The script checks exact source compatibility with the d030ba3558 revision lineage,
installs only reviewed code, tests and commits it. It does not modify private
configuration, renew accounts, connect datasets, start services or submit a chain
transaction. Keep any existing private keys and journals; never reset them.

## One-time retained snapshot import

The old stored packets stay signed with the old five-minute policy. Installing
code cannot rewrite or extend their signatures. One fresh audit and connection
is required to produce the new signed retained snapshots at the new code
revision. **After this import, you do not run the full audit every five minutes
or every time you start the web server.** Source updates and permission changes
still need their appropriate verified operator workflows.

Renew the Stage 4 request policy at the new source revision, with the web server
stopped:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/manage_stage4_workflow.py renew-requests \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/stage4-v1"
```

Create a new private read profile; do not edit an old profile or upload endpoints:

```bash
uv run python scripts/prepare_audit_read_rpc.py \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --profile-file "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-retained-details-v2/profile.json"
```

Paste the full QuickNode endpoint only at its hidden prompt. Keep PostgreSQL,
MongoDB and the original Fabric containers running. Run this one-time audit and
import:

```bash
uv run python scripts/provision_generated_connection.py audit-connect \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --read-profile "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-retained-details-v2/profile.json" \
  --stage4-policy "$HOME/ResearchKeys/police-personnel-integrity/stage4-v1/request-policy.json"
```

Expected successful connection: `SIGNED_UI_CACHE_IMPORTED`,
`detail_copy_expires_at:null`, `display_lifecycle:RETAINED_LAST_VERIFIED_SNAPSHOT`.
These statuses do not assert live findings anchoring or police review authority.
No transactions are submitted. For subsequent normal website starts, use only:

```bash
uv run python scripts/serve_research_workspace.py \
  --config "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/workspace-config.json" \
  --certificate "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/tls/server.crt" \
  --tls-key "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/tls/server.key"
```

Open https://127.0.0.1:8443, sign in again, select Connected detail views, and
inspect Full officer source details in Overview. Verify the countdown decreases
without extending, details remain available after five minutes, and private
content clears at logout. HQ/IGP have their existing broader scope; DIG/OIC remain
within theirs. Already retained data still needs current valid account/disclosure
permissions. The research setup's bounded daily authorization grants remain
independent of snapshot retention and session duration.

The corrected package also includes session-lifecycle-accountability-v2.md.
