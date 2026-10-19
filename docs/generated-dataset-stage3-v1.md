# Stage 3: anchored generated dataset connection

This deployment uses the user's **generated research records**, the original
anchored publication, existing protected replay algorithms, Stage 1 accounts,
and Stage 2 accountability. It is not an official police deployment.

## What is implemented

An operator pipeline provisions dedicated private controls, verifies the complete
original batch with the unchanged production replay loader, creates encrypted
recording journals at their actual observation times, enrolls persistent witness
stores, connects through pinned mutual TLS, captures protected comparison
findings, and imports signed scope-bound directory/detail copies.

The replay is performed once per connection operation. The internal loaded
import boundary rechecks its configured encrypted permit, source revision,
publication, witness state, signatures, current account versions, hierarchy,
disclosure conditions and cache generations before writing. The public import
entry still performs full replay. There is no HTTP route that accepts a snapshot,
provisions an account, assigns scope or starts a research algorithm.

Original CSVs, SQL/Mongo research records, source journals, public commitments,
network.json and original Fabric/Sepolia transactions are not changed. New
recording, findings, witness, accountability and UI storage is private and
separate. Comparison findings are reported candidates; this step does not accept
identities, infer historical authority or publish new findings to either chain.

## Coverage and disclosure

The authenticated directory covers all 6,596 original officers when the real
batch replay succeeds. The default initial detail batch contains **two officers**,
chosen by sorted canonical UUID. It supplies one officer in each simulated DIG
scope. Other officers are searchable within scope but their details remain
withheld until separately connected. A selected connection can process up to
100 officers; expiry and resource limits still apply, and 100 is a hard bound,
not a promised performance result. Never report all-officer detail coverage from
a two-officer result.

Membership is an explicit, deterministic **research simulation**, signed by the
existing research access operator. Sorted UUID positions alternate between
Division A/Station A and Division B/Station B; both are in District A/Province A.
It does not derive actual membership from historical rank, posting or CSV text.
The account hierarchy remains the installed Stage 1 hierarchy.

Selected ordinary/read-only disclosure grants are explicit simulation choices.
They are separate signed account-version-bound grants, not evidence that the
original records have assessed ordinary classifications. They carry no restricted
clearance, reviewer authority or review-request permission. The generated-record
owner has a distinct signing domain labelled
`GENERATED_RECORD_OWNER_NOT_POLICE_CUSTODIAN`. No real departmental or custodian
approval is asserted. This provisioning path rejects an account manifest whose
record origin is not generated research records.

## Timing and operational limits

* The audit permit retains its original 600-second deadline, measured from the
  beginning of the final live fingerprint. No renewal or deadline extension is
  supplied by this step.
* Detail presentation copies retain the connector's **300-second maximum**.
  Directory/disclosure copies last at most one hour and are clipped to their
  applicable account/data-use grants. An expired copy is withheld, even if an
  older successful audit exists.
* `audit-connect` runs the complete existing read-only audit, requires a fresh
  READY result at the clean current revision, and immediately starts connection.
  If full replay/capture/import cannot finish within the permit, it stops. Live
  performance on the user's Mac remains to be measured.
* Only actual journal observation times are recorded. CSV event dates are never
  used as system-recording times. The first baseline has a single knowledge
  instant; the UI's initial query preserves its exact microseconds. Knowledge
  before that observation is unsupported. Stage 4 adds real recorded corrections.
* Witnesses use separate stores/key domains, durable enrollment pins and actual
  mutual TLS. They are owned loopback listeners on the same computer. This is
  **not independently administered deployment** and cannot detect a coordinated
  rollback of every matching local store and retained configuration.
* These copies provide a bounded demonstration, not a continuously refreshed
  production read service. Repeat the full guarded connection after expiry.

## Install, validate and commit

Stop the running app with Ctrl+C in its server terminal. Leave PostgreSQL,
MongoDB and the existing Fabric network running. Extract the package into
Downloads and run:

```bash
cd "$HOME/Downloads/application-stage3-generated-connection" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
```

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_generated_connection.py \
  tests/test_research_connection.py \
  tests/test_research_connection_runtime.py \
  tests/test_research_workspace.py \
  tests/test_research_workspace_https.py \
  tests/test_accountability.py \
  tests/test_scoped_access_api.py \
  tests/test_scoped_access_policy.py -q &&
cd ../frontend/research &&
npm ci --ignore-scripts && npm test &&
bash "$HOME/Downloads/application-stage3-generated-connection/commit-local.sh"
```

The guarded installer checks the installed Stage 2 source and original prerequisite
pins, detects partial installation and preserves concurrent source changes. It
creates no private state, starts no services and performs no network/database
access. Commit source before creating a new source-pinned read profile.

## Prepare private state once

The following uses the exact source attempt paths already reported in this
project. It verifies private input/recovery-key properties and copies the original
identity-key bytes into a new private primary file outside Git, preserving the
original key and its existing backup. It reads key/configuration bytes, but no
source rows, research databases, RPC or chain state.

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/provision_generated_connection.py prepare \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1"
```

Expected: `STAGE3_PRIVATE_PREPARATION_PASSED`. Preparation requires a new root and
will not overwrite a previous setup. Do not repeat `prepare` to repair an
interrupted connection. A private custom source mapping can be supplied with
`--source-config`; its exact fields are the existing seven source paths excluding
`audit_gate_attempt`. Use that only when original paths differ, not to substitute
an unanchored batch. Optional `--effective-on YYYY-MM-DD` selects the first
comparison's reported effective date; the default is the current UTC date.

## Create a fresh read profile, then run audit and connection

The old profile belongs to an earlier source revision. Create a new profile and
paste the complete tokenized QuickNode Sepolia HTTPS URL only at its hidden prompt:

```bash
uv run python scripts/prepare_audit_read_rpc.py \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --profile-file "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-stage3-v1/profile.json"
```

Keep keys, credentials.json and RPC URLs private. The connection launcher hashes
and pins this profile locally before invoking the existing full audit. Original
Alchemy and the original wallet/network/journals remain unchanged.

```bash
uv run python scripts/provision_generated_connection.py audit-connect \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1" \
  --read-profile "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-stage3-v1/profile.json"
```

This forwards the existing reviewed `2.30 ETH` cumulative journal budget only to
RECONCILE checks. It cannot broadcast a transaction or spend that budget.
It checks that the local application listener is stopped before opening access
stores, which invalidate previous sessions. It owns only its new loopback witness
listeners; they close at completion/failure. Witness enrollment and journals
remain durable for subsequent reconnects.

Expected final connection result: `SIGNED_UI_CACHE_IMPORTED`,
`directory_officers: 6596`, `connected_detail_officers: 2`,
`original_source_replay: true`, and `blockchain_submission: false`.
Share that status output, not private configuration or key files. Stage 3 is
operationally completed on the Mac only after this result and the scoped browser
checks below succeed.

## Open the connected application

Start the server immediately after connection because detail copies expire:

```bash
uv run python scripts/serve_research_workspace.py \
  --config "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/workspace-config.json" \
  --certificate "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/tls/server.crt" \
  --tls-key "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/tls/server.key"
```

Open `https://127.0.0.1:8443`, sign in as `research.dig.a`, and choose
**Connected detail views in my scope**. Open its officer, then History and
**Run historical query**. Names and allowed personnel values appear as words;
hashes remain only as trace/commitment references. Findings show preserved
comparison results, authority reports remain CANNOT_VERIFY when unassessed,
and findings anchoring remains NOT_CONFIGURED until Stage 4 establishes it.

Sign out and repeat as `research.dig.b`: its connected officer is different.
`research.hq` can see both selected detail views; `research.inactive` cannot sign
in. DIG access to Access logs remains denied; the separately granted HQ log
reader can inspect connection/access events. Directly requesting an out-of-scope
UUID must return NOT_FOUND without personnel disclosure. Confirm expired detail
copies are withheld after their printed expiry timestamp.

## Additional officers and refresh

Stop the app, then repeat `audit-connect` with the same source-current profile.
Existing baselines, finding IDs, timestamps, entries and witness enrollment are
reused; only new signed UI generations/disclosures are produced. Account renewal
requires regenerated disclosures at the new account versions. Account/log grant
renewal uses Stage 2's operator tool while the app is stopped.

To connect another original officer, expand **Officer reference for the operator**
after selecting its scoped name, then supply its canonical UUID:

```bash
uv run python scripts/provision_generated_connection.py audit-connect \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1" \
  --read-profile "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-stage3-v1/profile.json" \
  --officer CANONICAL-OFFICER-UUID
```

Repeat `--officer` for a bounded selected batch. Each run refreshes only the
selected detail copies. Earlier journals remain intact; their previous detail
copies still expire. A still-current full permit can be supplied directly via
`connect --audit-gate-attempt ABSOLUTE-ATTEMPT-PATH` instead of another audit;
the exact same full replay and import guards apply.

## Failure and recovery

Stops never authorize fallback data, readiness, classification or scope. Preserve
the last printed stage and private import attempts. A blocked audit does not
start the dataset connection. Missing or changed witness enrollment never causes
automatic re-enrollment. A runtime only resumes after its complete private
configuration has been published. Partial provisioning before that publication
requires inspection; it is deliberately not reset or guessed.

Protected capture IDs are published before capture so an uncertain capture retry
retains the exact operation, finding, dates and destination. Interrupted registry
or journal advancement needs the existing explicit recovery authorization; this
step does not invent one. A complete captured finding is reused on refresh,
rather than creating a new finding because a response was lost.

SQLite access/workspace stores have separate transactions, so an interrupted
import can be partial. Details require both valid presentation and disclosure,
and incomplete grants fail closed. The private import manifest preserves exact
signed inputs for the existing reviewed importer while they remain current.
This module records administrative import ATTEMPT, ALLOWED or FAILED events;
a failure before that boundary may leave private journals but no UI import.

## Validation boundaries

Local tests use disposable encrypted permits, the fixture 6,596-commitment
publication, generated profile rows, real AES encryption, signed journals,
actual loopback mutual TLS and separate encrypted UI/log stores. Only the
original-batch loader and fixture publication pin are substituted in tests.
Production code has no fixture transport, callback loader or replay waiver.

No original Mac dataset, live database or RPC readiness was verified in this
workspace. The prior full audit passed at an earlier revision; the new full Mac
run is required. Graphical browser rendering, live source replay performance,
independent administration and new findings finality must not be claimed from
fixture results.
