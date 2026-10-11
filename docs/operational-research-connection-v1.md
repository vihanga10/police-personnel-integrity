# Operational original-dataset connection v1

This is the operator connection for the existing research UI. React/Vite is
postponed. It does not turn the disposable demo into a real-data application.
Use the separate configured workspace server after a validated import.

## Completion boundary

The implementation is installable and tested with disposable encrypted evidence
and actual mutual TLS. Original batch replay, actual custody permission, RPC 1,
original dual-chain readiness, deployed witnesses and Mac activation have NOT
been established here. Missing prerequisites stop the connector; no fabricated
records, default account, fallback snapshot, permission or permit are supplied.
The original backend, research databases, intake rows, artifacts and anchors
are unchanged. Only separate encrypted access/workspace caches may be imported.

## 1. Inventory the actual Mac artifacts

After installing the package, run from `backend`:

```bash
uv run python scripts/inspect_research_connection.py \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --data-root "$HOME/ResearchData/police-personnel-integrity" \
  --output "$HOME/Downloads/research-connection-inventory.json"
```

Replace the data root if the protected attempts live elsewhere; repeat
`--data-root` for additional known roots. Use a new output filename each time.
The command scans only explicit roots, bounded to depth 8 / 50,000 entries.
`scan_incomplete` is not proof of absence. It reports Git revision, allowlisted
artifact locations, permissions and public publication digest/count only. It
never reads CSV rows, encrypted contents, credentials or keys, opens a database,
or contacts RPC. The report includes private path names; review before sharing.
Do not send private keys, passwords, encrypted personnel bundles or CSV rows.

## 2. Establish the real prerequisites

| Requirement | Operator evidence | Failure behavior |
| --- | --- | --- |
| Reviewed source | Commit the reviewed source additions; clean Git HEAD | A dirty tree or new HEAD invalidates the operation |
| Custody authorization | Actual permission for this dataset, purpose and identities; appointed custodian's separately pinned signature | Signature is only a technical representation of external approval, never legal permission created by software |
| Original capture | Existing bundle, destination-binding and commitment attempts with both recovery key copies | Full original loader must reproduce ALL original commitments |
| Original dual-chain readiness / RPC 1 | Existing guarded public reconciliation, independent RPC agreement/finality, Fabric receipts and fresh live fingerprint | No audit permit, no operational replay; no RPC override |
| Current web scope | Administrator-reviewed membership for every anchored officer | Unknown scope stays NULL; historical posting/rank never becomes current web permission |
| Protected histories | Existing observed recording registry/journal and independently provisioned mTLS witness for each selected officer | Missing, offline, wrong-scope or mismatched witness refuses details |
| Optional findings | Existing findings journal/registry and its real mTLS witness | Configured findings must verify; NULL means not connected, not an invented finding |
| UI enrollment | Existing signed active accounts, scoped access configuration and distinct encrypted workspace store | No shared demo account or automatic enrollment |
| Disclosure assessment | Signed current assignment/classification, account version, scope and explicit restricted clearance when required | Unassessed and uncleared restricted details withheld |

A worksheet cannot settle custody authorization, current geography, production
trust or RPC 1. Those require actual evidence and the designated operators.
Recording baseline creation/enrollment, observation recording and reviewer
provisioning remain their existing guarded operations. The connector does not
write to these journals or enroll a witness when one is missing.

## 3. Configure private paths and pins

Examples in `docs/examples/research-connection/` are intentionally unusable
placeholders. Replace EVERY placeholder with a reviewed value and put working
configurations outside Git. Directories 0700; files 0600; owned by the operator;
no symbolic links or hardlinked files. All runtime paths must be absolute.
Use already protected key material, separate primary/backup copies, distinct
source commitment keys and distinct access/workspace encryption keys.

`connection-config.json` names the unchanged source loader's eight arguments,
access/workspace configurations, custodian public pins and signed authorization,
and an officer UUID map to private recording/findings configurations. Start with
one authorized officer to establish the connection. At most 100 officer details
and 1,000 disclosure grants per import; directory replay is always complete.

The recording runtime provides the existing journal/registry paths, separated
crypto and signing domains, all recorder/observation/recovery public pins and
an already provisioned witness profile. Findings has analogous journal/registry
fields plus explicit reviewer identities and authority scope lists. Profile hash,
CA, client certificate/key, witness identity, registry identity and journal
anchor must all match the already deployed service. No arbitrary Python factory,
fixture transport, disabled TLS, callback or network fallback is accepted.

Use existing `manage_scoped_access.py init/account` and
`manage_research_workspace.py init` only when the reviewed stores/accounts have
not yet been provisioned. Enrollment uses separately signed ACCOUNT grants and
hidden password prompts. Follow `research-workspace-ui-v1.md`; do not use the
demo's temporary paths, keys or credentials. Configuring roots does not create
the databases automatically during a connection operation.

After committing source, an appointed custodian can sign the independently
reviewed DATA_USE draft (Unix integer timestamps; maximum 24-hour validity;
exact original public digest and current Git HEAD):

```bash
uv run python scripts/sign_research_data_use.py \
  --config /ABSOLUTE/PRIVATE/connection-config.json \
  --draft /ABSOLUTE/PRIVATE/reviewed-data-use-draft.json \
  --signing-key /ABSOLUTE/OFFLINE/custodian.key \
  --key-id ACTUAL_CUSTODIAN_KEY_ID \
  --output /ABSOLUTE/PRIVATE/data-use-signed.json
```

The approval must cover the full identity directory, with selected detail UUIDs
or a genuinely approved ALL. The custodian key must be distinct from the UI
administrative public pins. Updating code requires re-review/signature for the
new revision; never change a signed envelope after issuance.

## 4. Obtain genuine fresh audit readiness

Use the existing `app.identity.check_audit_gate` command with the ORIGINAL
reviewed paths and budget. Consult its `--help` and the existing original
publication runbook; it needs the eight source/live arguments plus network,
wallet, backup-wallet and Fabric output roots, output root, and previously
reviewed publication budget. Its RECONCILE path cannot spend that budget.
It checks original publication completion before contacting live services.

RPC 1 remains an external pending prerequisite until its actual guarded checks
pass. Do not swap providers, overwrite fixed profile hashes, simulate a response,
weaken independent-provider checks or change original finality requirements.
If the original public publication is incomplete, the existing gate produces
PUBLIC_PUBLICATION_INCOMPLETE; it does not silently publish it. Any necessary
chain publication is a distinct reviewed operation, outside this connector.

Use the NEW successful attempt as `source.audit_gate_attempt`. The real encrypted
permit lasts approximately ten minutes and binds HEAD, selected attempt IDs and
the exact destination artifact. Renew through the unchanged gate when expired;
do not edit time fields, reuse an old permit or invent a PASSED marker.

## 5. Local check, full replay and membership review

```bash
uv run python scripts/connect_research_datasets.py check \
  --config /ABSOLUTE/PRIVATE/connection-config.json

uv run python scripts/connect_research_datasets.py verify \
  --config /ABSOLUTE/PRIVATE/connection-config.json \
  --officer ACTUAL_AUTHORIZED_OFFICER_UUID

uv run python scripts/connect_research_datasets.py membership-draft \
  --config /ABSOLUTE/PRIVATE/connection-config.json \
  --review-reference ACTUAL_SCOPE_REVIEW_REFERENCE \
  --output /ABSOLUTE/PRIVATE/membership-worksheet.json
```

`check` reads local protected configs/keys/permit, but performs no network access,
full replay or cache write. `verify` performs the unchanged complete source
replay, then real witness HEAD reads for selected officers; it does not import.
Without `--officer`, verify proves source replay only. The worksheet requires
full replay and gives every anchored UUID explicit NULL memberships. An appointed
administrator must review current canonical PROVINCE/DISTRICT/DIVISION/STATION
scope IDs with consistent parents. Unknown values stay NULL and remain withheld.
Sign the reviewed membership with the existing access authority tool:

```bash
uv run python scripts/sign_access_grant.py \
  --config /ABSOLUTE/PRIVATE/access-config.json \
  --authority-key /ABSOLUTE/OFFLINE/access-authority.key \
  --key-id ACTUAL_ACCESS_KEY_ID \
  --payload /ABSOLUTE/PRIVATE/reviewed-membership.json \
  --output /ABSOLUTE/PRIVATE/membership-signed.json
```

## 6. Export, review and separately sign

```bash
uv run python scripts/connect_research_datasets.py export \
  --config /ABSOLUTE/PRIVATE/connection-config.json \
  --membership /ABSOLUTE/PRIVATE/membership-signed.json \
  --directory-generation NEXT_DIRECTORY_GENERATION \
  --officer ACTUAL_AUTHORIZED_OFFICER_UUID \
  --presentation-generation NEXT_PRESENTATION_GENERATION \
  --output /ABSOLUTE/PRIVATE/new-connection-export
```

Output is a private new directory: `directory-draft.json`, one
`presentation-UUID-draft.json` per selected officer, and `EXPORT.json` with hashes.
No draft is automatically signed. Identity names/NICs come from exactly bound
original profiles; no secondary scraping, search-engine enrichment or CSV shortcut.
The history is reported evidence with its real bounded knowledge coverage.
Authority needs authenticated temporal assessment; it is never inferred from
CSV labels. Accepted identity linkage/valid authority/live finality are not
asserted by this export. Without selected officers, only directory is exported.

Sign directory using `sign_access_grant.py` with kind DIRECTORY. Sign each
presentation and each separately reviewed DISCLOSURE draft using the existing
`sign_research_presentation.py` (see the workspace runbook for exact arguments).
The disclosure must name the actual active account UUID/version, selected
original officer UUID and batch, reviewed assignment/classification, clearance
and explicit review-request permission. This package supplies no such decision.

Operational presentations last at most FIVE MINUTES; directories and disclosures
cannot outlast custody authorization. Finish signing/import while current. If
replay/signing cannot fit that period, stop and measure the actual bottleneck;
this implementation does not solve it by extending old timestamps. Each renewal
requires fresh observations and a higher presentation generation. Read-only
cached access expires; no automatic refresh or unattended signing is introduced.

## 7. Validate and import the signed bundle

Create a private import manifest using the example, listing the signed directory,
signed presentations and signed disclosure files (absolute paths). Then:

```bash
uv run python scripts/connect_research_datasets.py import \
  --config /ABSOLUTE/PRIVATE/connection-config.json \
  --bundle /ABSOLUTE/PRIVATE/reviewed-import.json
```

Import repeats full original replay, current authority/permit checks and actual
mTLS witnesses. Every signed directory identity is compared to the original
projection; every signed history/findings/authority/tip/anchoring projection is
compared to fresh protected observations. Account versions, web scope,
classification, clearance and all cache generations are validated before writes.
Config/key/profile changes during the operation stop it.

Only separate encrypted UI stores change. Import invalidates old sessions; sign
in again. Two stores have separate transactions, so there is no cross-database
atomicity claim. An interruption can leave a directory/packet without disclosure;
the existing API withholds details. Re-running exactly the same still-current
signed inputs is idempotent and resumes. Changed or stale input is refused;
if expired, renew via fresh exports and new generations rather than overwriting
old records or resetting versions. A private import lock serializes connector
imports; all administrative writers must be controlled by the operator.

Missing findings configuration remains disconnected. Per-finding private/public
anchoring is NOT_CONFIGURED in this connector; composing existing chain-pipeline
RECONCILE observations is still a distinct configured bridge integration.
No receipt, independent deployment or public finality is fabricated here.

## 8. Serve and accept the real configured workspace

Use the existing `serve_research_workspace.py` with the actual workspace config
and reviewed HTTPS certificate/key. The usable Mac URL is exactly the access
configuration's loopback origin (for example a reviewed `https://127.0.0.1:PORT`).
Keep the process running. The disposable demo command and its ephemeral port
remain invented data and are unrelated to this workspace.

Acceptance requires scoped search of an authorized actual identity, a historical
query within the real coverage, an out-of-scope direct UUID denied, CSRF refusal,
unknown/restricted disclosure withheld, logout clearing, stale evidence withheld,
and restart/re-import recovery. Do not publish identities externally to obtain
a hosted link. Graphical Mac acceptance, real source replay, provider readiness
and independent deployments remain recorded separately from test results.

## Blocked stages and evidence

The CLI prints safe JSON with BLOCKED and a phase; it omits personnel, keys and
raw exceptions. Read the requirement for that phase rather than relaxing it.

| Phase | Evidence to inspect privately |
| --- | --- |
| CONFIGURATION / ARGUMENTS | Exact schemas, actual absolute private paths and current public pins |
| SOURCE_REVISION / DATA_USE_AUTHORIZATION | Clean committed HEAD and genuine current custodian approval |
| ORIGINAL_SOURCE_ARTIFACTS / RECOVERY_AND_KEY_SEPARATION | Original public digest, destination artifact, recovery copies and distinct keys |
| FRESH_AUDIT_PERMIT | Latest successful unchanged gate, matching HEAD/attempts/artifact; resolve actual RPC 1 prerequisite |
| FULL_ORIGINAL_BATCH_REPLAY | All-officer commitment replay; never replace a missing source with demo evidence |
| OPERATIONAL_RECORDING_WITNESS / OPERATIONAL_FINDINGS_WITNESS / BOUND_HISTORY_EXPORT | Real profiles, scopes, certificates, reachable witness and retained journal head |
| REVIEWED_MEMBERSHIP / SIGNED_*_BINDING | Administrator-reviewed exact signatures, source identity/projection and expiry |
| UI_STORE_CONFIGURATION / ACCOUNT_SCOPE_AND_DISCLOSURE | Real initialized stores, active versioned account and assessed disclosure |
| CACHE_GENERATION_CONFLICTS / RESUMABLE_CACHE_WRITE / INPUT_REVALIDATION | Existing generations, exact current inputs and controlled retry; reauthenticate after failure |

A positive local check is not a positive full replay; a positive import is not
live research readiness or chain finality. Keep those acceptance claims separate.
