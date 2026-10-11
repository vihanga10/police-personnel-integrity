# Police Personnel Integrity research workspace — stages 3 and 4

This adds a navy, warm-white and restrained-gold interface to the existing
authentication backend. The branding identifies a research application, not an
official departmental service. It serves local HTML, CSS and JavaScript from the
same HTTPS origin as the APIs; it has no frontend build step or runtime npm
dependency. npm dependencies are used only for DOM and integration testing.

## What a user can do

| View | Input and behavior | Meaning of the output |
|---|---|---|
| Sign in and search | Provisioned account; exact NIC or partial English/Sinhala name; paginated scope-filtered results | A reported identity candidate within the current permitted scope |
| Overview | Select an officer | Observation timestamp, copy expiry, recorded coverage and available records |
| History | Effective calendar date, known-as-of timestamp and explicit UTC/Asia/Colombo time zone | Existing bitemporal reconstruction over a signed observed copy; candidates, review evidence, future/expired evidence and visible versions |
| Authority | Inspect retained action-date records; optional date/outcome filters | VALID, INVALID or CANNOT_VERIFY from the presentation, with assessment references; filters do not create a decision |
| Contradictions | The same historical query | Existing cross-source comparison results, bounded reported dataset names, compared values, explanations and trace references |
| Finding reviews | Select finding, request type, proposed outcome and reason | A retained review/correction request; not an accepted finding or completed decision |
| Recovery | Check an operation ID or load the latest 20 own requests for this officer | Current request status; same-actor/account-version/source boundaries survive process restart |
| Anchoring | Refresh the signed evidence presentation | Separate private-ledger, public-commitment and recovery observations; not a broadcast, repair or live finality claim |

The historical screen distinguishes effective time from recorded knowledge time.
No historical system timestamps are invented from CSV dates. At a correction's
recorded timestamp the newer version becomes visible; earlier queries retain
their earlier digest and predecessor. The UI does not change original CSVs,
evidence stores or anchors.

Evidence values are projected through a dimension-specific allowlist. Only known
dataset filenames and a source-reference digest accompany them. Whole source
rows, arbitrary provenance text, private paths and linked-person fields are not
returned. Dataset attribution remains reported; a filename does not establish
independent source custody.

## Permission and disclosure boundaries

The unchanged stage 2 backend controls IGP/HQ Admin access to all permitted
officers; SDIG by province; DIG/SSP/SP by district or division; and appointed
Station OIC by station. The web client cannot select or override any role, scope,
membership, reviewer identity or classification.

Officer scope is checked before presentation lookup. A second, signed and
time-limited disclosure grant ties user ID, current account version, officer ID
and source publication to assessed assignment/classification. Missing or
unassessed disclosure is withheld. CID/CCIB details also need restricted
clearance; a broad login role alone does not provide it. Identity-only search
continues to use the existing name/NIC projection.

Queries recheck access and packet generation before returning. Recent requests
are limited to the current actor/account version, selected officer and source
publication. Review requests need a separately granted reviewer identity. Login
permissions do not supply historical action authority or blockchain approvals.

Sessions use the existing Secure, HttpOnly, SameSite-strict cookie and CSRF token.
The existing outer boundary rejects wrong HTTPS hosts, origins, duplicate JSON
fields/headers, unexpected input fields and query strings; it bounds request
bodies to 4 KiB. Reasons have a 1,200-character ceiling but the whole UTF-8 body
must fit that byte limit. Queries and identities are not placed in URLs as query
parameters. Static assets use a self-only CSP and no external fonts or scripts.
Responses are no-store; there is no service worker or browser personnel storage.

Sign-out clears private content immediately, even while its server reply is in
flight. Moving the page to the background clears selected evidence and results.
Late replies cannot repopulate it. Periodic session/disclosure revalidation
locks the view if access cannot be confirmed. This does not promise zero exposure
between a remote revocation and the next server check.

## Review and correction workflow

1. The browser sends a request bound to current presentation generation, finding
   head, proposed decision and evidence references. The backend supplies the
   actor and source binding. It retains an encrypted immutable request.
2. If the acknowledgement is lost, no automatic POST retry occurs. Requests have a 20-second browser deadline; aborting the browser wait does not cancel or undo a server commit. A status
   lookup or recent-request list recovers the original operation. An explicit
   retry retains its exact operation ID and content. A definitive input denial
   permits correction of the form; uncertain/server-conflict outcomes retain
   the original intent for reconciliation.
3. A trusted operator separately calls `record_requested_review(...)` with the
   independently assessed and signed authority intent. It checks the current
   requester's permissions and exact request binding, then delegates to the
   existing protected temporal-review runner. The runner verifies full source
   replay, action-date actor histories, scope/delegation, authenticated evidence,
   exact finding head and witnesses. A REVIEW entry does not supersede the
   finding head.
4. For a correction, new source evidence must already be recorded through the
   protected recording process. `capture_requested_correction(...)` delegates
   to the existing protected capture runner and appends a CORRECTION entry.
   The original entries retain their exact bytes. The proposed decision on a
   correction request is contextual; it does not become an acceptance decision.
5. The bridge appends a protected result to the workspace event chain. Repeated
   exact protected results are idempotent. The operator exports a new signed
   presentation so the UI can display the appended finding/review version.

There are no HTTP routes for arbitrary execution, signing, evidence upload,
authority approval, key import, chain broadcast or automatic recovery. Those
actions need the existing controlled operator processes and separate approvals.
The application's request status and its observed evidence presentation can
differ temporarily until a new presentation is imported; both are labelled.

## Operational source and anchoring connection

`app.access.research_bridge.export_observed_presentation(...)` accepts the
existing protected-loader arguments and configured recording/findings objects.
It requires the original source loader and an operational recording mTLS
witness. Full original-publication replay and the unchanged audit permit are
mandatory. Its internal `_export_loaded` helper is never exposed through HTTP.

The exporter replays baseline claims against the original anchored catalog and
raw bindings, preserves recorded history and witnesses, and validates stored
temporal-review authority before summarizing it. Reported source actions without
authenticated assessment remain CANNOT_VERIFY. It does not invent VALID/INVALID
outcomes from CSV authority labels.

For anchoring observations, supply the same configured
`FindingsBackendPipeline` in **RECONCILE** mode, plus its separate fresh signed
Fabric read approval and optional public read approval. `observe_anchoring(...)`
uses the existing backend services, verifies receipt bindings and only observes.
It refuses an earlier publication prefix when representing current findings and
rechecks that the history has not advanced during observation. The exporter
rechecks source permits and recording/findings tips before returning its draft.

The public runtime still supplies only local isolated verification. Pending
public operations remain PENDING; locally verified ones remain ISOLATED_ONLY.
Real public finality and independent provider/witness deployment are not
established by a green private receipt or by a signed presentation.

The returned draft must be reviewed and signed by a configured presentation
authority, then privately imported. This stage does not provide a new readiness
permit or lower the existing source/authority/witness checks.

## Private provisioning, separate from the demo

Keep the existing stage 2 access configuration, access database and credentials.
Research presentations use a separate private directory and a distinct 32-byte
AES key outside the repository. Configurations and keys must be owner-only:
directories 0700; files 0600; no symlinks or hardlinks. Do not commit personnel
data, configuration, TLS keys or signing keys.

The workspace configuration has exactly these fields (replace every placeholder
through the controlled operational setup; this is not a usable default):

```json
{
  "policy": "RESEARCH_WEB_CONFIG_V1",
  "access_config": "/ABSOLUTE/PRIVATE/access-config.json",
  "state_directory": "/ABSOLUTE/PRIVATE/research-workspace",
  "key_file": "/ABSOLUTE/PRIVATE/research-workspace.key",
  "presentation_keys": {
    "REVIEWED_KEY_ID": "BASE64_ED25519_PUBLIC_KEY"
  }
}
```

The configured presentation public key must correspond to a separately protected
offline signing key. The server needs only the public pins. Disclosures and
presentations are signed in the `RESEARCH_WORKSPACE_V1` domain and expire within
one hour; the operational exporter defaults presentations to five minutes.
Renewal must use genuinely current observations and higher presentation
generations. Disclosure issuance must advance. Do not extend timestamps to
conceal stale observations.

From `backend`, after this private configuration is correctly provisioned:

```bash
uv run python scripts/manage_research_workspace.py init \
  --config /ABSOLUTE/PRIVATE/workspace-config.json
```

To sign an explicitly reviewed draft and import the resulting envelope:

```bash
uv run python scripts/sign_research_presentation.py \
  --config /ABSOLUTE/PRIVATE/workspace-config.json \
  --draft /ABSOLUTE/PRIVATE/reviewed-draft.json \
  --signing-key /ABSOLUTE/OFFLINE/presentation-signing.key \
  --key-id REVIEWED_KEY_ID \
  --output /ABSOLUTE/PRIVATE/new-signed-envelope.json

uv run python scripts/manage_research_workspace.py presentation \
  --config /ABSOLUTE/PRIVATE/workspace-config.json \
  --envelope /ABSOLUTE/PRIVATE/new-signed-envelope.json
```

Use `disclosure` in place of `presentation` to import a reviewed disclosure
envelope. Use `check` without `--envelope` to check private configuration. These
commands do not run algorithms, enroll users or submit transactions. Opening the
access store in a new administrative process invalidates old sessions; sign in
again after administration.

Launch on the existing configured **loopback HTTPS origin** with a reviewed TLS
certificate/key; do not expose this loopback launcher directly to a network:

```bash
uv run python scripts/serve_research_workspace.py \
  --config /ABSOLUTE/PRIVATE/workspace-config.json \
  --certificate /ABSOLUTE/PRIVATE/server.crt \
  --tls-key /ABSOLUTE/PRIVATE/server.key
```

Serving is one worker, with no reload, proxy trust or access logs. Real deployment
and operational provisioning remain the later controlled setup/readiness stages.

The encrypted request/event store detects authenticated-content and event-chain
changes, but deletion/rollback of a whole store requires separately retained
external pins/backups to detect. It is not the findings ledger, blockchain outbox
or an independent witness. Do not claim rollback-proof storage from encryption.

## Validation and acceptance boundary

The package provides actual ASGI HTTPS tests, shipped-JavaScript DOM tests,
protected journal review/correction tests, read-only receipt composition tests
and process-restart recovery. Tests use invented disposable identities/evidence;
original-source loaders, authority instruments and chain transports are explicit
test substitutes where noted. They do not establish original research-batch
replay, real police-law authority or live chain readiness.

See the package README and ACCEPTANCE.md for exact commands and the browser
checklist. Graphical browser rendering has not been verified in this execution
environment. Stage 3/4 isolated development can be accepted after installation,
automated checks and the manual browser check on the Mac. Original-batch and live
application acceptance still require real provisioning, fresh readiness and
data-use authorization. RPC 1 remains deferred.
