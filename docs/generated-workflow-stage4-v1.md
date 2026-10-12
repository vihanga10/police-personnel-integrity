# Stage 4: generated-record request and correction workflow

This step implements signed request permissions, retained review/correction
requests, operator correction processing, encrypted operator accountability and
complete witnessed findings commitment preparation. It does **not** complete
live approval or live findings anchoring. The current Stage 3 journals lack
reviewer identity and temporal authority trust. The public findings publisher
currently supports isolated testing only. Those are explicit remaining Stage 4
implementation and operational requirements, not successful live checks.

Original generated datasets, SQL/Mongo history, original Fabric/Sepolia dataset
anchors and transaction journals stay unchanged. Corrections here are new
reported findings from a changed historical query or newly recorded evidence.
They do not edit personnel records or declare an accepted true state.

## Install and validate

Stop the web server with Ctrl+C. Opening administrative account stores clears
sessions, so administrative operations require signing in again afterwards.
Keep the original database and Fabric services running. Install only on the
reviewed f588d482 source lineage, then run the provided source tests and commit.
All profile/config authorizations bind the new source revision, so create a
new private read profile and run the existing full audit/connect after commit.
Never edit the old profile's revision or bypass its digest checks.

```bash
cd "$HOME/Downloads/application-stage4-workflow" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
```

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest tests/test_stage4_workflow.py tests/test_generated_connection.py \
  tests/test_research_export_clock.py tests/test_research_connection_artifacts.py \
  tests/test_research_review_bridge.py -q &&
bash "$HOME/Downloads/application-stage4-workflow/commit-local.sh"
```

## Prepare private controls once

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/manage_stage4_workflow.py prepare \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/stage4-v1" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --connection-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1"
```

This generates separate request-permission and findings-commitment keys and
backups. It refuses an existing root. Preserve incomplete state for inspection;
do not delete/reset keys or journals to make an operation pass.

IGP, HQ, SDIG, DIG, SSP and SP can retain requests within their existing signed
scope. OIC accounts remain read-only; the inactive account stays inactive.
Request permissions last at most 24 hours and bind account versions and source
revision. They are **application request permissions**, not a police reviewer
identity or action-date authority assessment. The existing browser form already
supports both request types; no React migration is included.

## Refresh source-bound connection with request permissions

Prepare a **new** private read profile after committing, using the same hidden
QuickNode prompt and unchanged original wallet/network files:

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/prepare_audit_read_rpc.py \
  --wallet-root "$HOME/ResearchKeys/police-personnel-integrity/sepolia-v1" \
  --profile-file "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-stage4/profile.json"
```

The following command uses that profile, performs the full existing audit,
requires READY and imports current bounded detail presentations:

```bash
uv run python scripts/provision_generated_connection.py audit-connect \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/generated-connection-v1" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --read-profile "$HOME/ResearchKeys/police-personnel-integrity/audit-read-rpc-stage4/profile.json" \
  --stage4-policy "$HOME/ResearchKeys/police-personnel-integrity/stage4-v1/request-policy.json"
```

Check `--help` if your operator environment differs. Do not copy a SHA256 from a
previous profile; the command validates the current private profile. Presentation
expiry and the audit permit's 600-second limit are unchanged. A successful audit
alone does not keep the UI fresh indefinitely.

Restart the HTTPS server as before, sign in as `research.dig.a`, select a
connected officer and retain a correction request. Save its operation ID
privately. A repeated identical request reuses the original operation; changed
content cannot reuse that ID. OIC and the other division must not receive the
request permission or out-of-scope officer details.

## Apply a reported finding correction

Stop the server. Use the **current connected** audit attempt printed by the
successful audit/connect; it must still have a valid permit. Choose a changed
effective date inside the recording history's query bounds, and use the exact
aware `known_at` coverage timestamp displayed by the workspace. Never guess
source history or invent an observation timestamp.

```bash
uv run python scripts/manage_stage4_workflow.py correction \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --state-root "$HOME/ResearchKeys/police-personnel-integrity/stage4-v1" \
  --audit-gate-attempt /absolute/current/connected/audit-attempt \
  --operation RETAINED_OPERATION_UUID \
  --effective-on YYYY-MM-DD \
  --known-at 'EXACT_AWARE_COVERAGE_TIMESTAMP'
```

Placeholders must be replaced with retained values. The operator performs a full
original replay, validates current requester account/scope/disclosure and exact
finding head, contacts both existing local mTLS witnesses, and appends a
correction preserving the previous finding. An identical query with unchanged
evidence is refused. The existing operation ID and encrypted capture intent
support exact recovery after interruption. Do not retry with a new ID blindly.
Operator actions are logged under `OTHER_REQUEST`, with `stage4_action` and a
separate LOCAL_OS_OPERATOR identity. This does not impersonate the requester.
A failed completion log means the protected outcome needs inspection.

Refresh audit/connect and restart the server to display the appended correction.
No source-field edits, authority decisions or chain transactions occur.

## Review decisions and anchoring: explicit remaining work

`manage_stage4_workflow.py status` reports the configuration inventory only.
Review execution requires a source-bound independently assessed signed intent,
a protected finding receipt, a verified reviewer identity and configured temporal
authority trust. Current Stage 3 journals deliberately have none of that trust.
Adding new keys/identities changes registry trust pins; do not edit runtime JSON
to add them. A reviewed trust migration and reviewer-to-requester mapping are
required before protected approval can be enabled. Login as DIG alone cannot
satisfy this condition. The CLI refuses the current unconfigured state.

`prepare-anchor --officer OFFICER_UUID --audit-gate-attempt CURRENT_ATTEMPT`
uses separate keys to create commitments for the complete witnessed findings
prefix. Its public payload contains opaque commitments, not officer names/NICs.
Its output explicitly says **COMMITMENTS_PREPARED**, `chain_submitted:false` and
`both_chains_anchored:false`. Each preparation has a separate private directory;
never treat it as a transaction receipt or upload the encrypted private payload.

Live findings anchoring still requires a dedicated Fabric findings chaincode and
separate Sepolia findings contract, reviewed destinations, actual signed
publication approvals, durable submission recovery and readback/finality from
both Fabric organizations and both public RPC providers. The existing isolated
public findings publisher cannot establish live Sepolia finality. This step
contains no live publication command and must not be described in the report as
completed live Stage 4 anchoring.
