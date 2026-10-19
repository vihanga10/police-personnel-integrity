# Priority 2: authority/delegation and contradiction workflows

This update integrates the existing algorithms with operational, scoped web
inspection. It uses the 6,596 retained historical workspaces already imported by
Priority 1. It does not re-import datasets, renew the audit permit, change original
anchors, or submit a transaction. Normal inspection does not call an RPC provider.

## Install and start

Stop the existing HTTPS server with Ctrl+C. Extract the new ZIP into Downloads:

```bash
bash "$HOME/Downloads/application-priority2-workflows/run-priority2.sh"
```

The script checks the source at or after commit
`3659c1954a1cd490508b5047111145fe8415cb1e`, installs reviewed source, runs tests,
commits locally, prepares a separate private research-assessor key and public
trust pin, and starts the existing HTTPS application. It retains all officer
workspaces, passwords, roles, account scopes, logs, requests and earlier findings.
Source installation itself changes no private configuration or evidence.

The explicit `prepare` step adds only the new assessor key and backup, its public
pin in `workspace-config.json`, and a private operator lock. It records the setup
in protected accountability. It creates no assessment, governing rule, police
reviewer identity, legal authorization or chain entry.

Open **https://127.0.0.1:8443** and sign in again using the same account/password.
No new full RPC audit or Priority 1 history import is required for this update.
The private read profile from Priority 1 remains unchanged and pinned to its
original revision; do not edit it to bypass a future gate.

## Authority and delegation

Open a permitted officer and select **Authority & delegation**. The tab inspects
reported actions, using their recorded action dates. An optional knowledge time
selects which documented research assessment versions were available. Leaving it
blank selects the latest retained evidence. Filter by action date and outcome;
page through all actions rather than viewing only a truncated initial list.

Each result shows:

* the reported action and date, including missing/invalid dates;
* the outcome and explanation;
* recorded actor-history references, with identity details only when the viewer
  also has the actor's current scoped disclosure permission;
* supplied rules, powers, ranks/roles, actor scopes and target scopes;
* delegation parent, issuer/recipient when disclosable, issuance date, effective
  interval, revocation date and sufficient paths;
* preserved assessment versions, supersession, source references and bindings.

Earlier summaries captured with the source copy remain separately inspectable.
They are not silently replaced by a new evaluation.

**A source report, current rank or login role does not establish legal authority.**
Present-day exact NIC matches identify candidates only. Missing actors, unknown
historical identity, unassessed rules, absent instruments, unavailable actor
evidence and incomplete refutation remain visible. Future reported actions cannot
become historical valid decisions at an earlier knowledge time.

| Outcome | Meaning in this workflow |
|---|---|
| VALID | The supplied, authenticated research assessment establishes a sufficient modeled direct/delegated path. |
| INVALID | Assessed facts refute every applicable path and the supplied coverage supports that conclusion. |
| CANNOT_VERIFY | Required facts, instruments, identity, dates, coverage or source versions are insufficient, ambiguous or unavailable. |

A known sufficient positive path can remain valid without a complete inventory
of every possible rule. Incomplete coverage prevents concluding invalid solely
from a refuted route. This preserves the existing evaluator's semantics.

The results are **research evaluations of supplied assessed evidence**. They do
not authorize a police action or automatically accept personnel state. On the
existing generated dataset, reports without documented assessments correctly
remain CANNOT_VERIFY. Showing VALID everywhere would be incorrect.

## Documented assessments: private operator workflow

The website is read-only for this purpose. Users cannot submit rules, assessment
flags, actor identities or authority powers through these routes. A separate
configured research assessor signs documented inputs through a private operator
command. It is not the login, presentation, owner-authorization or encryption key.

Prepare trust (also done by `run-priority2.sh`):

```bash
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python scripts/manage_priority2.py prepare \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1"
```

The application must be stopped for operator commands. Use the officer UUID shown
in its permitted workspace. Create a private action inventory:

```bash
uv run python scripts/manage_priority2.py template \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --officer "OFFICER_UUID" \
  --output "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1/priority2/actions.json"
```

Choose the actual action reference from that inventory and supply
`--action-reference "ACTION_REFERENCE"` to create a new private draft. For
delegation issuers, add `--actor-at "ISSUER_UUID@YYYY-MM-DD"` for the issuance and
action dates. The template includes the exact reconstructed state references;
it does not mark facts as assessed or invent an instrument. New output paths are
required so an existing reviewed draft cannot be silently overwritten.

The strict draft contains `officer_uid`, `action_reference`, `workspace_sha256`,
`actor_packets`, `assessment`, `evidence_files`, `review_reference`, `supersedes`.
`assessment` follows the existing `AuthorityAssessment` structure: explicit
identity/date/coverage facts, actor/date state assessments, rules, delegations
and evidence digests. All fact/instrument evidence references must resolve to
provided evidence files with exact SHA256 digests. Unassessed template facts
remain unassessed until supported by a documented review. Do not flip flags just
to obtain a desired outcome, infer instruments from CSV ranks, or label a developer
fixture as independently reviewed police law.

`evidence_files` maps evidence reference names to existing absolute private file
paths outside the repository. Each file must be owner-only and not linked.
The total is bounded at 8 MiB and 128 references. Recording verifies every byte,
the signed subject copy, action/destination binding, source publication, actor
copies and reconstructed state IDs. Exact evidence bytes are retained encrypted
alongside the immutable signed assessment; raw documents are not served to the UI.

Record a reviewed draft:

```bash
uv run python scripts/manage_priority2.py record \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --draft "/ABSOLUTE/PRIVATE/assessment-draft.json"
```

Recording uses the actual recording time, not a caller-selected old date or CSV
event date. A correction requires the exact prior assessment reference in
`supersedes`. Earlier versions/documents remain immutable and selectable through
their original knowledge times. A changed subject or actor copy cannot silently
reuse a prior valid assessment. Its original signed version is retained and the
current inspection stays unresolved until an applicable new documented assessment.

If recording is interrupted, inspect the retained assessment/version references
before creating another request. Duplicate operation content is idempotent in the
store; different content for the same operation conflicts. A completed draft with
a stale predecessor is refused. Ambiguous acknowledgments are not automatically
retried with new identifiers. Preserve private inputs and stored evidence.

These assessment records are local protected research evidence. They are not
independently witnessed or blockchain-anchored, and they do not constitute the
separate Stage 4 police review-authority receipt. Findings/review approval and
anchoring remain Priority 3 work.

## Contradiction workflow

Open **Contradictions** directly. Choose **Effective on**, **Known as of**, and
UTC or Asia/Colombo. **Use last recorded evidence** selects the exact supported
knowledge boundary, including microseconds. The original History form continues
to return comparisons too, and synchronizes their date controls.

Filter by dimension, outcome and reported source relationship. Filters do not
reclassify a result or establish source independence. Paging preserves the
submitted criteria. Each pair shows reported values/datasets, reasons, exact
visible version references, destination bindings, recorded receipt references,
and query/comparison digests. Excluded future, expired and withdrawn versions
remain inspectable. A bounded comparison limit prevents an excessively large
signed inventory from causing an unbounded quadratic computation.

Outcomes preserve the existing semantics: reported disagreement candidate,
reported agreement, no conflict at that point, and unresolved comparison.
Snapshots are not backdated, uncertain dates stay uncertain, case/spelling
equivalence is not guessed, different events or number types are not presumed
conflicts, and open/endpoint semantics remain explicit. An empty result proves
neither agreement nor absence of contradiction. Later corrections and withdrawals
preserve earlier knowledge-time answers.

## Security, accountability and validation

Both endpoints require the current signed account, scoped officer membership,
current disclosure and CSRF for the read POST. They recheck authorization and
source versions before return. Caller-supplied role/scope/assessment fields are
rejected. Out-of-scope actor names, NICs and UUIDs are withheld even when the
server evaluates their protected actor history. Evidence/source references are
bounded; full authority documents and private paths are not returned.

HQ's existing log-inspection grant can inspect authority/contradiction queries,
requested/resolved dates, filters, query digests, outcomes, trust setup and operator
assessment records. Other accounts gain no log access. ALLOWED refers to the
server outcome, not legal authority. The fixed 30-minute session deadline and
private clearing on logout/backgrounding remain; stored logs and records are
not deleted. Late replies cannot restore a cleared officer or log screen.

Tests exercise valid/invalid/unresolved direct authority, issuer state at both
issuance and action date, delegation power/target scope, expiry/revocation,
missing parent, cycles, missing/invalid/future dates, signatures, evidence
tampering, source changes, exact correction lineage, atomic failure and replay.
All 20 existing developer-annotated contradiction scenarios run through the scoped
facade, including agreement, disagreement, ordinary transitions, uncertain dates,
snapshots, lexical ambiguity, number types, interval bounds and missing attribution.
Real HTTPS, scope/CSRF/logout and DOM injection/late-response tests cover the UI
integration. The actual 6,596-history import remains the earlier Mac-verified
Priority 1 result; this update preserves it.

The fixture results are implementation verification, not independent research
precision/recall/F1, authentic police law, proof of source custody or independent
deployment. Report operational Mac/browser acceptance separately from tests run
in this development environment.
