# Local bitemporal reported reconstruction

This additive module selects recorded evidence versions at an explicit knowledge
timestamp, then invokes the existing reported effective-date reconstruction.
It does not change the previous snapshot runner or authority integration. It
does not execute research, authenticate receipts, access stores, issue permits,
save findings or submit blockchain transactions. RPC 1 remains deferred.

## Input contract

`RecordingHistory` describes one officer's complete supplied recording history
within an explicitly established UTC coverage window. Each `EvidenceVersion`
contains a reported `Claim`, stable source key, unique version ID, aware system
recording timestamp, receipt reference and SHA-256 digest. Corrections name the
immediately previous version through `supersedes` and replace the whole claim.
Use the same `claim_id` for versions of one logical source claim. Multiple state
dimensions from a row have separate stable claim IDs. Independent source rows
have distinct IDs even when their values agree.

The recording timestamp must come from an authenticated system intake/version
receipt. Never substitute CSV event dates, source-written capture dates, file
modification dates, blockchain timestamps or the current time for missing intake
history. A later protected snapshot alone does not prove earlier visibility.
Coverage is supplied by the trusted adapter; this pure module validates its
shape and bounds but cannot prove completeness or authenticity.

## Query behavior

| Situation | Result |
| --- | --- |
| Query before coverage starts or after coverage ends | Reject; unavailable history is not an empty history. |
| Version recorded after `known_at` | Exclude from all result state and provenance. |
| Version recorded exactly at `known_at` | Include; its predecessor stops being current then. |
| Correction with earlier effective date | Apply only at/after its actual system recording time. |
| Correction changes effective interval | Recompute using the replacement interval. |
| Explicit withdrawal | Remove its candidate; keep withdrawal version in visible provenance. |
| Reinstatement | Require another later version naming the withdrawn predecessor. |
| Fork, missing predecessor, duplicate version, same-time correction | Reject rather than guess precedence. |
| Correction changes officer, source key or dimension | Reject. |
| Independent competing source claims | Retain both; existing conflict behavior applies. |
| Snapshot, uncertain date, restriction or open interval | Preserve existing conservative reconstruction semantics. |

System-time head selection is inclusive at arrival and exclusive at the next
correction. Reported effective interval end dates remain inclusively selected
as candidates only, with the existing end-day uncertainty reason. The module
does not interpret those candidate intervals as legally accepted periods.

The result includes effective date, normalized knowledge timestamp, selected
version provenance, per-dimension projections and a deterministic query digest.
Later arrivals do not change an earlier query digest. The digest is an internal
fingerprint, not an HMAC commitment or blockchain anchor. Preserve it in
protected output only; do not publish it as personnel evidence.
`accepted_state` remains null, and `receipt_authenticity_claim` remains false.

## Python usage with authenticated inputs

```python
from app.identity.bitemporal_reconstruction import query

# history is an explicitly constructed RecordingHistory backed by verified
# intake/version receipts; effective_on is a date; known_at is aware datetime.
result = query(history, effective_on=effective_on, known_at=known_at)
```

Do not build a historical version sequence from the existing CSV dates. If only
one receipt-backed baseline is available, queries earlier than that baseline
must fail. An initial version must have no predecessor and cannot be withdrawn.
Full historical correction chains must be present; this release does not accept
truncated chains with missing ancestors.

## Install on the Mac

Extract the ZIP in Downloads, outside the repository and outside incoming.
The installer requires the clean existing `feat/identity-resolution` branch and
the exact reviewed historical reconstruction source. It adds three files only,
rejects existing targets and does not commit automatically.

```bash
cd "$HOME/Downloads/bitemporal-query-step-v2-compatible"
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"

cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest tests/test_bitemporal_reconstruction.py -q
```

After focused tests pass, run the existing historical and authority regression
tests on the complete local repository:

```bash
uv run python -m pytest tests/test_historical_reconstruction.py \
  tests/test_temporal_authority.py tests/test_action_authority_integration.py -q
```

Review and commit the three added files after those checks pass. If installation
or tests fail, preserve the output for review; do not re-import CSVs or rerun
publication to resolve a source-code issue.

## Remaining research integration

The existing runner still accepts only its captured knowledge snapshot. A future
guarded history adapter must authenticate exact intake/version receipt bytes,
source identity, stable logical IDs, coverage, corrections and destination
bindings before constructing this input. It must version actor-state references
by both dates and revalidate permits around protected processing and saving.
Those integrations are not claimed by this pure-module release.

Real execution requires current evidence readiness, fresh Fabric/Sepolia
reconciliation after resolving RPC 1, and authenticated assessment evidence.
Fixture tests establish local algorithm behavior, not historical truth, legal
authority, dataset accuracy or a completed research audit.

## Compatibility revision

This package requires the exact uploaded historical reconstruction V2 source.
It preserves typed police-number comparisons and explicitly binds
`REPORTED_HISTORICAL_RECONSTRUCTION_V2` in each result and query digest.
Different reported number types are retained without inferring equivalence;
missing types remain unverifiable. The existing reconstruction file is never
replaced. The previous V1-compatible bitemporal package should not be installed
on this repository. No archived outputs are rewritten by this revision.
