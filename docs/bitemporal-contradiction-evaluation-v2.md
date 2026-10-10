# Bitemporal reported contradiction comparisons V2

This additive local-development step leaves the archived V1 contradiction algorithm, source CSVs, destination bindings, anchors and earlier query rules unchanged. It adds a pure comparison policy, a fixture scoring function and explicitly annotated fixture cases. No production reader, findings store, service, endpoint, CLI or chain writer is enabled. RPC 1 stays deferred.

## Selection and outcomes

`compare_history(history, effective_on=..., known_at=...)` first calls the existing bitemporal query, which validates typed coverage and correction lineage. Only the latest head of each claim known by the requested instant participates. A visible withdrawal removes its claim from comparisons but remains in provenance. Dated future and expired interval heads are excluded at the effective date; review/snapshot/missing-date/issue-bearing evidence remains unresolved. Point queries differ from a scan for every historical disagreement: an interval dispute that ended before the requested effective day does not become an active conflict there.

The module compares pairs within the same officer and dimension, preserving exact claim/version IDs, full source references, destination fingerprints and receipt digests. Outcomes are:

- `REPORTED_CONTRADICTION_CANDIDATE`: differing exact comparable fields for the same reported event date, or overlapping intervals at the requested day. This is an unaccepted report disagreement.
- `REPORTED_AGREEMENT`: exact fields agree and their reported temporal applicability permits that comparison. Agreement does not authenticate truth, independence or identity.
- `NO_REPORTED_CONFLICT_AT_POINT`: distinct reported event dates are not a same-event contradiction; differing exact number types or distinct restriction IDs may coexist. This outcome does not establish a unique personnel state or prove that all evidence agrees.
- `UNRESOLVED_COMPARISON`: uncertain dates/modes/fields, end-day ambiguity, blank values, unapproved posting/service-status semantics or lexical/type equivalence needing review. Equal text does not erase these uncertainties. A request after the knowledge date cannot establish future state.

Rank comparisons use exact `to_rank` fields. Police-number comparisons retain their exact reported type namespaces. Restrictions must use the existing four fields (`restriction_id`, `restriction_category`, `restriction_effect`, `restriction_scope`); independent IDs can coexist. Posting/unit identity and historical service-status interpretation remain unapproved. No fuzzy name matching, rank alias equivalence, source precedence, cancellation interpretation, restriction override or accepted identity is invented. Whitespace/case-only differences are unresolved; original strings remain preserved. Open ends and shared end days retain explicit uncertainty.

Reported source labels, including NPC or absent attribution, are descriptive. `cross_reported_source` is null when attribution is missing. Different files are not automatically independent custodians. Receipt fingerprints are retained, but the pure function explicitly makes no receipt-authenticity claim. All outcomes retain source/identity/date/classification limitations. Empty comparisons do not prove absence of conflict or completeness.

## Trusted integration boundary

Research callers must obtain history through fresh authenticated journal/registry/witness replay and the existing full anchored source/readiness gate. A `RecordingHistory` type alone does not authenticate its contents. A local integration test feeds this module history selected by the witnessed registry after the controlled intake hook; it preserves earlier comparison digests after later capture. This step does not yet publish protected comparison artifacts or connect an authenticated UI/API. Protected findings-runner integration and encrypted append-only finding/correction storage remain separate pending work. Do not run the pure API over caller-supplied history and call it an authenticated audit.

## Fixture evaluation

`evaluate_cases` accepts explicit immutable `BenchmarkCase` / `ExpectedPair` annotations. It checks unique case IDs/pairs, available same-dimension evidence and prediction annotation coverage. Its multiclass confusion matrix includes `NOT_EMITTED`; candidate precision/recall/F1 measure candidate classification against these annotations, with unresolved outcomes retained as their own class. Zero denominators produce null, not perfect scores. Required-reason coverage is scored only where reasons were explicitly annotated; an empty reason annotation receives no automatic perfect explanation score. It is reason-presence coverage, not independently reviewed explanation correctness.

Twenty hand-authored toy cases cover event differences, agreement, interval overlaps, expiry, future dates, end-day ambiguity, blank/ambiguous fields, concurrent restrictions and reported custody. Eighteen annotate eligible pairs; two intentionally expect no emitted comparison. Correction/withdrawal/late-arrival boundaries, provenance, ordering, malformed inputs and scorer false-positive/false-negative accounting have separate unit tests. Fixture results and benchmark review notes are included in the installation package for inspection; they are not research findings.

A perfect fixture score demonstrates conformity to these declared test rules only. Independent reviewer annotations, representative real/authorized research cases, sampling protocol, source/date/identity review, held-out evaluation and query performance measurements are still required before reporting research accuracy, precision/recall/F1 or novelty effectiveness. The benchmark digest binds cases to the resulting comparisons and expected labels; it is not a blockchain commitment or public research publication.

## Validation

```bash
uv run python -m pytest tests/test_bitemporal_contradictions.py tests/test_temporal_contradictions.py tests/test_bitemporal_reconstruction.py tests/test_historical_reconstruction.py tests/test_authenticated_recording_history.py tests/test_protected_bitemporal_runner.py -q
```

No Docker container or production database is needed for this pure-policy step. Cryptographic integration tests use disposable local fixtures, not real research execution. Keep intake disabled; research provisioning, witness deployment and fresh RPC readiness remain pending.
