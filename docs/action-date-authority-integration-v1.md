# Action-date authority integration v1

## Scope

This step connects the existing `ActionReview`, `ActorHistory` and temporal authority evaluator through a pure, versioned adapter. The default remains reported evidence only. It is development and local evaluation, not a completed real-data authority audit.

RPC 1 was identified by the operator as `ethereum-sepolia-rpc.publicnode.com`; a later fresh gate reported historical-state unavailability at fixed block `0xb546e7`. The prior gate `92dc3640-b07f-40fb-b712-69fd8c6e3c60` completed exact dual-chain/live verification, but its permit was subsequently rejected as expired. Neither outcome authorizes a new run. Endpoint resolution is deferred while local development continues. Existing CSVs, evidence, commitments and transaction journals remain preserved.

## Input boundary

`ActionAuthority.review(action, assessment=None)` accepts the existing reported action and actor-history collector. Without assessments it preserves missing dates, unresolved/ambiguous actors and all candidate history links and returns CANNOT_VERIFY.

`AuthorityAssessment` is an explicit typed input packet containing the exact publication digest, original action digest, destination digest, selected candidate officer_uid, resolved target scope, action identity/date semantics, coverage, governing rules, delegation instruments and dated actor-state assessments. Every cited assessment reference must appear in its evidence-digest inventory. Each state assessment must match the actual generated state ID for its officer/date pair. Mixed evidence versions, unknown selected actors, duplicate instruments, orphan packets and unused state overrides are rejected.

IMPORTANT: this packet is NOT a signature, authenticated assessment document or permission to accept real-world authority. Fingerprint shape validation does not verify referenced document bytes. A future guarded ingestion/runner must authenticate assessment artifacts, verify their content/provenance and assessor authority, bind them to versioned evidence and require a fresh dual-chain permit. This package intentionally supplies no automatic JSON import or real-run switch that could bypass those requirements.

Reported rank and source text do not produce an assessed rule, role, geographic scope or active-service fact. No Sri Lanka Police legal rule is fabricated. The local test labels and instruments are invented fixtures, not legal authority or dataset modifications.

## Evaluation

A direct route uses actor facts reconstructed at the reported action date. A delegated route also reconstructs issuers at issuance and action dates, including parent chains. Missing explicit assessments use the original reported, UNASSESSED actor facts. The v1 continuing-issuer-authority convention comes from the existing evaluator; it is an explicit algorithm convention to evaluate against governing instruments, not asserted law.

The evaluator retains assessed half-open intervals [start,end), revocation dates, power/location subset checks, delegation permission and recipient identity. Cycles/depth and absent parent evidence remain unresolved. Integration traversal is separately bounded. VALID means an assessed input route satisfies the model; INVALID requires an explicitly assessed complete route set with every applicable route refuted. Otherwise CANNOT_VERIFY remains appropriate. A refuted route cannot invalidate a separately successful route.

`evaluate_action_inventory()` evaluates every supplied action, rejects duplicate actions and orphan/duplicate assessment packets, and returns ordered results plus coverage/status/reason aggregates. It does not authenticate/decrypt a saved run, issue a research completion receipt, write findings or access chains. Results include `accepted_authority_claim=false`, `assessment_authenticity_claim=false` and `new_research_audit_executed=false` to keep this boundary explicit. Sensitive detailed outputs belong in encrypted artifacts when a guarded runner is added.

The existing research runner, actor-history runner, their policies and archived replay behavior are unchanged. There is no authority-assessment research execution yet. Bitemporal extension, assessed-rule ingestion, integrated guarded execution, contradiction evaluation, findings storage/anchoring, UI and final evaluation remain separate pending work.

## Installation and local tests

```bash
unzip -q "$HOME/Downloads/authority-integration-step.zip" -d "$HOME/Downloads"
cd "$HOME/Developer/police-personnel-integrity" &&
python3 "$HOME/Downloads/authority-integration-step/install.py" --repository "$PWD" &&
git diff --check &&
cd backend &&
uv run python -m pytest -q --tb=short \
    tests/test_action_authority_integration.py \
    tests/test_action_actor_history.py \
    tests/test_temporal_authority.py \
    tests/test_actor_history_runners.py \
    tests/test_historical_reconstruction.py \
    tests/test_reported_authority_actions.py \
    tests/test_audit_gate.py
```

Tests exercise real collector/evaluator integration, unassessed defaults, assessed direct/delegated fixtures, exact action-date and issuer-date reconstruction, missing issuer assessments, revocation, scope expansion, inactive actors, forbidden delegation, alternative routes, interval boundaries, cycles, ambiguity, version mismatch, missing references, duplicate/orphan inputs, deterministic replay and coverage. Tests do not connect to a research DB or RPC, and are not an independently reviewed accuracy benchmark.

The installer requires the committed actor-history checkpoint `85717bf`, a clean feat/identity-resolution branch and exact source fingerprints. It adds source/test/documentation files only and refuses existing new targets. It does not change source CSVs or any existing algorithm implementation.

## Commit after tests pass

```bash
cd "$HOME/Developer/police-personnel-integrity"
git add \
    backend/app/identity/action_authority_integration.py \
    backend/tests/test_action_authority_integration.py \
    docs/action-date-authority-integration-v1.md
git diff --cached --check &&
git commit -m "Integrate version-bound action-date authority and delegation inputs" &&
git push &&
git status --short --branch
```

Do not repeat the long audit gate for this local development step. A future research run requires source committed, RPC capacity/state support resolved, authenticated assessment inputs and fresh readiness. Source comments explain the boundaries and temporal rules.
