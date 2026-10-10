# Protected temporal authority for findings reviews V1

This step adds an authenticated assessment and protected recording adapter for human findings-review decisions. It reuses the existing action-date actor-history bridge and temporal authority/delegation evaluator. It changes no research data, database schema, wallet, RPC or blockchain. No services, keys, human login endpoint or storage are provisioned. RPC 1 remains deferred.

## Why signatures are insufficient

A reviewer key allowlist authenticates a signature but does not establish officer identity, role, geographic scope, active service, legal power or delegation validity at the review date. This adapter requires all of those assessments needed for a supported authority path, backed by exact retained evidence bytes and a separately trusted, scope-limited assessment signature. It never infers review power from a reported rank, SP-or-above status, a CSV label or possession of a signing key.

`REVIEW_FINDING:<decision>` is an application action identifier, not an assertion that Sri Lankan law grants that power to any particular rank. Governing rules, role memberships, scope memberships, delegation instruments and completeness are supplied as explicitly assessed facts by an independently configured assessment workflow. Production instruments, assessor eligibility and source custody must be checked before enrolling assessment keys. Fixture rules in tests are invented and establish no police-law conclusion.

## Trust configuration and compatibility

The findings journal gains optional `authority_keys`, `reviewer_identities` and `authority_scopes` constructor configuration. These are backend-owned configuration, never user-request parameters. Authority keys are pinned Ed25519 public keys; reviewer identities bind configured reviewer key IDs to immutable officer UUIDs; authority scopes give each assessor an explicit tuple of permitted target-scope IDs. All three must be present together. Assessor signing keys must be separate from reviewer, writer, registry, recovery and witness signing keys. Signing seeds cannot reuse the journal's encryption or lookup secrets.

The registry's key pins bind this authority configuration when enabled. Without authority configuration, existing legacy journal/registry/witness behavior and old pins remain unchanged. Legacy V1 review records remain replayable and are not relabeled as temporally authorized. With authority configured, new review appends require the versioned authorized-review intent and a trusted publication callback; the old unassessed-intent path cannot create a new review. The new protected adapter always refuses legacy intents.

Configure these keys and identities before initializing a new operational findings registry. Adding or changing this configuration on a registry that already contains entries changes its pinned policy and blocks replay. This package provides no policy-migration/key-rotation authorization or bypass; existing deployments would need a separately reviewed migration. No operational findings registry is currently provisioned. The installer updates only exact inspected versions of three existing code files.

## Exact review action and time

`review_request` binds ledger, subject officer, finding UUID, current finding-entry ciphertext hash, producer-receipt ciphertext hash, operation UUID, reviewer UUID and signing-key ID, reported decision, reason, references, target scope, actual review timestamp, original replay context/publication, source catalog/bindings digest and actor manifest/capture-time digest.

Review timestamps must be explicit UTC instants. The assessment issuance timestamp is separately recorded from the backend clock after assessment computation, not copied from the requested review time. Issuance and review must be contemporaneous, and the authorization expires within 600 seconds of the review instant. Authority instruments and actor states use the calendar date in `Asia/Colombo`, retained explicitly in the versioned intent. A review signed near midnight therefore uses the correct Sri Lankan date rather than the UTC date. No date is guessed from a CSV event or replaced with an effective date. New publication must occur within the signed window, at most 600 seconds, and on the same Sri Lankan calendar date. Expired, future-dated or backdated new publication is refused. This conservative same-day rule may require obtaining a new assessment if an attempt spans local midnight.

The subject's membership in the requested target scope is a separate assessed `Fact(True)` citing retained evidence. The reviewer signing-key identity map is checked independently of the packet's assessed identity facts. An assessment for another decision, reviewer, finding, officer, scope, receipt, source version or operation cannot authorize this action.

## Assessment and reviewer signatures

The trusted assessment workflow uses `issue_authority_assessment(snapshot, journal, ...)`. It must first independently inspect and assess identity, dates, state facts, legal/application instruments, scope mappings, delegation powers and coverage. The helper authenticates the configured assessor signer and scope, verifies every evidence byte hash against the typed `AuthorityAssessment`, and binds its actor/date state IDs to `ActorHistory` over the original replayed snapshot. Assessment evidence is bounded (128 references, 8 MiB total), nonempty, base64 encoded inside the subsequently encrypted journal record, and retained in full. There are no plaintext evidence files created by this helper.

This is an explicit trust root: a configured assessor's signature authenticates their assessment statement, not the legal truth of arbitrary bytes. No automatic assessor certification, custody investigation, revocation service or governing-law lookup is implemented. Do not give ordinary reviewers assessor signing capabilities or accept keys supplied by a client.

The helper may produce signed INVALID or CANNOT_VERIFY assessments for investigation, but `issue_authorized_review_intent` refuses them as review permissions. Only VALID evaluated paths can produce a protected reviewer-signed intent. Delegation reuses the existing continuing-authority convention: issuer authority must hold at both issuance and action dates, with half-open validity intervals, revocation, non-expansion of powers/scopes and bounded traversal. Missing or conflicting facts cannot be upgraded into permission.

The authorized review retains the complete independently signed assessment, evidence bytes, actor/date reconstruction links, chosen timezone and computed authority decision, including reasons, evidence references and successful paths. The reviewer signs all of it. Replay verifies both signatures, configured identity and scope pins, evidence hashes, action bindings and the temporal decision again. The authorization window is checked against the recorded entry time; historical replay does not treat an old completed review as a new current authorization.

## Protected recording and exact target

Operational `record_review(args, repo, revision, findings, *, intent, expected_authority_sha256, finding_receipt_path)` requires the exact findings adapter with mutual TLS and fixture mode disabled. It calls the existing full verified snapshot loader, including original-anchor replay and fresh live readiness. There is no RPC/readiness waiver. The approved assessment digest must come from a trusted independent assessment-selection/approval channel, not merely be copied from an untrusted client declaration.

The internal `record_loaded_review` is a trusted full-loader/test boundary and must never receive a request-supplied snapshot or configured objects. Each operational invocation, including retries, obtains fresh readiness. A permit is repeatedly authenticated and never extended in place.

Before publication, the adapter verifies the exact signed review and approved assessment pin, replays the original actor/date histories, matches the signed reconstruction links, recomputes authority, and obtains fresh witness-backed findings selection. It targets only the latest FINDING/CORRECTION entry for that finding. The original producer receipt must be available privately; both recovery keys must yield the exact stored finding, its ciphertext SHA must equal the signed request and journal entry, and its original publication/context must match the replayed evidence. Producer and current reviewer code revisions may differ; original evidence-context fields and publication must agree. The signed review retains the current review code context and the exact older producer receipt SHA.

The callback is forwarded through witness and registry to the journal. After encrypted staging, immediately before nonoverwriting review publication, it checks the permit, all source/actor/configuration digests, signed assessment and evidence, reconstructed actor states, receipt bytes/result, exact time window and fresh witness predecessor again. A correction, changed source, modified receipt, expired permit, changed trust mapping or unavailable/advanced witness blocks new publication.

Existing registry publication, directory fsync, signed witness compare-and-swap and fresh acknowledged replay must then complete. The returned summary is redacted and leaves accepted personnel state unset; a review does not overwrite evidence or make findings blockchain-anchored.

## Retries and recovery

Operation retries require the exact same signed authorized intent, approved assessment and freshly replayed snapshot context. A completed review may be returned as ALREADY_REVIEWED after fresh witnessed selection and authority replay; this audits an existing record and appends nothing, even if the original short authorization window has elapsed. A new review cannot use an expired token. Later corrections do not erase earlier signed reviews or invalidate their audit replay; a new review must target the latest finding head.

Partial writes are retained. No distributed atomic transaction spans journal, registry and witness. A lost response after witness commit is recognized through fresh HEAD and identical retry. A locally registered entry lacking witness acknowledgment blocks ordinary selection and requires the existing separately signed inventory-pinned recovery authorization before retry. The recovery signer does not create new reviewer authority; it reconciles the exact already-signed entry. No automatic deletion, latest-file guessing, re-enrollment or unsigned rebasing occurs.

Callers must not hold recording or findings locks when entering this adapter. No recording-store lock is acquired by this review adapter; it reads the retained producer receipt and the original snapshot. Lower storage APIs are trusted implementation boundaries, not public authorization endpoints.

## Coverage and research limits

Actor histories here are reconstructed from the original replayed anchored universe and linked to separately signed assessments. This step does not automatically replace them with later recording-journal actor versions or claim complete bitemporal actor-state coverage. New assessed evidence can support explicit dated state facts, but the original reconstructed state version remains visible. A future intake/assessment-history adapter must authenticate any later versioning and key rotation; it cannot silently swap actor evidence.

Tests cover direct and delegated paths, rejected rank/role/scope/activity/identity/date/rule constraints, missing coverage, unsigned or changed evidence, wrong identity/pin/target/receipt, correction head changes, final-publication guards, configuration drift/key overlap, legacy refusal, unchanged retry, replay beyond expiry, both witness-interruption phases, explicit local-midnight semantics and actual loopback mutual TLS with a mocked full loader. Fixtures do not prove independent research accuracy or production legality/readiness.

Production assessor and reviewer provisioning, authenticated/scoped UI, witness deployment, legal instrument validation, independent evaluation, findings commitments on both chains and live execution remain pending. Existing CSVs, databases and original anchors remain unchanged; RPC 1 stays deferred.
