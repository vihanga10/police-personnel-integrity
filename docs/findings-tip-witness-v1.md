# Durable latest-tip witness integration for findings V1

This adds a trusted-backend `WitnessedFindingsRegistry` adapter over the existing encrypted findings registry and the existing durable signed witness protocol. It does not modify the recording witness, registry, findings journal or secure transport. It does not deploy any service, provision keys or enable a live research pipeline.

## Separate findings scope

`findings_scope_anchor(registry_id, ledger_id)` computes SHA256 over a typed canonical `FINDINGS_WITNESS_SCOPE_V1` object. Both UUIDs must be canonical. Configure the existing `DurableTipWitness` and `WitnessClient` with this hash in the protocol's `journal_anchor` field, the findings registry UUID and a separately configured witness ID. This is a distinct findings scope; it is not the recording journal's original evidence anchor or a blockchain transaction.

The wire protocol, encrypted witness artifact policy names and HTTPS path remain the existing recording-witness names. This is deliberate protocol reuse, not a new independent wire format. Typed scope hashing, exact scope/key/profile matching and disjoint key domains prevent a recording witness client from being substituted for the findings witness. Findings registry tips map to existing wire `{sequence, sha256}` tips; a configured new empty registry maps to `None`. No arbitrary registry UUID is accepted from a witness response.

Use a separate enrolled witness store, signing key and service-side encryption/lookup keys for this scope. The adapter rejects witness public keys overlapping registry, recovery, findings writer or reviewer public-key domains. The remote adapter cannot inspect remote private/encryption keys or prove administrative independence: provisioning must independently enforce secret separation, service ownership and restore controls.

## Transport and enrollment

The adapter constructor defaults to exact `HTTPSWitnessTransport` mutual TLS, with the existing signed provisioned profile pinned to repository, findings scope, writer key ID and writer/witness public-key map digests. Plain in-process/callable transport is refused by default. `fixture_transport=True` is an internal isolated-test option; never expose it or the configured objects in a user request or operational API.

The service uses existing explicit one-time enrollment and durable append-only witness advances. Retain the enrollment hash in independently trusted service configuration. Restart by reopening with that hash; do not call initialize as a missing-file fallback. No production enrollment, certificate or profile is created by this package. Real loopback mutual TLS with ephemeral test certificates is exercised locally.

## Reads, appends and durability

`select()` obtains a fresh signed challenge-bound witness HEAD, replays registry and findings history against it, checks another fresh HEAD inside the registry/journal locks and replays the selection again. Sensitive plaintext is returned only to authorized backend code. A head change, unavailable service, bad signature/nonce/scope/expiry, stale local inventory or rolled-back local store blocks selection; there is no cached-tip or caller-supplied old-tip fallback. Witness freshness is established at validation instants, not a permanent promise that no later append exists.

`append_receipt` and `append_review` fetch a fresh witness predecessor, call the existing guarded registry append, and verify the newly published registry and full findings chain before witness compare-and-swap. Registry and journal directories are fsynced before remote acknowledgment. The registry must advance exactly once and preserve the prior witness-pinned ciphertext prefix. The witness CAS is signed, uses a fresh challenge, advances exactly once and persists its own encrypted signed advancement before acknowledging. A fresh HEAD and local replay are checked after acknowledgment. Successful summaries use `WITNESSED`; matching-content retries against the fresh current head use `ALREADY_WITNESSED` and do not append another entry.

A witness failure or local durability failure does not roll back or erase newly published local files. There is no distributed atomic transaction across journal, registry and service. No successful witnessed result is returned until the protocol completes; surviving partial publication blocks ordinary reads/appends until explicitly authorized reconciliation. If the witness committed but its response was lost, a fresh HEAD authenticates that completed tip and the original identical operation can retry idempotently. Concurrent conflicting CAS histories fail closed and require investigation; this module does not overwrite a divergent remote/local branch.

## Guarded recovery

`authorize_recovery` invokes the existing trusted recovery signer helper with the fresh witnessed registry predecessor, exact pending journal/registry pins and operation, both current artifact inventories, configured key maps and a bounded expiry. It rejects a witness head change while issuing the authorization. This is a configured recovery-signing capability, not a personnel action-date authority decision.

`recover` verifies the signature/time/scope and requires the signed old registry tip to equal the current fresh witness head. Existing registry recovery handles either one complete finding waiting for registration or one complete registered tip waiting for witness acknowledgment. The adapter then verifies and fsyncs local history and acknowledges the new registry tip through CAS. No expiry waiver, local latest-file guess, deletion or overwrite occurs.

An old recovery authorization is rejected after the witness has advanced. For a lost response after witness commit, use fresh selection and identical operation retry rather than reapplying that old predecessor authorization. Incomplete/corrupt ciphertext, unexpected staging artifacts, multiple pending advances or divergent branches require a separate trusted repair procedure; this module does not authorize their removal.

## Threat boundary and research meaning

A separately intact service tip detects rollback of the findings journal and registry together, including a complete valid old prefix. This integration does **not** detect an administrator rolling the witness store back along with both local stores. Protect the witness independently with service administration, durable backup/restore controls and monitoring; never silently re-enroll it. The retained enrollment hash protects enrollment identity, not rollback of a complete old advancement prefix.

Witness scope and enrollment must be provisioned for the correct research ledger; signing key allowlists do not establish independent source custody or truth of personnel evidence. Existing findings receipts retain their original producer claims. This adapter verifies stored chain/freshness and does not rerun protected source readiness or issue a fresh algorithm receipt. Protected producer-to-findings capture, temporal reviewer authority, scoped UI access and independent research evaluation remain pending.

Outputs remain `accepted_state=null`, `findings_anchored=false`. The witness protocol does not anchor findings to either blockchain and does not accept reported contradiction candidates as true. No CSV event date becomes an invented system date. No RPC, wallet, research database or source-anchor operation is performed. RPC 1 remains deferred; no live research has run.

## Validation

New disposable tests cover explicit empty enrollment, restart/full provenance, correction/review/retry, single and simultaneous local rollback, outage refusal, signed recovery of both interrupted phases, lost response before/after witness commit, rejected recovery/signature/challenge/configuration changes, missing enrollment, mid-selection witness advance, recording/findings scope isolation, local fsync failure, recovery-issuance head changes and actual loopback mutual TLS plus service restart. Existing registry, findings-journal, durable witness and secure transport suites accompany the new adapter tests.
