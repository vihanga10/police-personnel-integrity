# Authenticated recording history verifier

## What this addition does

Verify Ed25519 recorder signatures, exact ordered version receipt membership,
hash-chain continuity and a separately pinned coverage checkpoint. Convert the
verified claims into the existing immutable `RecordingHistory`; its existing
constructor verifies immediate correction predecessors, strict correction
times, stable officer/source/dimension and unchanged withdrawal claims.

The existing `query` then selects versions using system recording time and
projects their reported effective dates using reconstruction policy V2.
Independent claims remain independent. Corrections and withdrawals preserve
old versions. No accepted state or source-truth claim is introduced.

## Trust boundary

This is a pure trusted-backend verification adapter, not a production recorder,
database ingestion hook, endpoint, receipt store, permit issuer or chain writer.
It adds no command that performs real research. No signing secret is generated
or saved outside synthetic test fixtures.

Trusted backend inputs are pinned recorder public keys, a journal context,
authoritative source scope and the expected coverage-envelope SHA-256. Never
derive these expected values from incoming receipts themselves. The checkpoint
pin must originate in an independently authenticated checkpoint/readiness
process. Passing `digest(coverage)` from untrusted input defeats the independent
pin requirement. Signer authorization/revocation and checkpoint rollback
protection belong to that trusted process and are not provided here.

A valid signature authenticates an authorized recorder's assertion. It cannot
prove that a recorder told the truth, that all upstream systems were covered,
or that recording happened at a particular historical instant. An independent
source registry and recorder policy must justify the asserted scope, committed
visibility semantics and coverage. Existing chain audit permits are scoped to
the original snapshot; this adapter does not authorize later versions under
those old permits. Real execution needs a separately integrated readiness and
evidence-epoch check before authenticated histories can enter protected queries.

## API

```python
history = authenticate_recording_history(
    receipts, coverage,
    trusted_keys=pinned_ed25519_public_keys,
    expected_context=trusted_journal_context,
    expected_scope=trusted_officer_source_scope,
    expected_coverage_digest=independently_pinned_checkpoint_sha256,
)
result = query(history, effective_on=effective_date, known_at=knowledge_time)
```

`now` defaults to the UTC system clock. Its optional override is for controlled
tests/trusted callers, not request parameters. Results should remain inside the
existing protected backend; no plaintext disclosure endpoint is added.

## Signed format

Each envelope has exactly `key_id`, `payload`, `signature`. Signature is base64
Ed25519 over UTF-8 canonical JSON `[POLICY, key_id, payload]`, using the existing
`evidence_bundle_v2.canonical` serializer. Key ID is bound into the signature.
Public keys are pinned 32-byte values. Policy is
`AUTHENTICATED_RECORDING_HISTORY_V1`. Strict schemas are defined in source.

Context contains `journal_id`, `recorder_policy_sha256`,
`source_registry_sha256`. Scope contains one canonical `officer_uid`, sorted
unique `source_keys` and all five reconstruction `dimensions`. Every event and
coverage payload repeats this exact scope and context.

VERSION receipts include unique receipt/version IDs, consecutive sequence
numbers starting at 1, the preceding signed envelope's SHA-256 (null first),
the complete reported Claim, source key, recording/issuance instants,
predecessor version ID and explicit withdrawal flag. The only supported time
semantics is `RECORDER_OBSERVED_COMMITTED_VERSION`. PostgreSQL transaction
start, CSV event dates and derived timestamp-review receipts are refused.
All instants use canonical UTC ISO strings. This policy must be backed by an
actual recorder observing committed versions; a caller must not relabel old
metadata to satisfy the string check.

COVERAGE signs start/end, issuance, the exact ordered receipt-envelope hashes,
checkpoint reference, `ALL_COMMITTED_VERSION_EVENTS_IN_SCOPE` and an
`EMPTY_AT_START` baseline. Versions must arrive strictly after coverage start.
No events, including prior versions of claims, may be assumed missing before
that boundary. Queries at the start therefore see an empty history.

This first verifier deliberately supports only a justified empty origin.
Existing data with unknown earlier history requires an authenticated baseline
design before it can be used. Never mark it empty to make tests pass. No historic
system timestamp is inferred from current database rows or receipt creation.
Empty signed histories are permitted when the trusted recorder legitimately
attests zero events in the independently pinned scope/interval; that is not a
statement that an officer had no real-world state.

## Validation and remaining integration

52 new tests exercise real signatures and queries with fixture signing keys.
The four related suites total 144 passing local tests. They cover signature and
key-ID tampering, missing/extra/reordered events, invalid timestamp semantics,
unusable coverage, gaps/forks, changed withdrawal claims, independent claims,
correction visibility and stable earlier query digests. These are local
algorithm tests, not an evaluation of research accuracy.

Still needed for real use: a trusted post-commit recorder, append-only receipt
storage, justified existing-data baseline, controlled signing keys and source
scope, authenticated checkpoint pin/rollback protection, and protected query
integration with fresh readiness for the selected evidence epoch. RPC 1 remains
deferred. Existing CSVs, databases, wallets and anchors remain unchanged.
