# Existing-data baseline and observation recording journal

## Research meaning

This addition starts a new encrypted observation journal for one candidate
officer, preserving state claims derived by the current source adapter from
the original authenticated anchored snapshot. Its baseline time is the new
recorder observation time after extraction, assigned by the backend UTC clock.
It is not the original intake time, transaction-start time, CSV event date or
the earliest instant the research system knew those facts. Queries before this
baseline are rejected. Earlier evidence may have existed; this journal makes
no claim that it did not. Old archives, datasets, database rows and anchors
remain unchanged. Effective dates in each source claim remain unchanged.

The existing signed-history verifier's `EMPTY_AT_START` contract remains
unchanged. Existing evidence is handled under a distinct policy,
`OBSERVED_RECORDING_JOURNAL_V1`, and never relabeled as an empty origin.

## Protected baseline entry

`create_baseline(args, repo, revision, officer_uid, root, signer, key_id,
recorder_keys)` invokes the existing full snapshot replay loader and its fresh
live-readiness gate. It derives the complete supported state-claim inventory
for the selected candidate subject using `historical_source_claims.source_claims`.
Unsupported sources remain part of original evidence, but are not silently
converted into state claims. Source subjects, classifications, uncertainty
issues, dimensions, values, effective dates and destination references retain
their existing interpretation. Candidate identity remains unaccepted.

`create_loaded_baseline` is an internal trusted-backend boundary for a snapshot
already authenticated by that full loader. Never expose it to request-supplied
snapshots. A permit alone cannot authenticate arbitrary catalog dictionaries.
The baseline checks the unchanged catalog/bindings and fresh permit immediately
before each publication, including after encryption and temporary-file staging.

The recorder signing key must match its pinned public key and must not reuse
any supplied identity encryption or lookup secret. No production signing key
is generated, written or uploaded by this package. Both supplied encryption
key copies must recover each artifact identically. Production callers retain
the existing independently protected primary/backup key-file controls.

## Separate committed-evidence authorization

`append_observation` requires a signed authorization under policy
`COMMITTED_CLAIM_OBSERVATION_AUTHORIZATION_V1`, issued by a separately pinned
authority key. Recorder keys and committed-evidence authority keys cannot
overlap. This package implements the consumer, not that authority's issuer.

The trusted issuer must inspect the actual committed evidence version, its
provenance and selected evidence epoch before signing. Its payload binds the
baseline file hash, complete claim, source key, immediate predecessor ID,
withdrawal flag, evidence-epoch SHA-256 and readiness reference. It asserts
`COMMITTED_VERSION_VERIFIED` and has a fixed 600-second validity interval.
Prepared/uncommitted state, future or expired approvals and changed payloads
are rejected. Signatures authenticate issuer assertions, not source truth or
independent proof of SQL/Mongo commit. Key authorization, revocation and the
actual production post-commit issuer/hook remain integration work.

An authorization is not a research audit permit. The old anchored-snapshot
permit is never extended to authorize changed evidence. New evidence readiness
must be assessed by the independent committed-evidence authority, and real
research execution still needs its own correctly scoped fresh authorization.

The recorder assigns observation time with its UTC clock. There is no caller
parameter for an old system recording time. Observation means the recorder
has seen authorized committed evidence, not that this is the first historical
database visibility instant or the precise filesystem durability instant.
Backwards clocks and non-advancing correction observations fail. Clock trust
and a single trusted writer process configuration remain operational duties.

The existing `RecordingHistory` validates corrections, gaps/forks, stable
source/dimension/officer and unchanged withdrawal claims before publishing any
new event. New independent claims can be recorded without superseding another
claim. Withdrawals and replacements leave predecessors preserved.

## Durable storage and recovery

An existing private, owner-only directory outside the repository is required.
Symlink paths and public artifact permissions are rejected. An advisory lock
on the directory serializes cooperating writers on macOS/Linux. This protects
against concurrent cooperating appends, not a malicious filesystem owner.
Paths and key configuration are trusted backend inputs, not API parameters.

Baseline, events and checkpoints are individually signed and encrypted. The
files contain no plaintext personnel identifiers or values. Each completed
checkpoint contains exact ordered event filenames and SHA-256 fingerprints
of their file bytes. A changed JSON encoding also changes its fingerprint.
The journal chain additionally binds signed receipt identities. Every artifact
is staged privately, flushed and published through a non-overwriting hard
link, then its directory entry is flushed. Existing artifacts are never edited.

A baseline publication followed by checkpoint failure leaves an incomplete
initialization. An event publication followed by checkpoint failure leaves
an uncertain, uncheckpointed event. Further appends refuse that state. No
checkpoint is treated as completed merely because the event exists. The
operator must use a separately designed authenticated recovery process; this
package deliberately provides no discard, overwrite or automatic repair.
An I/O error after a successful hard link may leave a published artifact even
if the operation reports failure. Inspect preserved artifacts rather than
retrying blindly. Future correction hooks must not acknowledge a complete
research recording workflow until the new checkpoint and its trusted pin
have been durably recorded.

Creation/appending returns only journal/checkpoint hashes, an observation
time and non-personal artifact names (plus the new opaque version ID on append).
Store the baseline hash and latest checkpoint filename/hash independently in
a trusted durable registry. `load_checkpoint` requires those caller-supplied
pins and recovers both encrypted key copies before signature/lineage validation.
Do not calculate expected pins from the untrusted files being loaded.

The latest trusted pin prevents rollback. Appending with a stale checkpoint is
also refused if newer/uncheckpointed events exist. Deleting a later checkpoint
and its events cannot be detected from a self-contained old prefix without
an independent latest pin; the independent registry is therefore mandatory.
Historical checkpoint reads are allowed for archived verification and do not
authorize appending to an old head. The reader does not enforce registry
freshness on its own. No multi-file transactional database or distributed
writer guarantee is claimed.

## Query scope

`query_observed_journal` uses the existing V2 reported bitemporal reconstruction
and returns explicit `JOURNAL_OBSERVATIONS_ONLY` coverage with
`source_change_completeness_established=false`, `earlier_knowledge_supported=false`
and no accepted state. Checkpoint coverage ends at the last recorder observation;
issuance does not extend it to an arbitrary later date. Queries outside that
window fail. These returned details belong in protected backend output; no
human disclosure endpoint or research execution CLI is added.

The journal can show what this recorder had observed as of an instant within
its checkpoint. It cannot prove every relevant upstream/database change was
recorded. That stronger completeness claim needs a committed change-capture
hook, source coverage rules and independent checkpoint controls. Consumers must
preserve these flags rather than presenting the history as complete system
knowledge or accepted officer state.

## Tests and remaining integration

Tests use invented fixtures and actual existing permits, signatures, AES-GCM,
recovery, file publication, locking and bitemporal queries. The full real-data
loader is mocked only in the public-entry boundary test; internal fixtures
explicitly stand in for the already-replayed snapshot. No live database or RPC
is used. Test timings are not real-cohort performance measurements.

43 new tests passed. The expanded reconstruction, authority, audit-gate,
receipt/journal and bitemporal suites passed together: 387 tests. The five
bitemporal-related suites total 187 tests for focused Mac installation checks.

Before real use, integrate the post-commit evidence authority, controlled
signing-key lifecycle, durable independent pin registry, authenticated failure
recovery, comprehensive change capture and the protected query runner. Existing
data's earlier intake history remains unavailable unless separately evidenced.
Findings storage/anchoring and human access controls remain later work.
RPC 1 remains deferred during development. No live baseline or research was
created by this package's installation/tests.
