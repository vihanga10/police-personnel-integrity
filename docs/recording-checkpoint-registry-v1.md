# Independent checkpoint registry and authenticated recording recovery

## Meaning and scope

This additive module implements a separate encrypted checkpoint registry for
one observation journal and recovery of authenticated published artifacts.
It preserves the original baseline, events, checkpoints, claims, effective
dates and observation times. It does not create historical intake dates,
establish complete upstream change capture, accept candidate identities or
authorize real research execution. Existing CSVs, databases, wallets and
blockchain anchors are unchanged. RPC 1 remains deferred.

The registry records which checkpoint is the current registered observation
head. Checkpoint selection verifies the entire registered prefix and every
preserved checkpoint, rather than accepting a caller-selected old journal
checkpoint. Unknown files, pending events, altered bytes and stale selections
block active reads. Archived low-level checkpoint reads still exist in the
older module; production active reads must use this registry boundary.

## Independent trust and storage

`CheckpointRegistry` is an internal backend API. Paths, registry identity,
baseline anchor, public-key pins and encryption configurations come from
trusted backend configuration. Neither directories nor keys are request inputs.
Both directories must already exist, be owner-only and outside the repository.
The registry cannot equal, contain or be inside its journal directory. Files
must be owner-only regular files; symlinks are rejected.

Registry encryption/lookup secrets must be separate from journal secrets.
Primary and backup copies must recover identical plaintexts. Ed25519 public-key
sets for registry signing, journal recording, committed-evidence authorization
and recovery authorization must be pairwise disjoint. Registry signing seeds
cannot reuse supplied encryption/lookup secrets. No production keys or recovery
authorizations are created by installation or by this module.

Every registry entry is signed under
`INDEPENDENT_RECORDING_CHECKPOINT_REGISTRY_V1`, then encrypted. Its payload
binds registry identity, baseline anchor, consecutive sequence, previous entry's
exact encrypted-file SHA-256, selected checkpoint filename and file SHA-256,
ordered event inventory, preserved checkpoint map, observation coverage end,
actual registration time and operation. Changing even JSON whitespace changes
the pinned file fingerprint. Successive entries must extend the observation
history without dropping or changing earlier fingerprints. This is logical
append-only storage with authenticated integrity; it is not a hardware WORM
store or a guarantee against destruction by a filesystem owner.

**The latest registry tip must also be durably stored in an independent trusted
witness.** The tip is exactly `{"sequence": positive_integer, "sha256": file_hash}`.
Use the caller's trusted latest tip, never a hash calculated from untrusted
local files. `None` is allowed only for a trusted initial empty registry.
The original baseline file hash must likewise come from independently trusted
publication state. The external witness and its persistence protocol are not
implemented by this package.

Restoring an old journal and old registry is detected when the witness retains
the latest tip. Restoring the witness to the same old tip defeats this local
check. A second folder on the same computer does not solve that problem by
itself. Protect the witness against rollback and acknowledge a recording only
after its returned registry tip is durably committed there.

## Normal registration and reading

`register(expected_tip, checkpoint_file=..., checkpoint_sha256=...)` verifies
the trusted registered prefix, the complete completed checkpoint and all
preserved events. It appends a registry entry and returns its new tip. Repeating
registration of the same verified head with its current trusted tip is
idempotent. Registering an old checkpoint cannot remove newer observations.
Unregistered alternative checkpoints require authorized recovery.

`select(expected_tip)` returns the authenticated current checkpoint/state and
its pins. It rejects an out-of-date independent tip, incomplete journal head,
unregistered checkpoint, missing predecessor or changed artifact. Pass the
returned state to the existing `query_observed_journal` for local reported
bitemporal queries. This does not add a public search endpoint or a protected
research runner. Production consumers still need a fresh correctly scoped
permit and must retain the observation-only coverage flags.

Registry operations lock registry then journal directories in a fixed order.
The existing ordinary journal writer locks the journal directory. Locks
serialize cooperating macOS/Linux writers; arbitrary filesystem mutation and
noncooperating writers are outside that guarantee. Publication uses a private
staging file, flush, non-overwriting hard link and directory flush. Final checks
exclude only that writer's own active temporary file. They do not ignore
unrelated staging files.

## Recovery authorization

`recover(expected_tip, authorization, recorder_signer=..., recorder_key_id=...)`
requires a separately pinned Ed25519 authorization under
`RECORDING_CHECKPOINT_RECOVERY_AUTHORIZATION_V1`.
The signed payload has exactly these fields:

| Field | Requirement |
| --- | --- |
| `policy`, `kind` | Recovery policy above, `RECOVERY` |
| `registry_id`, `journal_anchor` | Trusted configured registry and independently pinned baseline |
| `registry_tip` | Caller’s old independently trusted tip, or authorized initial `null` |
| `artifact_inventory` | Exact journal filename-to-file-SHA-256 map |
| `registry_artifact_inventory` | Exact registry filename-to-file-SHA-256 map |
| `checkpoint_file` | Existing checkpoint to adopt, or `null` to create a replacement |
| `issued_at`, `expires_at` | Canonical UTC timestamps; fixed 600-second interval |
| `status` | `RECOVERY_AUTHORIZED` |

The receipt envelope uses the existing `key_id`, `payload`, `signature`
format. Its signature covers canonical `[policy, key_id, payload]`.
The trusted recovery issuer must independently inspect the failure, preserved
artifacts and latest witness state before approving exact bytes. This package
provides the consumer only. Signature possession alone does not establish
source truth, commit status or permission to create new evidence.

Scope, hashes, signatures, chain, correction lineage, canonical observation
times and each nested committed-evidence authorization are independently
validated. A recovery signature cannot make invalid evidence valid. Original
committed-evidence approvals are validated at the original observation time;
their later expiry does not erase a valid archived observation. Recovery's own
approval must still be current, including immediately before publication.

## Supported interruptions

| Preserved state | Authorized action |
| --- | --- |
| Baseline published, initial checkpoint missing | With independently retained baseline anchor and trusted empty-registry state, authenticate baseline and append a checkpoint/first registry entry |
| Event published, checkpoint missing | Replay authenticated event suffix, append a replacement checkpoint and registry entry |
| Completed checkpoint published, registry entry missing | Register the completed checkpoint normally; recovery can also adopt the approved checkpoint |
| Valid alternative checkpoints exist | Recovery authenticates and preserves every checkpoint, then registers one full head |
| Registry entry published, caller’s witness update absent | `reconcile_published_tip` validates authorized exact bytes and old trusted prefix, then returns the preserved published tip |
| Unknown temporary files, missing/invalid evidence, sequence gaps or forks | Reject; preserve files for separate investigation |

For a replacement checkpoint, its issuance time is the actual recovery time,
while its coverage ends at the original last observation. Recovery never
extends coverage to the current clock, renews an old evidence authorization,
creates an evidence version or removes a predecessor. The registry records
the actual new registration time separately.

`reconcile_published_tip(expected_tip, authorization)` does not create, edit
or delete artifacts. Approval must select the already published full head and
bind both exact inventories plus the old trusted witness prefix. It verifies
the complete signed registry chain and current journal head, flushes both
directories, rechecks approval/time/inventories and returns the published tip.
Persist that tip independently before acknowledging recovery.

An I/O failure after a hard link can leave a published artifact even when an
operation raises. A failed registry publication can leave a valid replacement
checkpoint for subsequent registration. Reconciliation does not acknowledge
durability if a directory flush fails. A hard crash can leave uncertain staging
files; they block these APIs. Automatic cleanup, promotion of partially staged
files and universal crash repair are deliberately not implemented.

## Installation and local validation

Extract `checkpoint-registry-recovery-step.zip` into Downloads. On the clean
`feat/identity-resolution` branch, with committed ancestor `79ebd2f`, run:

```bash
cd "$HOME/Downloads/checkpoint-registry-recovery-step" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
```

The compatibility check writes nothing. Once it passes:

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" &&
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_recording_checkpoint_registry.py \
  tests/test_observed_recording_journal.py \
  tests/test_authenticated_recording_history.py \
  tests/test_protected_recording_review.py \
  tests/test_bitemporal_timestamp_binding.py \
  tests/test_bitemporal_reconstruction.py -q
```

Expected focused result: **229 passed**, including **42 new tests**. The broader
reconstruction, action authority, audit gate and registration receipt/journal
regression set totals **429 tests**. Tests use invented fixtures and actual
Ed25519, encryption, private files, locking and failure injection. No real
database, RPC, personnel query or research execution is performed. Synthetic
test timings are not cohort performance measurements.

After reviewing the source diff and successful local output:

```bash
cd "$HOME/Developer/police-personnel-integrity" &&
git add backend/app/identity/recording_checkpoint_registry.py \
  backend/tests/test_recording_checkpoint_registry.py \
  docs/recording-checkpoint-registry-v1.md &&
git diff --cached --check &&
git commit -m "Add independent checkpoint registry and authenticated recording recovery"
```

The installer adds only these three files and refuses existing targets or
changed source preconditions. Production witness integration, authorization
issuers, signing-key lifecycle/revocation, committed change capture and protected
query-runner integration remain pending. Item 2 is still partly complete.
Contradiction evaluation, findings storage/anchoring and scoped human access
remain later research work.
