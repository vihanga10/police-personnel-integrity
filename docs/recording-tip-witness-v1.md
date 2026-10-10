# Durable latest-tip witness and checkpoint integration

## What this development step adds

`recording_tip_witness.py` supplies an encrypted, append-only witness service
core, a signed challenge-response client and a registry adapter. It locally
tests durable latest-tip persistence, restarts and interrupted acknowledgments.
It does not deploy an external service, expose a network endpoint, create
production keys or initialize a real research journal. Installation adds three
source/test/documentation files only. RPC 1 remains deferred.

An independently administered witness is the authoritative holder of the
latest registry tip. Active callers obtain a fresh signed tip rather than
selecting an old checkpoint or consulting a cached local pin. Failure to reach
or authenticate the witness blocks operations; there is no offline fallback.

This does not turn the existing observation journal into complete historical
system knowledge. Effective dates and original observation times stay unchanged.
Candidate identities remain unaccepted. Earlier intake dates, source truth and
complete change capture are not established. Protected query-runner integration,
actual committed-evidence issuers/hooks and real research readiness remain pending.

## Independence is an operational requirement

The witness must run under independent administration and storage protection,
outside the journal/registry's rollback or restore domain. A second directory
on the same Mac is only a local development fixture, not independent protection.
Use separate encryption/lookup keys and protected primary/backup copies. The
witness authority signing key must be separate from registry writer, recorder,
committed-evidence authority and recovery authority keys. The registry adapter
checks those public-key domains. The witness service checks its signer against
its pins and forbids reuse of its own encryption/lookup secrets as signing seeds.

If a journal and registry are restored to an old prefix while the independent
witness retains the latest tip, active reads reject the rollback. However, an
attacker restoring the witness authority's own store too can obtain fresh
signatures for that old state. A challenge proves the service answered this
request now; it is not proof that the authority's storage was never rolled back.
This trust limit is explicitly tested. Protect the authority through independent
restore controls, access controls and externally retained audit/anti-rollback
measures appropriate to the eventual deployment. No hardware monotonic counter,
quorum, WORM guarantee or Byzantine witness is claimed here.

Production deployment and authenticated transport require a later reviewed
integration. The injected `exchange` callable is an internal service boundary,
not an HTTP endpoint. Use confidential, authenticated transport with timeouts,
endpoint identity pinning, rate limits and appropriate key authorization when
deploying. Do not expose Python objects, private keys or filesystem paths as
request parameters. Test loopback transport is not a production deployment.

## Service provisioning and persistence

`DurableTipWitness` is configured for exactly one opaque witness ID, opaque
registry ID and independently trusted journal baseline anchor. Keep IDs free
of personnel identifiers. Its root must already exist, be owner-only, outside
the repository and separate from journal/registry storage. Symlinks, non-private
files, unknown artifacts and missing sequence predecessors are rejected.

`initialize()` is an explicit trusted provisioning action on a new empty root.
It writes a signed and encrypted enrollment artifact containing the scope,
writer/witness public-key inventory digests and actual creation time. Retain
its returned file SHA-256 in trusted service configuration. Normal service
restarts supply this as `expected_enrollment`; they never hash the untrusted
file to manufacture an expected pin or auto-initialize missing state. A failed
provisioning with a preserved artifact requires investigation, not blind reset.

Updates are separately signed/encrypted `advance-NNNNNNNN.encrypted.json`
artifacts. Each contains a consecutive sequence, previous encrypted entry's
file SHA-256, full signed registry-writer request and actual witness commit time.
Reopening replays the complete chain, verifies both encryption-key copies,
signatures, pinned scope, archived request validity at original commit time,
clock order and every compare-and-swap predecessor. This is logical append-only
storage, not physical protection against filesystem-owner deletion.

Cooperating service writers serialize with an advisory directory lock. Updates
use the existing private staging, file flush, non-overwriting hard link and
directory flush publisher. A current operation excludes only its own temporary
file during inventory checks. Uncertain stages from other operations remain
preserved and block use. No automatic deletion or partial-stage promotion exists.

## Authenticated protocol

Registry-writer requests use `RECORDING_TIP_WITNESS_REQUEST_V1`; witness replies
use `RECORDING_TIP_WITNESS_RESPONSE_V1`. Both use the existing signed envelope
`{key_id, payload, signature}` over canonical `[policy, key_id, payload]`.

| Operation | Signed request | Signed response |
| --- | --- | --- |
| `HEAD` | Scope, fresh random 256-bit nonce, `expected_tip=null`, `proposed_tip=null`, issued/expiry times | Same scope/operation/nonce, exact signed-request digest, authoritative current tip, `HEAD` status and response times |
| `CAS` | Same bindings plus exact expected tip and proposed next tip | Exact proposed tip, `COMMITTED` status and fresh challenge bindings, only after durable publication |

Requests and responses have a fixed 60-second validity interval. Canonical UTC
times are required; client and service clocks must be trusted and synchronized.
Future, expired, malformed, untrusted or wrong-scope messages fail. Responses
must also arrive before the original request expires. The client passes a copy
to transport so in-place mutation cannot replace its original challenge.
Cached replies cannot satisfy a new nonce/request-digest binding.

A tip is exactly `{"sequence": positive_integer, "sha256": lower_case_SHA256}`;
`null` represents explicitly enrolled empty witness state. Boolean sequence
values are rejected. A CAS may advance exactly one entry from the service's
current tip. Conflicts, jumps and forks fail. A fresh retry of the exact same
already-committed transition is idempotent and does not append another artifact.
Archived requests may expire after commit without invalidating stored history.

The service authenticates the registry writer's assertion about a tip. It does
not have journal plaintext or independently replay personnel evidence. The
trusted registry adapter performs that validation before issuing the CAS.
Possessing a registry writer signing key is therefore a significant authority;
transport signatures alone do not prove source truth or research permission.

## Registry adapter and interruption handling

`WitnessedCheckpointRegistry(registry, client)` checks registry identity,
baseline anchor, writer pin inventory and witness authority key separation.
Its active methods use fresh witness state rather than request-supplied tips:

| Method | Behavior |
| --- | --- |
| `select()` | Fetch head; lock and fully verify matching registry/journal; fetch another fresh head; reject advancement or artifact changes |
| `register(checkpoint_file=..., checkpoint_sha256=...)` | Register against fresh witness head, fully replay completed head, flush local directories, CAS witness, verify fresh acknowledgment and local state |
| `recover(authorization, recorder_signer=..., recorder_key_id=...)` | Use fresh head with the existing separately authorized event/checkpoint recovery, then witness its new registry tip |
| `reconcile(authorization)` | Use fresh head and existing separately signed recovery approval to acknowledge an already-published registry entry |

Before acknowledging a new tip the adapter locks registry then journal,
verifies the complete selected head and preserved witness prefix, flushes both
directories and holds those cooperating-writer locks across witness CAS and
confirmation. The service never calls back into the registry or acquires its
locks. Transport must respect that lock hierarchy and have bounded timeouts.

If the witness commits and its response is lost, the operation raises rather
than claiming success. A new fresh read can recover the already-durable tip
after restart; no new checkpoint or duplicated witness update is necessary.
If publication/transport fails before witness commit, the published registry
entry is preserved, while normal active reads/writes reject the mismatch.
Use a separate exact-byte recovery approval and `reconcile`; do not overwrite
the old witness tip or infer authority from the new local files alone.

A directory-flush failure after hard-link publication can leave a complete
witness artifact. Subsequent fresh reads flush the directory and fully verify
the ledger before returning a reply. Repeated flush failures remain blocking.
If a request expires after a successful commit, no response is accepted, but
the durable tip remains available to a later fresh request. Multi-entry jumps
and retroactive witness bootstrap are deliberately unsupported by this adapter.
Existing local registry history must be integrated through a separately reviewed
bootstrap when it is more than one entry ahead of an enrolled witness.

## Install and test on your Mac

The clean `feat/identity-resolution` branch must contain committed ancestor
`050a113`. Extract `durable-tip-witness-step.zip` into Downloads, then:

```bash
cd "$HOME/Downloads/durable-tip-witness-step" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
```

`--check` writes nothing. After it passes:

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" &&
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_recording_tip_witness.py \
  tests/test_recording_checkpoint_registry.py \
  tests/test_observed_recording_journal.py \
  tests/test_authenticated_recording_history.py \
  tests/test_protected_recording_review.py \
  tests/test_bitemporal_timestamp_binding.py \
  tests/test_bitemporal_reconstruction.py -q
```

Expected focused result: **281 passed**, including **52 new witness tests**.
The expanded reconstruction, authority, audit-gate and registration journal/
receipt regression set totals **481 tests**. These use invented fixtures,
real signatures, encryption, durable private files and concurrency. No live
database, external service, RPC or research is executed. Test timings are not
research-cohort performance measurements.

After successful local testing and source-diff review:

```bash
cd "$HOME/Developer/police-personnel-integrity" &&
git add backend/app/identity/recording_tip_witness.py \
  backend/tests/test_recording_tip_witness.py \
  docs/recording-tip-witness-v1.md &&
git diff --cached --check &&
git commit -m "Add durable latest-tip witness and guarded checkpoint integration"
```

This development addition leaves existing modules/CSVs/databases/anchors
unchanged. Independent service deployment, transport security, key lifecycle,
source change capture, protected query execution and later findings/UI work
remain pending. Item 2 is not yet production-complete; RPC 1 remains deferred.
