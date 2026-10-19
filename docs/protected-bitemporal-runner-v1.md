# Protected observed bitemporal query runner V1

This additive backend adapter connects reported bitemporal reconstruction to
the original anchored snapshot replay, signed observation journal, checkpoint
registry and fresh independent witness reads. It publishes an encrypted query
receipt outside the repository. It does not accept an officer state as truth.

## Trusted entry and inputs

`app.identity.protected_bitemporal_runner.run_bitemporal_query` takes the existing
snapshot loader arguments, repository and current revision, plus a
backend-configured `WitnessedCheckpointRegistry`. Keyword arguments are
`officer_uid` (immutable UUID), `effective_on` (date), `known_at` (aware datetime)
and `destination` (new file in a separate existing owner-only directory).

The public entry requires `HTTPSWitnessTransport`: TLS 1.3, private CA, client
authentication, exact certificate pins and the previously signed provisioning
profile. Scope and application signing key pins must match the witness client.
It calls the existing `load_verified_snapshot` without exemptions. Both chains'
fresh readiness permit, original commitment replay and recovery remain required.
There is no CLI or web endpoint, request authentication or scoped UI access in
this step. The application must choose all configuration and destination paths;
never accept snapshots, key maps, adapters or transports from an HTTP request.

`run_loaded_query` is an INTERNAL trusted-runner boundary for an already fully
replayed snapshot. A permit alone does not authenticate arbitrary dictionaries.
Tests use this boundary with disposable evidence. In-process witness transports
are accepted there for tests, but refused by the public entry.

## Query and verification

1. Validate the existing short-lived algorithm permit and private output path.
2. Obtain a fresh authenticated witness head, then hold registry/journal locks in
   their established order and replay the exact selected registered history.
3. Match officer, original publication, evidence attempt and destination pins,
   source registry fingerprint and every baseline claim against source replay.
   The baseline code revision may precede the current runner revision; the fresh
   permit remains bound to the current revision. Other context fields must match.
4. Query the immutable history at both dates. The knowledge cutoff must lie
   between the baseline observation and latest recorded observation. Corrections
   supersede one stable claim at their recorded time; withdrawals retain their
   receipt provenance. Earlier query digests remain stable after later arrivals.
5. Encrypt the result with existing primary/recovery material, verify both-key
   recovery, stage and fsync a private file. Recheck permit, unchanged snapshot,
   witness scope/key pins, fresh head and full registry/journal replay immediately
   before non-overwriting publication; fsync the output directory.

The output includes query projections and visible version provenance, the
selected registry tip, checkpoint pin, witness scope and observed coverage. Its
authenticated encryption binding includes the source context, original
publication digest, journal anchor, registry tip and complete result digest.
The returned console summary contains no officer identifiers or source values.
The pure query's `receipt_authenticity_claim=False` remains unchanged: the outer
receipt separately records `authenticated_journal_replay=True`.

## Exact limits

- Coverage is `JOURNAL_OBSERVATIONS_ONLY`, not proof that every source/database
  change was captured. `source_change_completeness_established=False` and
  `accepted_state=None` remain explicit.
- Existing archived evidence becomes known at its newly recorded observation
  time, never at a fabricated CSV event date or historical database commit time.
  Queries before the observed baseline or beyond coverage are refused.
- Fresh witness validation applies at the check instants. A later observation
  can be committed after publication; the result identifies its selected tip
  and does not claim permanent latestness. Participating writers must cooperate
  with the existing locks; arbitrary privileged filesystem mutation is outside
  that guarantee. Independent witness administration and rollback protection
  remain operational requirements.
- Output is an immutable encrypted query receipt, not the later append-only
  findings store or a findings commitment anchored on either chain. It does not
  record a reusable signed witness response; independent offline replay of the
  witness exchange is not established by this artifact alone.
- Publication never overwrites a destination and cleans its own temporary file.
  If directory fsync fails after the final link, a destination may already exist;
  no success is returned. Inspect it through an authenticated recovery workflow
  rather than deleting or overwriting uncertain output automatically.

## Install and test

From the extracted package directory:

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest \
  tests/test_protected_bitemporal_runner.py \
  tests/test_witness_secure_transport.py \
  tests/test_recording_tip_witness.py \
  tests/test_recording_checkpoint_registry.py \
  tests/test_observed_recording_journal.py \
  tests/test_authenticated_recording_history.py \
  tests/test_protected_recording_review.py \
  tests/test_bitemporal_timestamp_binding.py \
  tests/test_bitemporal_reconstruction.py -q
```

The installer requires a clean `feat/identity-resolution` branch containing
commit `be1ce20`, checks exact prerequisite sources and adds only this module,
its test and this document. `--check` writes no source files. Tests use ephemeral
fixtures, including local mutual TLS; they do not execute real research.

Independent service deployment/key lifecycle, trusted committed-evidence issuer
and complete intake/change capture are still pending. Source-independent
evaluation, contradiction refinements, findings storage/anchoring and scoped
search/UI remain separate work. RPC 1 remains deferred. Existing CSVs, database,
wallets and chain anchors are untouched by this package.
