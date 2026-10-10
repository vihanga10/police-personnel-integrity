# Isolated PostgreSQL recording integration tests V1

This additive step supplies 23 real PostgreSQL integration tests and a launcher
that creates a new temporary PostgreSQL 16 Docker container. It also supplies
49 launcher isolation/cleanup tests using simulated Docker responses. The
installer adds files only; it does not start Docker, connect to PostgreSQL,
create schemas, use research credentials or submit blockchain transactions.

## Isolation boundary

The launcher accepts no database URL, credential file, image override or existing
container. It generates a new UUID-like run token, container name, database name,
cluster name and temporary password, using the Docker Official Image
`postgres:16`. It records that run's actual image and container IDs. This pins
the running image within one run; the moving tag is not a supply-chain attestation.
The Docker daemon and local image store remain trusted operator infrastructure.

PostgreSQL data is mounted on tmpfs, with no host-directory or persistent-volume
mount. Its port is selected by Docker and bound to `127.0.0.1`. The launcher and
suite independently check container ID/name/label, exact startup command,
credentials, image ID, tmpfs, running/autoremove state and loopback port mapping.
The suite checks database/user, unique server cluster name, PostgreSQL major
version 16, primary status and `fsync=on` BEFORE any schema writes.

The fixture refuses even an existing `identity` schema inside the isolated
database. For each test it creates a new schema/outbox and a restricted runtime
role; cleanup rechecks server/container identity before dropping ONLY that
fixture's schema and role. The launcher removes ONLY its own randomly named,
run-labelled container. Cleanup uncertainty fails the launcher; it never removes
unrelated containers. The existing native PostgreSQL service, research database,
Mongo services, Docker volumes, CSVs and blockchain anchors are not selected.

Temporary credential/config files are owner-only, outside the repository and
deleted afterward. No passwords appear in Docker command arguments or status
messages. Temporary test credentials remain visible to Docker administrators
through that disposable container's environment, as expected for this fixture.
Ordinary application `.env`, `Settings` and database URL configuration are not
used to select the test connection.

## What the 23 tests check

- Real post-commit readback, receipt signing, journal append, witness acknowledgment
  and completed-capture retry without duplicates.
- New independent claim intake, correction and withdrawal lineage.
- Uncommitted rows invisible to the receipt issuer through a separate transaction.
- Conflicting operation IDs/intents and SQL transaction rollback.
- Delayed capture using new observation time rather than CSV/database-default time.
- Engine-pool reconnect to committed rows, lost readback retry and pending coverage.
- Interrupted checkpoint publication and witness failures before/after commit.
- PostgreSQL itself denying runtime UPDATE, DELETE and TRUNCATE with SQLSTATE 42501.
- The production guard rejecting real excess UPDATE, column UPDATE, DELETE,
  TRUNCATE and TRIGGER grants, and rejecting the administrative account.
- Transaction-local synchronous WAL commitment even when the role's default is off.
- The public bridge over actual PostgreSQL and temporary mutual TLS, with only the
  original snapshot loader replaced by a disposable test fixture.

The suite uses test officer/source/permit/signing fixtures, not actual research
evidence or a live research-readiness waiver. Its witness is a disposable local
test service, not a deployed independently administered production witness.
These tests verify actual PostgreSQL transactions/configuration; they do not
prove physical power-loss recovery or distributed atomicity. The reconnect test
reopens the engine pool, not the PostgreSQL server process. tmpfs data is designed
to disappear when the container stops and can be swapped by the host; no real
personnel data belongs in this temporary fixture.

## Install and regular tests

Requires clean `feat/identity-resolution`, committed step `7911dfe`, and the exact
existing source fingerprints. Run the package compatibility check first.

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest \
  tests/test_isolated_recording_postgres_launcher.py \
  tests/test_committed_evidence_postgres.py \
  tests/test_committed_evidence_capture.py \
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

Expected regular result: **476 passed, 23 skipped**. The skips mean PostgreSQL
integration has NOT run. An absent launcher config causes explicit skips; a
present invalid config fails, rather than using another database or silently
skipping. The installer checks prerequisites and adds four source/test/doc files.
It never overwrites existing files or provisions a database.

## Real PostgreSQL execution — only after regular tests pass

Start Docker Desktop on your Mac. From the backend directory run:

```bash
uv run python scripts/run_isolated_recording_postgres.py
```

The first run may download the PostgreSQL image. The launcher prints its unique
temporary container name, then runs the 23 tests and removes the container.
Expected: **23 passed**, followed by confirmation that every expected real
PostgreSQL test ran without skips and that the isolated container was removed.
Only that output establishes actual PostgreSQL test success on your Mac.
Launcher success also requires a generated test report with the exact expected
test count and zero skips/errors/failures. It clears pytest option/plugin
environment overrides that could turn execution into collection-only or skip it.

If Docker is stopped or the image cannot be fetched, the launcher fails without
selecting any research database. If interrupted normally, cleanup runs. If the
process is forcibly killed or Docker becomes unreachable, cleanup cannot be
guaranteed: use Docker Desktop to identify the printed UUID-labelled temporary
container. Do not delete unrelated volumes or containers to retry.

No production outbox schema, intake hook or independent witness deployment is
performed by this command. Bitemporal coverage remains journal observations
only; complete intake/change capture, real evaluation and later findings/UI
work remain pending. RPC 1 remains deferred and no live research is executed.

Official references: [Docker PostgreSQL image](https://hub.docker.com/_/postgres),
[Docker tmpfs mounts](https://docs.docker.com/engine/storage/tmpfs/),
[Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).

## Development verification limits

The development workspace had no Docker runtime or PostgreSQL server. Launcher
checks were executed with simulated Docker responses and the existing focused
regressions were run. The 23 real PostgreSQL tests were collected and skipped.
Their SQL/driver/runtime behavior must therefore be verified with the isolated
Mac command above; this package does not claim they already passed.
