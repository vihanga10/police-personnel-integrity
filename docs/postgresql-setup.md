# PostgreSQL identity database setup

## Purpose

Provide a dedicated PostgreSQL identity database and a restricted
application connection. Operational MongoDB integration is separate.

## Accounts

- police_identity_migrator: owns the database and identity schema.
- police_identity_app: can connect and use the identity schema.
- Application table permissions will be granted by later migrations.

Neither project account is a superuser or has CREATEDB, CREATEROLE,
REPLICATION or BYPASSRLS privileges.

## Initial provisioning

From the repository root, run once using a PostgreSQL administrator:

```bash
psql -X -d postgres -v ON_ERROR_STOP=1 -f database/postgresql/001_bootstrap_identity.sql
```

The script is not idempotent. If it fails partway through, inspect the
existing objects before retrying. Do not delete data to rerun it.

Assign separate passwords interactively using psql's \password command.
Never store real passwords in SQL files or Git.

## Local authentication

Before broader trust rules in pg_hba.conf, configure:

```text
local all police_identity_migrator,police_identity_app scram-sha-256
host all police_identity_migrator,police_identity_app 127.0.0.1/32 scram-sha-256
host all police_identity_migrator,police_identity_app ::1/128 scram-sha-256
```

Back up the machine configuration before editing. Check
pg_hba_file_rules for errors and reload with SELECT pg_reload_conf().

Other accounts may still follow trust rules. This setup does not
establish complete server hardening or physical isolation.

## Backend configuration

Inside backend:

```bash
cp -n .env.example .env
chmod 600 .env
```

Confirm .env is ignored by Git, then enter the application password
locally. Keep .env.example free of credentials.

## Connection check

```bash
cd backend
uv run python check_database.py
```

Expected result:

```text
Database connection: OK
Database: police_identity
Account: police_identity_app
SELECT 1: PASSED
```

## Verification completed

- Incorrect application password rejected over 127.0.0.1.
- Correct application password accepted.
- Application schema USAGE allowed.
- Application database CREATE and identity schema CREATE denied.
- Application privileged role attributes all false.
- Python connection check passed.

## Current scope

This is a standalone backend connection check. The /health endpoint
still checks API liveness only. Personnel tables, migrations, CSV
imports and API database operations are not implemented yet.