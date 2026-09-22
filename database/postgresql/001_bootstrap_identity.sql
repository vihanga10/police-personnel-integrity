\set ON_ERROR_STOP on

-- Administrative setup: run once against the postgres database.
-- Passwords are assigned separately and must not be stored here.

CREATE ROLE police_identity_migrator
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

CREATE ROLE police_identity_app
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

CREATE DATABASE police_identity
    OWNER police_identity_migrator;

-- PUBLIC means all PostgreSQL roles.
REVOKE ALL ON DATABASE police_identity FROM PUBLIC;

GRANT CONNECT ON DATABASE police_identity
    TO police_identity_app;

\connect police_identity

-- Application code must not create objects in the public schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- The migration account owns the identity schema.
CREATE SCHEMA identity
    AUTHORIZATION police_identity_migrator;

-- The application may reference objects in this schema.
-- Table permissions will be granted explicitly by later migrations.
GRANT USAGE ON SCHEMA identity
    TO police_identity_app;