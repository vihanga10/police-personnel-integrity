# Secure recovery witness transport and controlled provisioning v1

## Scope

Adds a genuine HTTPS transport with mutual TLS 1.3 and certificate pins to the
existing append-only anchoring recovery witness. Both protected witnessed runners
accept an authenticated secure client. This is development source with isolated
network tests. Installing it starts no listener, creates no production key, and
changes no research database, evidence CSV, wallet, contract or original anchor.
RPC 1 remains deferred. No live research execution is authorized by these tests.

## Protocol and trust

The new explicit policy is `FINDINGS_RECOVERY_WITNESS_MTLS_V1`. The local fixture
policy remains available for previous isolated tests. Secure and fixture histories
have different signed policy fields; they are never silently migrated. Existing
nonempty fixture histories must not be enrolled as empty secure histories.
A reviewed migration and independent deployment remain future work.

The backend verifies the configured CA chain, normal TLS hostname/SAN validation,
and exact SHA-256 of the server's DER leaf certificate. The service requires a
CA-valid client certificate and exact SHA-256 of its DER leaf certificate.
TLS 1.3 is required. TLS credentials must match and be current. Exact certificate
pins intentionally mean certificate rotation requires a reviewed configuration
change; there is no automatic trust-on-first-use or fallback.

Application requests additionally require the separately trusted backend Ed25519
signature. Responses and checkpoint history use the witness Ed25519 signing key.
Requests/replies bind policy, operation/selection, fresh nonce and timestamp.
A fresh read checks the authoritative tip; updates are append-only compare-and-swap.
Exact uncertain update retries can return the existing checkpoint. They cannot
change, remove or skip history. The final checkpoint is terminal.

The endpoint is exactly HTTPS `POST /v1/recovery/checkpoint`. The client does not
follow redirects, retry, use a proxy agent, or accept request-chosen callbacks.
Each call makes its own authenticated connection with a bounded deadline.
Canonical UTF-8 JSON and a bounded Content-Length are required, with a 32 KiB
limit. Compressed/chunked wire messages and malformed schemas are rejected.
HTTP errors are generic and never print keys, payloads or raw server exceptions.
No health, enrollment, reset, deletion or provisioning endpoint is exposed.

Transport factories and witness clients are registered in private WeakSets;
lookalike capability objects are rejected. The trusted backend must construct the
client through `createConfiguredClient` from an explicitly pinned, owner-private
configuration. Never allow API callers to choose URLs, trust pins, keys, grants,
loaded snapshots, callbacks or recovery directories.

## Submission and recovery guarantees

Both existing witnessed runners now use the secure client without weakening the
loaded evidence/permit, signed approval or receipt checks. Every new retained stage
must be locally durable and confirmed by the witness before subsequent work.
In particular, the attempt checkpoint is confirmed before Fabric submission or
public transaction broadcast. A witness outage or uncertain acknowledgement blocks
transmission. Once an attempt exists, restart observes the original transaction;
it never automatically re-endorses, re-signs, replaces or rebroadcasts it.

A restored old local recovery directory is rejected when the witness is ahead.
Read-only reconciliation never repairs checkpoints. Writable recovery can confirm
exactly one pending local stage, under a fresh signed runner approval; divergence
or a multi-stage gap stops. Final results still require fresh chain observation.
The witness stores opaque stage hashes, not retained transaction bytes or findings.

Returned fields identify `recovery_witness_transport` as `MTLS` or `LOCAL_FIXTURE`.
They retain `independent_witness_deployment_verified: false`. A TLS connection does
not prove separate administration, trustworthy anti-rollback storage or readiness
of the research environment. Public execution remains fixture-only with
`live_chain_verification: false` and `both_chains_anchored: false`.

## Controlled service administration (reference, do not run for installation)

`recovery-witness-service.js` has three explicit administrative commands:

- `check`: read pinned configuration/credential files, validate settings, and
  construct the service without opening a socket or creating a checkpoint.
- `provision`: create exactly one new operation's empty secure checkpoint in an
  already existing private directory. Existing history/reset is refused.
- `serve`: bind only the explicitly configured IP and unprivileged port. It never
  provisions an unknown operation. SIGINT/SIGTERM closes the owned listener.

No command generates keys, creates storage directories, reads environment database
credentials, enables intake, creates an OS service, or deploys infrastructure.
The operator must first supply private directories, TLS certificates/CA and distinct
backend/witness signing material. Files require owner-only permissions and one link;
symlinks are refused. Material/config/storage must be outside the checkout.

The service configuration must contain exactly these fields:

```json
{
  "policy": "FINDINGS_RECOVERY_WITNESS_MTLS_V1",
  "directory": "/absolute/private/witness/checkpoints",
  "repository": "/absolute/checkout/police-personnel-integrity",
  "host": "127.0.0.1",
  "port": 9443,
  "timeout_ms": 5000,
  "tls_ca_file": "/absolute/private/witness/client-ca.pem",
  "tls_certificate_file": "/absolute/private/witness/server.pem",
  "tls_private_key_file": "/absolute/private/witness/server.key",
  "tls_certificate_sha256": "REPLACE_WITH_SERVER_DER_CERTIFICATE_SHA256",
  "client_certificate_sha256": "REPLACE_WITH_BACKEND_DER_CERTIFICATE_SHA256",
  "witness_private_key_file": "/absolute/private/witness/witness-ed25519.key",
  "writer_public_key_file": "/absolute/private/witness/backend-ed25519.pub",
  "witness_public_key_sha256": "REPLACE_WITH_WITNESS_DER_SPKI_SHA256",
  "writer_public_key_sha256": "REPLACE_WITH_BACKEND_DER_SPKI_SHA256"
}
```

Placeholders are deliberately invalid and must not be used to start a service.
SHA-256 values are lowercase bare 64 hexadecimal characters. Certificate pins
hash raw DER certificates; application key pins hash DER SubjectPublicKeyInfo.
The configuration file hash hashes its exact bytes, independently of those pins.

Administrative JSON must be serialized with sorted keys and compact separators,
UTF-8, with no trailing newline (the same encoding as `canonical`). For a complete
reviewed dictionary, Python uses
`json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`.
All existing files must be private (600), directories private (700).

Reference command syntax, using reviewed absolute paths and explicit hashes:

```bash
node blockchain/fabric/client/recovery-witness-service.js check \
  --config /absolute/private/service.json --config-sha256 CONFIG_HASH

node blockchain/fabric/client/recovery-witness-service.js provision \
  --config /absolute/private/service.json --config-sha256 CONFIG_HASH \
  --binding /absolute/private/binding.json --binding-sha256 BINDING_FILE_HASH

node blockchain/fabric/client/recovery-witness-service.js serve \
  --config /absolute/private/service.json --config-sha256 CONFIG_HASH
```

A binding is exactly `policy`, `operation`, `selection_sha256`, with retention
policy `FINDINGS_ENCRYPTED_GATEWAY_RETENTION_V1`. The two hashes must come from the
trusted runner's verified selection and policy, not invented identifiers.
Backend Ed25519 private keys never belong on the witness host, and witness signing
private keys never belong in backend retention. The local tests intentionally
co-locate disposable credentials; they do not establish that operational separation.

## Trusted backend configuration

`recovery-witness-client-config.js` exports
`createConfiguredClient({file, sha256, binding, repository})`. It accepts only
owner-private, pinned configuration/material outside the repository; it starts
no requests until `read`/`advance` is called. The exact configuration fields are:

```text
policy = FINDINGS_RECOVERY_WITNESS_MTLS_V1
endpoint = https://reviewed-witness-host:9443/v1/recovery/checkpoint
tls_ca_file, tls_certificate_file, tls_private_key_file
tls_certificate_sha256, server_certificate_sha256, timeout_ms
writer_private_key_file, writer_public_key_sha256
witness_public_key_file, witness_public_key_sha256
```

Pass the resulting client as `recoveryProtection` to the existing witnessed runner
through the trusted backend composition boundary. Operational backend routes are
not wired/enabled by this installer.

## Validation and practical limits

System `openssl` generates disposable test certificates in private temporary
folders; tests use actual HTTPS sockets on loopback and clean up only owned files
and listeners. No Docker, installed research credentials or live RPC is used by
the new secure tests. They cover mutual TLS and pins, hostname/CA/client rejection,
application signatures and policies, CAS and lost acknowledgement, deadlines,
HTTP/schema bounds, configuration safety, explicit provisioning and fresh-process
service restart. Protected runner tests exercise HTTPS submission barriers with
Fabric adapter doubles and actual local EVM execution. Genuine Fabric SDK/peer
and dual-chain tests from the previous step remain regression suites; this package
does not claim a new genuine-peer/HTTPS composition test.

Operational work still includes separate witness hosting/storage administrators,
backup/anti-rollback policy, TLS/application-key rotation and revocation, monitored
service lifecycle, reviewed history migration, genuine-peer plus HTTPS composition,
full backend readiness wiring and RPC 1 resolution. Restoring or compromising the
witness's own entire storage/key domain can defeat its latestness guarantee;
transport authentication alone cannot solve that threat. User evaluation and live
public finality/provider independence remain separate requirements.
