# Secure witness transport and controlled provisioning

## Scope

This additive module implements a direct HTTPS transport, a bounded internal
mutual-TLS listener and offline signed provisioning. It connects to the existing
challenge-bound witness and registry adapter without changing their policies.
Installation deploys no service, initializes no witness, generates no production
keys/certificates and changes no CSV, database, wallet or chain anchor. RPC 1
remains deferred. No real personnel query or research execution is performed.

Production independent hosting, access administration, anti-rollback/restore
controls, key revocation/rotation and protected research-runner integration
remain pending. The listener is a controlled integration interface, not a
general-purpose public production web server. Production hosting and operational
security need a separately reviewed deployment. No deployment or Git push is
performed by this package.

## Explicit provisioning

`provision(service, ...)` is a trusted offline operator API. The service must
already have a verified enrolled store and an independently retained enrollment
file pin. It verifies the full store and creates one new signed profile at an
explicit private path. It never enrolls, resets or overwrites the store, starts
a listener, changes an existing profile or writes a key/password.

Supply existing certificate/private-key paths through trusted configuration.
Do not expose paths, pins or secrets to user requests. All supplied material
and profiles must be owner-only regular files in private directories outside
the repository; symlinks and public permissions fail. Profile storage must be
separate from the witness ledger. Keep the witness independently administered,
outside the journal and registry rollback domain. A sibling directory on a
research Mac is suitable for local tests, not independent production protection.

This first transport policy intentionally supports one self-signed private
issuing CA, directly issued server/client certificates and one client certificate
per pinned registry writer. It rejects ambiguous certificate bundles rather than
silently accepting intermediates or general Internet trust stores. Different CA
or intermediate-chain arrangements require an explicitly reviewed extension.

Preflight checks include CA constraints/signature and signing permission,
certificate validity, direct issuer/signature, server/client extended key usage,
private-key/public-certificate correspondence and exact server SAN identity.
DNS SAN matching is exact; wildcard and subject-common-name fallback are refused.
CA, server, client and application signing public keys must be distinct. The
server TLS context also loads the checked material before profile publication.

Encrypted TLS PEM private keys are supported using password bytes supplied only
in memory. Passwords are never part of profiles or logs. The code creates no
production credentials; test certificates/private keys are disposable fixtures.

The signed provisioning policy is `PRIVATE_WITNESS_MTLS_PROVISIONING_V1`. Its
profile binds witness/registry IDs, journal anchor, enrollment file SHA-256,
exact HTTPS endpoint, issuing-CA and server-leaf DER certificate SHA-256 pins,
client-certificate fingerprint-to-writer-key-ID map, application key inventory
digests, creation/expiry times and fixed/bounded limits. It uses the existing
witness signing key under a separate signature domain. It authenticates that
authority's configuration assertion; it is not a research audit permit.

The profile expires at the earliest supplied CA/server/client certificate expiry.
Publication is private, flushed and non-overwriting. Retain the returned exact
profile file SHA-256 through trusted configuration handoff. Consumers require
that expected pin and the pinned witness signing-key inventory; they never
calculate a supposedly trusted expected hash from an untrusted profile file.
Preserved partial provisioning requires investigation, not automatic overwrite.

## Client transport

`HTTPSWitnessTransport(...)` loads and verifies the profile and local client
credentials without contacting a network endpoint. Use its callable as the
existing `WitnessClient(exchange=...)`, then use `WitnessedCheckpointRegistry`
for active reads, registration and authorized recovery.

The endpoint must be explicit HTTPS with the exact path
`/v1/recording-tip-witness/exchange`; userinfo, whitespace, other paths,
queries, fragments and invalid ports are refused. Requests connect directly;
environment proxy settings are not inherited. Redirects are rejected and never
followed. There is no plaintext, cached-tip, alternative-endpoint or retry fallback.

Each connection requires TLS 1.3, trusted private-CA validation, hostname/SAN
verification and a client certificate. The client additionally checks the exact
server-leaf certificate fingerprint immediately after handshake and before
sending any signed witness request. A different valid certificate from the
same CA is insufficient. TLS credentials remain separate from the application's
Ed25519 witness/registry signatures.

The transport requires its client certificate to be provisioned for the request's
registry writer key ID. It sends bounded canonical JSON and accepts only a
successful JSON response with one bounded Content-Length. Transfer/content
encoding, duplicate lengths, oversized/truncated bodies, duplicate JSON keys,
non-finite JSON, wrong status/content type and redirects fail. The existing
WitnessClient still independently verifies scope, signer, nonce, exact request
digest, status, tip and timestamps. TLS does not replace those checks.

Failures return a sanitized `WitnessTransportError`; no acknowledgment is
accepted. Connection/read timeouts and socket-abort timers enforce a network
I/O budget, with a monotonic deadline recheck before sending and after reading.
Operating-system DNS resolution and filesystem calls are separate dependencies;
these APIs do not promise to cancel a blocked DNS resolver or storage operation.
Deployment must supply bounded/trusted DNS and operational storage controls.

## Internal listener

`WitnessHTTPSServer(bind_address, service, ...)` explicitly validates the pinned
profile, scope, enrollment, writer inventory, server certificates/key and replayed
store before binding the configured port. Provisioning itself never binds it.
No startup CLI, background daemon, container or public deployment is installed.

The only supported application operation is POST to the exact witness exchange
path. TLS requires a client certificate issued by the private CA. After handshake,
the server additionally requires a provisioned exact client certificate fingerprint
and its bound registry writer key ID. It then calls the existing service signature,
freshness, scope, compare-and-swap and durable-history checks. A CA-valid but
unlisted client or a certificate/request signer mismatch receives no witness data.

| Boundary | Limit |
| --- | --- |
| TLS | Minimum TLS 1.3; mutual certificate verification |
| Request line/headers | 8 KiB combined reader budget |
| JSON request/response body | 16 KiB |
| Request I/O budget | Default 5 seconds; configured range 0.1–10 seconds |
| Admitted connection workers | Default 8; configured range 1–16 |
| Requests per pinned client/minute | Default 60; configured range 1–120 |

Admission is bounded before TLS handshake work. Handshake timeout and request
socket-abort timer release stalled connection resources. Excess connections
are closed; per-certificate rate excess is rejected. All limits are signed in
the profile. This bounds cooperating code resources but does not guarantee
availability against a network attacker or cancel an underlying storage lock.

Only one HTTP operation is served per connection. Content framing is checked
before body reads. Chunked requests, content encodings, duplicate Content-Length,
Expect/continue, oversized headers/bodies and malformed JSON fail. Other verbs
and paths do not expose files, administrative provisioning or personnel APIs.
Responses use `Connection: close` and `Cache-Control: no-store`.

Network errors are deliberately generic; request bodies, private paths, keys
and raw exceptions are not logged or returned. Protected operational audit
logging/monitoring remains a deployment integration duty. The service's signed
ledger still preserves successful witness updates.

## Interrupted exchanges and research meaning

A transport timeout/disconnection does not prove that an authorized CAS failed
to commit. The service may already have durably updated its latest tip. The
caller raises instead of inventing a success/failure acknowledgment, and a later
fresh signed HEAD retrieves committed state. An actual TLS response-loss test
verifies that a committed update remains readable without duplication.

When publication fails before witness commit, existing separately authorized
registry recovery/reconciliation is still required. No network retry silently
overwrites the independent witness or infers trust from local files. Unknown
staging artifacts remain preserved and blocking under existing policies.

Fresh TLS/challenge replies do not prove the witness authority's storage was
never restored. Its independence and restore controls remain essential. No
quorum, hardware monotonic counter or Byzantine protection is claimed. Transport
authentication also does not prove source truth, SQL/Mongo commit or complete
source change capture, and never extends observation coverage to a later date.

## Local installation and tests

The clean `feat/identity-resolution` branch must contain committed ancestor
`31e6e4a`. Extract `secure-witness-transport-step.zip` into Downloads:

```bash
cd "$HOME/Downloads/secure-witness-transport-step" &&
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
```

`--check` writes nothing. After it passes:

```bash
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" &&
cd "$HOME/Developer/police-personnel-integrity/backend" &&
uv run python -m pytest \
  tests/test_witness_secure_transport.py \
  tests/test_recording_tip_witness.py \
  tests/test_recording_checkpoint_registry.py \
  tests/test_observed_recording_journal.py \
  tests/test_authenticated_recording_history.py \
  tests/test_protected_recording_review.py \
  tests/test_bitemporal_timestamp_binding.py \
  tests/test_bitemporal_reconstruction.py -q
```

Expected focused result: **350 passed**, including **69 new tests**. The broader
reconstruction, authority, audit-gate and registration journal/receipt regression
set totals **550 tests**. New tests create temporary private credentials and
real loopback TLS listeners that are closed afterwards. They cover restart,
mutual authentication, wrong CA/name/certificate pins, TLS downgrade, credential
reuse, enrollment/profile binding, framing limits, rate/admission controls,
timeouts, loss after durable CAS and sanitized failures. No real credentials,
external witness, databases, RPC or personnel research are used. Fixture timings
are not research-cohort performance results.

After local tests and source review:

```bash
cd "$HOME/Developer/police-personnel-integrity" &&
git add backend/app/identity/witness_secure_transport.py \
  backend/tests/test_witness_secure_transport.py \
  docs/witness-secure-transport-v1.md &&
git diff --cached --check &&
git commit -m "Add secure witness transport and controlled provisioning"
```

This creates a local commit only. Nothing in the installer or tests executes
`git push`. Bitemporal integration is still partly complete; independent
production deployment, key lifecycle, source capture, protected query execution
and later findings/UI work remain pending. RPC 1 remains deferred.

API references: [Python 3.12 ssl](https://docs.python.org/3.12/library/ssl.html)
and [cryptography X.509 reference](https://cryptography.io/en/50.0.0/x509/reference/).
OpenSSL performs live TLS chain/hostname verification; direct issuer checks in
preflight are deliberately limited to the private root/direct-leaf policy above.
