# Configured local public-runtime factory

This step connects the committed public worker to a backend-selected private
wallet and two pinned local HTTPS RPC listeners. It preserves the existing
fixture policy and the default worker's refusal when unprovisioned. RPC 1 remains
deferred. No production keys, research storage, public-chain deployment or remote
RPC endpoints are selected by the installer.

## Boundaries

The trusted Python `run_public` entry accepts optional `runtime_config_file` and
`runtime_config_sha256` administrative arguments. Both or neither must be supplied.
With neither supplied, the original fixed worker stays unprovisioned. With both,
the service validates the exact canonical runtime file, its approved SHA-256,
network selection, writer, wallet bytes and key separation. It invokes the fixed
`configured-public-backend-worker.js` with only the administrative file path and
digest as argv. The private-pipe job does not accept a runtime module, injected
wallet, endpoint list or loader. Signed selection/source verification precedes
runtime credential loading in the Node process.

The configured worker supplies the actual factory to the existing private-pipe
protocol. The original worker remains the default. The internal library loader
parameter is for trusted composition and tests; it cannot be selected from pipe
messages. Every existing source/Fabric guard remains in place.

## Runtime configuration

The exact policy is `FINDINGS_CONFIGURED_LOCAL_HTTPS_RUNTIME_V1`. The canonical
JSON object has these fields:

| Field | Requirement |
| --- | --- |
| `policy` | Exact local policy above |
| `network_config_sha256` | Approved selection's existing fixture-network digest |
| `writer` | Exact lowercase address in the approved dedicated findings destination |
| `wallet_file` | Absolute private ordinary file outside the repository |
| `wallet_sha256` | SHA-256 of that file's raw 32 disposable wallet-key bytes |
| `timeout_ms` | Integer 100–10000, absolute request deadline |
| `providers` | Exactly two provider descriptions in approved network order |

Each provider has exactly `endpoint`, `connect_url`, `ca_file`, `ca_sha256`,
`client_certificate_file`, `client_certificate_sha256`, `client_key_file`,
`client_key_sha256` and `server_certificate_sha256`.

`endpoint` is the approved `.invalid` fixture identity in the existing network
configuration. `connect_url` must be the exact form
`https://127.0.0.1:PORT/rpc`, without user information, query, fragment or other
routes. The two connect URLs must differ. There is no public DNS resolution or
remote-address option. This is a deliberate isolated-runtime policy, not a live
Sepolia provider factory.

File hashes bind PEM byte content. The server pin binds the leaf certificate's DER
bytes. TLS 1.3, CA verification, IP hostname verification and client certificates
remain mandatory. There is no certificate-verification bypass. Ordinary files
must be owner-only, have one hardlink, have no symlink ancestors, and reside in
private directories outside the repository. Runtime files are rechecked before
and after RPC calls and signing; the Python service also rechecks its runtime and
wallet pins at source guards. The wallet must derive the approved writer and
must differ from recovery/source commitment keys checked by the backend.

## HTTPS RPC behavior

The factory exposes only the ten methods used by the existing findings adapter.
Only the first view may invoke `eth_sendRawTransaction`. Every RPC uses one
request with a unique matched ID, bounded canonical JSON, an absolute timeout,
and pinned credentials. Redirects, encoded replies, duplicate keys, invalid IDs,
extra top-level fields and oversized bodies fail closed. Errors retain the
numeric code and revert-data string needed to distinguish the contract's precise
`publication absent` revert from an unavailable provider. HTTP errors do not imply
absence. There are no automatic retries, alternate-provider submissions or nonce/
fee replacements. Runtime cleanup aborts owned requests and clears key buffers;
JavaScript does not guarantee erasure of internal immutable wallet strings.

## Validation and limitations

The new Node suite uses actual HTTPS/mTLS, a real disposable Ganache EVM, the
configured wallet loaded from disk, the committed worker process and the actual
Python `_exchange` protocol. It covers successful execution, read-only restart,
denials at SIGN/SUBMIT/ACK and loss of the original submission acknowledgement.
Recovery preserves encrypted history and does not sign or broadcast a replacement.
Other cases cover configuration/key/filesystem rejection, TLS pin/CA/client
failure, file drift, malformed responses, bounds, redirects and deadlines.

The Python configuration tests validate fixed command construction and repeated
administrative pins using explicit pipe-result doubles. The Node pipe tests use
an explicit source/Fabric callback double. They do not establish genuine full
source replay or a new genuine Fabric observation through `run_public`. The two
HTTPS listeners share one local EVM. Sepolia genesis and public finalized heads
are simulated by the existing local-EVM helper. Neither the local listeners nor
the local witness demonstrate independent deployment.

The result continues to report `FIXTURE_ONLY`, `public_transport_enabled=false`,
`live_chain_verification=false`, `both_chains_anchored=false`,
`provider_independence_verified=false` and `live_research_ready=false`. Existing
per-receipt fixture verification flags are not public-readiness claims.

Complete source/Fabric/public backend integration and independently operated
providers, consensus finality, authority configuration and deployed witness
readiness remain pending. This package does not resolve RPC 1 or enable a live
research execution.

## Run focused checks

From `backend`, run the Python command in the package README, then use `uv run
node` for the Node checks. Running Node through `uv` ensures the actual Python
pipe tests use the repository's Python environment. System OpenSSL is required
for disposable TLS certificates. There are no skipped checks or Docker dependency
in this new suite. Temporary EVMs, wallets, TLS material and listeners are removed
after the tests; original databases, CSVs and evidence anchors are unused.
