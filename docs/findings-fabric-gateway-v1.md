# Findings Fabric Gateway adapter library v1

## Implemented and disabled boundaries

Adds `findings-gateway.js`, `findings-adapter.js`, `findings-block.js`, isolated
tests and this document. No existing evidence Gateway, journals, chaincode,
configuration or Python coordinator source is changed. No CLI is provided.
Constructing a connection defaults to READ_ONLY: prepare/submit are refused.
Source installation and tests never construct a real Gateway connection.

The library includes a concrete SDK transport factory using the existing pinned
`@hyperledger/fabric-gateway` 1.8.0 and `@grpc/grpc-js` 1.14.4 dependencies.
Tests inject SDK/gRPC doubles. Installing those dependencies in the development
environment was blocked by a registry HTTP 403 on a transitive package, so real
SDK deserialization, gRPC handshakes and peer behavior have NOT been validated.
The current code is API-informed development, not production readiness.

The Python coordinator still accepts isolated adapters only. A protected backend
bridge, encrypted durable callbacks, real peer integration tests and approved
deployment remain pending. Do not remove its fixture guard to try this library.

## Trusted construction

`connectFindings(options)` accepts a separately approved private config path and
exact SHA-256 of its bytes, repository path, retention and authorization callbacks,
and READ_ONLY (default) or EXECUTE mode. Optional dependency injection is internal
test infrastructure, not a user API. Never let requests nominate dependencies,
trust keys, callbacks, credentials, destination pins or EXECUTE mode.

The config has policy `FINDINGS_AUTHENTICATED_GATEWAY_V1` and exact fields:

| Config field | Meaning |
| --- | --- |
| destination | genesis_sha256, channel, chaincode, namespace, organizations |
| genesis_file | Approved private saved genesis block path |
| genesis_identity | Captured FABRIC_GENESIS_HEADER_DATA_V1 descriptor |
| identity | Enrollment certificate/private_key paths and SHA-256 pins |
| tls_client | Separate TLS certificate/private_key paths and SHA-256 pins |
| peers | Exactly two pinned peer descriptors |

Destination requires `personnel`, dedicated chaincode `findings-anchor-v1`,
namespace `findings-anchor-v1` and Org1MSP/Org2MSP. Each peer descriptor contains
`msp_id`, `endpoint`, `hostname`, `tls_certificate`, `tls_sha256`, and
`definition_sha256`. Local development endpoints are pinned to Org1 at
localhost:7051 / peer0.org1.example.com and Org2 at localhost:9051 /
peer0.org2.example.com. Other deployments require a separately reviewed change.

All credential/config files and their immediate parent directories must be owned
by the invoking user, outside the repository, with 0600/0700-style permissions.
Symlinks and explicit traversal are refused. Exact configured credential/root
digests are checked before SDK creation; all bytes are rechecked before/after
network operations. Enrollment key must be EC P-256 and match its X.509 cert.
Transport certificate/key must also match; enrollment and TLS certs must differ.
Both certificate validity windows are checked. No key, certificate or configuration
initializer is included. No source-saved test key becomes a production credential.

gRPC uses each approved root certificate, pinned endpoint/hostname and client TLS
key/certificate. SDK proposals use the enrollment signer and the DER TLS-client
certificate SHA-256 binding. Each organization path independently queries genesis
header/data identity and `_lifecycle.QueryChaincodeDefinition` using a binary
protobuf name argument. Its response bytes must match the externally approved
per-peer definition digest. That digest must be reviewed against the required
AND(Org1MSP.peer,Org2MSP.peer) policy, dedicated chaincode/version and lifecycle
configuration. A digest of an unreviewed response is not an endorsement-policy
approval. This library does not independently attest installed package IDs or
container/runtime binaries. Lifecycle/deployment attestation remains pending.

## Retention and authorization callbacks

Callbacks are trusted backend capabilities, not request data:

- `authorize(action,destination,payload)` must enforce the full approved selection,
  current protected readiness/permit, signed approval window/mode, witness history,
  subject/scope and destination pins. READ calls may omit payload; the callback
  must retain the exact bound operation/selection in its trusted closure.
- `retention.save(operation,plan)` must atomically publish the exact plan with
  fsync and nonoverwriting, dual-recoverable authenticated encryption. It must
  serialize competing operators and reject different content under the same ID.
- `retention.load(operation)` must independently authenticate/recover the plan,
  not return a dictionary supplied by a request or assume editable local files
  are independently rollback protected.

The callback contract is exercised with in-memory stores in these tests. The
library verifies exact save/load round trips and requires retained bytes before
submission, but cannot itself prove another callback actually fsynced or encrypted
them. Integration must use the already tested protected Python storage boundary;
that bridge is not implemented in this step.

## Transaction flow

`prepare(operation,payload,destination)` first verifies the network/config, then
uses an existing retained plan if present. Otherwise it endorses exactly
FindingsAnchor:AnchorFindings with both organizations, checks the returned record,
retains serialized endorsed transaction bytes and reloads them before returning.
This is endorsement only; it does not broadcast. An endorsement returning an
older record's transaction ID is refused: recovery needs the original plan.

Plans have the same five fields as the coordinator's transaction plan:
operation, payload_sha256, destination, transaction_id and transaction. The
transaction string contains FINDINGS_GATEWAY_PLAN_V1, base64 SDK transaction bytes
and the exact expected findings record. Bounded parsing binds the plan to the
nonce/creator-derived ID, signer certificate/MSP, channel, dedicated chaincode,
FindingsAnchor:AnchorFindings invocation and exact canonical payload argument.

`submit(plan,payload,destination)` requires EXECUTE, unchanged retained bytes,
authenticated destination and fresh trusted SUBMIT authorization. It reconstructs
and submits only that SDK transaction. No replacement proposal is built. SDK
signing may produce a different ECDSA signature on a retry, but its retained
transaction payload, nonce and ID stay identical. Submit acknowledgement is not
a VALID receipt. No automatic resubmission loop exists; ambiguous submission must
first be investigated using the original plan.

`observeCommitted(plan,payload,destination)` queries GetBlockByTxID and ReadFindings
through each organization path. Both blocks must contain exactly one matching
transaction payload on the bound channel, a nonempty envelope signature, correct
block data hash and VALID (zero) transaction-validation flag. Returned findings
records must match the full endorsed expected record, including original ID.
Both block identities must match. Configuration and authorization are rechecked
after observations before returning the exact coordinator FINAL receipt shape.

`verification.block_sha256` is SHA-256 of canonical JSON containing the SHA-256 of
serialized block-header bytes and block-data hash. It is a stable adapter content
identity, NOT Fabric's native ASN.1 block-header hash. This convention must remain
pinned when binding the public-chain receipt. Envelope signature presence is not
independent signature verification: trust relies on authenticated configured peers,
their ledger/validation flags and matching paths. This is not an offline MSP/orderer
signature or consensus verifier. Compromised channel governance/peers are outside
that trust model; independently approved public anchoring remains necessary.

Missing/unavailable/invalid observations throw. They are never converted to ABSENT
or a fresh transaction. The API deliberately exposes observeCommitted, not the
coordinator's simulated observe-with-ABSENT protocol. The protected bridge must
define first-submit state and ambiguous retry policy explicitly before enabling
live use; do not map arbitrary network errors to ABSENT.

## Validation and remaining work

46 new tests cover retention round trips/failures, read-only gates, authorization
expiry, exact retries, lost acknowledgements, invalid/missing/different blocks,
VALID flags, nonce/creator/invocation binding, data hashes, exact peer records,
bounded/malformed protobuf, file/config/symlink/credential pins, resource cleanup,
TLS SDK options, genesis and binary lifecycle query wiring. SDK doubles provide
fixtures; OpenSSL creates disposable test certificates only. No TLS handshake or
real endorsement/consensus test is claimed. Existing Gateway/journal, chaincode
and original evidence tests run alongside these cases.

Next: protected bridge with encrypted durable callbacks and explicit submission
recovery state, followed by genuine SDK/disposable two-peer Fabric integration,
deployment/credential/lifecycle review, public-chain integration and fresh full
readiness. Existing original anchors and databases are untouched. RPC 1 remains
deferred; no witness/chaincode deployment or live research execution occurs here.

## Primary API references

- [Gateway serialization APIs](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/Gateway.html)
- [Gateway connection/TLS options](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/ConnectOptions.html)
- [Proposal arguments and organization options](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/ProposalOptions.html)
- [Fabric common, gateway and lifecycle protobuf messages](https://hyperledger.github.io/fabric-protos/protos.html)
