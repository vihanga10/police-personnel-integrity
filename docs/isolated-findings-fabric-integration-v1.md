# Genuine SDK and disposable findings peer validation

## What this implements

A standard-library Python launcher with two explicit suites:

- `--suite sdk` (default): builds a separate locked test runtime and runs eight
  genuine SDK/protobuf/chaincode-library tests. No peer/orderer ledger is created.
- `--suite peers`: generates new fixture CAs and identities, starts two peers and
  one orderer, creates the personnel fixture channel, deploys the dedicated
  findings chaincode as an external service and runs 12 real SDK/peer checks.

No existing research network, gateway configuration, wallet, CSV, database,
original evidence anchors or public RPC is selected. These tests are not actual
research execution or production deployment. RPC 1 remains deferred.

The peer suite itself is NOT validated merely by the unit tests or SDK suite.
Docker is unavailable in the development environment; successful peer execution
must be established by the Mac's printed completion and cleanup output.

## Software and isolation

Pinned direct packages: Gateway 1.8.0, grpc-js 1.14.4, fabric-protos 0.3.7,
fabric-contract-api 2.5.8 and fabric-shim 2.5.8. A separate npm lockfile pins
transitive resolution and integrity values. `npm ci --ignore-scripts` is used in
the test image. No existing package or dependency lock is overwritten.

Fabric peer/orderer/tools image tags are 2.5.16, matching the existing project's
version. Fabric images explicitly use linux/amd64; Docker Desktop on the M4
provides emulation. The Node test image uses the host-native build architecture
and node:24-bookworm-slim. This compatibility suite is not a native-performance
benchmark; emulation availability remains part of the Mac execution check. Base image tags and apt packages
are not immutable digest attestations; this is a disposable compatibility test,
not a production supply-chain approval. Docker Desktop, registry access and
internet access for images/packages are needed. First build may take several
minutes; runtime compatibility on the Mac remains a test result, not an assumption.

Each run has a random ppi-findings-* project/network and owner-private temporary
root. No host port is published; no fixed container name, existing network,
Docker socket mount, named ledger volume or host credential mount is used.
Ledger directories use tmpfs. Containers mount only this newly created fixture
root. Only an explicit list of source files is copied into the image build
context. Database/peer/CA/SDK and arbitrary Docker endpoint environment variables
are not passed into subprocesses. Docker uses the user's normal Docker context.

The unchanged adapter expects loopback 7051/9051 and certificate hostnames
peer0.org1.example.com/peer0.org2.example.com. Proxies on those ports exist only
inside the disposable runner's container namespace and forward encrypted bytes
to peers on its private project network. Peer mTLS remains end-to-end. Nothing
binds those ports on the Mac, so the existing research network can stay intact.

The test chaincode runs via the built-in ccaas_builder and has no Docker-daemon
access. Its peer-to-chaincode service hop has TLS disabled only inside the
isolated fixture network. Peer/Gateway and orderer endpoints use TLS, and both
Gateway peers require client certificates. This is not a production topology.

Fixture writer and denied certificates are signed offline by newly generated
cryptogen fixture CAs. The findings attribute is encoded in Fabric's X509 OID;
the genuine fabric-shim ClientIdentity decoder is tested against this encoding.
The writer has findings.anchor=true. The denied identity has evidence.anchor=true
only. A separately generated client TLS certificate is used. This tests the
chaincode attribute boundary; it does not establish legal/reviewer eligibility,
Fabric CA enrollment workflows or production trust governance.

## Checks and expected results

The 12 launcher unit cases verify namespace separation, absence of host
ports/socket/named volumes, ephemeral ledgers, filtered inherited configuration,
resource cleanup ownership, package structure, TLS settings and temporary MSPs.
They do not contact Docker or prove the peers work.

Eight genuine dependency tests verify exact package versions, full SDK Prepared-
Transaction deserialization/result/digest/byte roundtrip, proposal reconstruction
and independent nonce, the existing bounded parser against official protocol
classes, VALID/INVALID block flags, malformed bytes, the real contract wrapper
and the real shim's X509 attribute decoder. Their messages are artificial and
neither signed peer endorsements nor committed ledger blocks.

The peer suite requires all of these actual-network checks:

1. mTLS and genesis/lifecycle readback from both organizations.
2. Protected bridge endorsement/submission and VALID two-peer exact readback.
3. Encrypted storage of original real transaction material.
4. Restart verification without replacement endorsement/submission.
5. Read-only reconciliation without recovery-file writes.
6. Rejection of an evidence-only writer identity by the actual chaincode.
7. Rejection of conflicting content for a committed opaque publication handle.
8. Rejection of an extraneous personal field.
9. Approved configuration digest mismatch rejected before SDK construction.
10. Injected acknowledgement loss after real submission, recovered by original
    transaction ID without another endorsement/submission or read-only writes.
11. Rehydration of an actual endorsed SDK transaction before broadcast.
12. Two real absent-key endorsements followed by a VALID first commit and an
    MVCC_READ_CONFLICT second commit, with the invalid block rejected by the
    verifier and the original record preserved in both peers.

The peer fixture uses random opaque commitments, no research personnel records.
`checkLoaded` in this suite is explicitly a controlled fixture capability. It
neither performs full research replay nor issues an actual AlgorithmPermit. The
real SDK/configuration/transport/chaincode and filesystem retention are exercised;
operational protected-loader and independent recovery-state wiring remain pending.

## Cleanup and interruption

Cleanup enumerates only resources with this exact random run label, verifies
ownership and removes only the returned exact container IDs (including their
anonymous volumes), its exact labeled network and its exact labeled image tag.
Shared downloaded base images/cache are preserved. No docker prune, sample
network.sh down, broad container deletion or existing ledger reset is used.
Cleanup failure makes the command exit unsuccessfully and preserves the run root.

Successful runs remove the private fixture root after resource cleanup. Failed
runs retain owner-private logs and disposable test keys at the printed temporary
path for diagnosis. Send aggregate phase/status output only; do not upload that
whole directory. SIGKILL, Docker daemon loss or host crash can prevent cleanup;
those run-specific resources require supervised inspection. There is no automatic
cross-run sweep or deletion of uncertain resources.

SDK/bootstrap/query errors are fail-closed. The harness does not normalize a
failed query into ABSENT. A retained attempt prevents automatic resubmission.
If a platform/real SDK incompatibility surfaces on the Mac, this step remains
pending until corrected and rerun. Do not bypass those checks to obtain success.

## What remains after this test

Operational backend/Python full-loader wiring, independent recovery-state
protection, authority configuration, witness deployment, real findings contract
provisioning, public adapter/dual-chain validation and RPC 1 remain on the research
completion checklist. Success here proves local fixture SDK/peer behavior only.

References consulted: Fabric external-service and channel-participation guides:
https://hyperledger-fabric.readthedocs.io/en/release-2.5/cc_service.html
https://hyperledger-fabric.readthedocs.io/en/release-2.5/create_channel/create_channel_participation.html
Genuine installed SDK/shim code was inspected to verify binary reconstruction,
server CLI options and certificate-attribute decoding.
