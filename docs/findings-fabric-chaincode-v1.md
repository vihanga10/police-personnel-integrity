# Dedicated findings Fabric chaincode v1

## Implemented boundary

`blockchain/fabric/findings-chaincode` is a separate Node.js chaincode package.
It exports contract `FindingsAnchor` with only `AnchorFindings` and `ReadFindings`.
Nothing is added to or replaced in `blockchain/fabric/chaincode`, the original
officer-evidence package. No deployment or network command is included.
The package uses the existing pinned Fabric dependencies 2.5.8 and Node >=18.
The isolated rules tests require only Node built-ins, so no npm install is needed
to run them. Installation of source does not install chaincode on a peer.

`AnchorFindings` requires invoking MSP `Org1MSP` and the certificate attribute
`findings.anchor=true`. The original `evidence.anchor=true` attribute alone is
insufficient. `ReadFindings` accepts only Org1MSP or Org2MSP. This is technical
service authorization, not legal review authority or scoped user UI access.
Certificate provisioning and CA eligibility controls remain pending.

## Payload and storage

Canonical JSON contains exactly:

| Field | Required value |
| --- | --- |
| policy | FINDINGS_FABRIC_ANCHOR_V1 |
| namespace | findings-anchor-v1 |
| publication_id | Opaque 64-character lowercase hex handle |
| public_sha256 | SHA-256 of the exact public commitment payload |
| merkle_root | Findings commitment Merkle root |
| publication_commitment | Keyed commitment from protected preparation |

These fields match the existing isolated coordinator's private-chain payload.
Extra fields, invalid digests, alternate JSON encodings, duplicate keys, wrong
policies/namespaces and inputs over 4096 bytes are rejected before state writes.
The public-only test vector was generated with the installed Python commitment
module using fixed fixture keys/salt and minimal fixture history. Node tests
independently match the Python canonical payload digest and SHA-256 Merkle tree.
The vector is a test fixture, not authenticated research evidence.

The only state key is `findings-anchor-v1:publication:<publication_id>`.
Its record contains policy `FINDINGS_FABRIC_RECORD_V1`, exact payload and original
Fabric transaction ID. There are no delete/update/reset, acceptance-state,
identity, evidence, correction or review mutation APIs. Each subsequent findings
history snapshot gets a fresh opaque publication handle from protected preparation
and appends another record. Corrections/reviews remain inside the encrypted journal
and its keyed commitments; individual plaintext decisions never reach this package.

Existing-key reads return the original record only when the entire payload matches.
Changing any anchored digest under that same handle is rejected. Retry proposals
may have a different proposal transaction ID, but the returned anchor identity
remains the original committed transaction. A client MUST independently verify
that original transaction's VALID status and peer readbacks; a returned object or
successful endorsement alone does not establish commit.

The initial absent-key read precedes its write and therefore provides the Fabric
MVCC read dependency against simultaneous inserts. Isolated tests simulate version
checks: only one competing write commits, and the loser is retried by reading the
existing record. Actual endorsement/MVCC behavior on peers remains to be tested.
Stored state is schema/encoding/handle checked during reads; corruption is refused,
not repaired or overwritten. Full schema-compatible tampering by a compromised
ledger is beyond this check and must be caught by authenticated chain verification.

## Deployment requirements — still pending

Deploy under a dedicated chaincode definition, proposed name `findings-anchor-v1`,
with a separately reviewed package and chaincode-level endorsement policy
`AND('Org1MSP.peer','Org2MSP.peer')`. Do not upgrade or reuse `officer-evidence-v1`.
The code does not install an endorsement policy itself: lifecycle governance must
set and verify it. Client readback from two peers is a separate verification step,
not a substitute for endorsement-policy enforcement.

The chaincode deliberately records an authorized writer's opaque commitment claim.
It does not receive plaintext history, verify backend approval signatures,
authenticate witness history, recompute HMACs, validate research facts or ensure
that a supplied root represents the latest history. Those checks belong in the
protected preparation/coordinator and future authenticated Gateway adapter.
An authorized writer can submit arbitrary well-formed digests; CA/service-key
controls and protected runner integration are required before enabling it.

Future Gateway implementation must verify genesis/channel/dedicated definition,
package identity and endorsement policy; retain exact endorsed transaction bytes
and identity before submission; independently verify VALID commit and equal exact
record from both organization peers; retain encrypted immutable recovery artifacts;
and reconcile the original transaction after lost acknowledgements. Avoid building
a replacement transaction on ambiguous network errors. Public-chain contract,
finality/readback verification, fee controls and dual-chain live integration remain
pending. The previous coordinator still accepts fixtures only and is unchanged.

Channel peer/admin access can reveal transaction identity, timing and publication
counts. Attribute-based chaincode reads do not hide ledger state from organization
administrators. Opaque payloads reduce data exposure; they do not provide anonymity.
Chaincode upgrades and channel governance can change behavior in the future;
append-only guarantees here apply to these explicit transaction methods.

## Tests and scope

Run the README's Node test command. Tests cover writer/reader authorization,
immutable retry/conflict behavior, independent later publications, original
evidence-state preservation, malformed/private inputs, transaction IDs, simulated
MVCC conflicts, read/write outages, corrupt state, wrapper transaction inventory
and Python-to-JavaScript canonical/Merkle compatibility. The wrapper API test uses
a stand-in Contract class; it does not instantiate a running Fabric peer.
The original evidence contract tests run alongside these new tests.

No Docker/network, production keys, CA enrollments, original CSV/database changes,
chaincode lifecycle actions, wallet use or ledger submissions occur in these tests.
No real Fabric deployment/consensus or live research is claimed. RPC 1 remains deferred.

## Primary API references

- [Fabric ClientIdentity API](https://hyperledger.github.io/fabric-chaincode-node/main/api/fabric-shim.ClientIdentity.html)
- [Fabric 2.5 read/write set semantics](https://hyperledger-fabric.readthedocs.io/en/release-2.5/readwrite.html)
- [Fabric 2.5 endorsement policies](https://hyperledger-fabric.readthedocs.io/en/release-2.5/endorsement-policies.html)
