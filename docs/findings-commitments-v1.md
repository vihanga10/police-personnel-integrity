# Privacy-preserving findings commitments V1

This step prepares per-officer findings-history commitments for later private-ledger and public-chain anchoring. It adds a pure commitment/proof core and a protected preparation adapter. It submits no transactions, changes no existing chaincode or contracts, and does not provision keys or storage. Existing evidence commitments and original anchors remain unchanged. RPC 1 remains deferred.

## Covered history and research meaning

One preparation covers the complete current witnessed selection from one findings ledger: every FINDING, CORRECTION and REVIEW entry, including exact values, reasons, query/comparison evidence, signed review/authority packets and explanations, operation IDs, recorded timestamps, ciphertext pins and correction/review links. The private selection also retains the exact journal and registry tips, witness scope and existing reported/unaccepted/anchoring flags. Entries retain their original order privately; none is rewritten or omitted.

A commitment authenticates the committed bytes against an approved artifact and subsequent anchor. It does not establish the truth of a personnel fact, correctness of a human assessment, completeness of external source changes or research accuracy. Legacy unassessed reviews remain legacy reviews; they do not gain temporal authority through hashing. The complete signed authority proof of a newer protected review is preserved without exposing it publicly.

## Dedicated keys and private salt

`FindingsCommitmentKeys` uses policy `FINDINGS_COMMITMENT_KEYS_V1`, version `findings-commit-v1`, and separate 32-byte content/publication keys. They are distinct from original officer commitment keys, local encryption/lookup keys, available local signing seeds and pinned public keys. The primary and backup key files must be separate owner-only files outside the repository and recover exactly the same configuration. No initializer, example production secret or default operational key is supplied.

The protected adapter checks all available journal, registry and snapshot key domains. Remote witness encryption keys and private reviewer/assessor keys are not exposed to the adapter and cannot be inspected by it; provisioning must independently enforce separation from those secrets as well. Key provisioning, escrow and rotation require a separately reviewed operational process. The fixed version here does not implement rotation or unsigned substitution of keys.

Each new preparation chooses a fresh cryptographically random 32-byte salt. The salt stays inside the encrypted manifest. Publication and entry handles use the publication key; content/history/publication MACs use the content key. Both use SHA-256 HMAC over canonical arrays containing the findings policy, key version, explicit domain and exact payload. This is a keyed commitment, not an unkeyed hash of predictable identities or a digital signature. Key custody and approved artifact/anchor pins remain essential.

Repeated preparations of the same history in different attempt directories produce different opaque handles and roots. Within one attempt, a retry reuses the saved salt and exact original context. This supports per-officer publications without publishing a stable officer identifier or making correction/review links public across epochs. Authorized custodians retain the encrypted mapping; old preparations remain verifiable and are never overwritten.

## Public payload and ordered Merkle tree

The public payload contains only a fixed policy/version/key-version label, opaque publication handle, sorted opaque entry handles with keyed commitments, a keyed history commitment, a keyed publication commitment and the Merkle root. No officer UUID, NIC, name, ledger UUID, scope ID, raw evidence hash, reviewer identity, event/review date, decision, correction link, signing key, salt or explanation appears in it.

Entries sort by their opaque handles instead of chronological order. Each public leaf has the same `FINDINGS_ENTRY` tag regardless of its actual private entry kind. A separate `FINDINGS_HISTORY` leaf binds the policy/version/key-version metadata, opaque publication ID, entry count, history MAC and publication MAC. The publication MAC binds the complete private history context, all public entry commitments and history MAC. The history MAC binds the complete verified selection and preparation context. No original publication or findings ciphertext digest is exposed as a plain public field.

The existing tree framing is reused: leaf = SHA256(0x00 || canonical leaf); parent = SHA256(0x01 || left || right). Odd nodes duplicate themselves. The history leaf covers the manifest even when an entry inclusion proof is independently verified. Public validation enforces exact fields, canonical ordering, unique entry handles/commitments and the recomputed root. Changing the public history MAC also changes the root.

`inclusion_proof(public, publication_id)` produces the opaque leaf, its index, leaf count and ordered sibling hashes/directions. `verify_inclusion` validates the public schema/root, exact leaf membership, count/index shapes, every direction, odd-node duplication and exact proof length. A public observer can check opaque leaf inclusion. An inclusion proof does not authenticate a caller-provided root: compare the public payload digest and root against an independently approved publication or verified chain receipt before treating inclusion as anchored. Recomputing a commitment from sensitive plaintext requires authorized custodial access to the separate commitment keys and encrypted manifest; do not disclose those keys to enable public verification.

The payload reveals the number of entries. Public transaction timing, publishing accounts, external disclosures and other metadata could still permit correlation. This format limits direct identifier/content disclosure; it does not promise anonymity or eliminate traffic analysis.

## Protected preparation

Operational `prepare(args, repo, revision, findings, *, key_file, backup_key_file, directory)` requires the exact configured findings witness adapter with mutual TLS and fixture mode disabled. It uses the existing full original evidence replay and fresh dual-chain readiness loader, and checks original commitment-key recovery before and after replay. There is no RPC 1 waiver, permit-only shortcut or cached witness fallback.

The internal `prepare_loaded` accepts only a snapshot from that full trusted loader and backend-owned configured objects. Its fixture use is not an operational permission. The subject must belong to the original anchored officer universe. The output is an existing owner-only, dedicated directory outside the repository and separate from findings stores. Symlinks, traversal, unrelated artifacts and orphaned public output are refused. No public endpoint or CLI is enabled by this package.

Preparation fetches the complete fresh witness-verified findings selection. It freezes source/context/publication and key/configuration digests, repeatedly authenticates the permit, and reselects that same full history immediately before each publication and again before returning success. Any history advancement, outage, source/configuration/key change or expired permit blocks completion. This is freshness at the checked instants, not a promise that no later append can occur.

The preparation timestamp comes from the actual backend clock. It must not precede the latest recorded finding; clock rollback during preparation is refused. Original recording timestamps and effective dates remain unchanged. The timestamp does not create new evidence intake history or backdate old CSV observations.

## Files, retries and interrupted writes

The adapter publishes `findings-commitments.encrypted.json` first. Its primary and backup AEAD recovery must agree; the binding contains only the findings policy and digest of the opaque public payload. The private manifest retains the salt, exact preparation context, current history selection and matching public payload. It contains no commitment keys.

It then publishes `public-findings-commitments.json`. Both files use owner-only permissions, staged/fsynced writes, nonoverwriting links and directory fsync. The public payload file remains in a private attempt directory until a later controlled publication workflow exports it.

A complete preparation returns a redacted PREPARED result with public payload digest, encrypted-manifest ciphertext digest, `latest_history_checked=True`, `findings_anchored=False` and no accepted personnel state. These exact digests must be retained through an independently trusted approval/checkpoint or anchoring workflow; this step does not deploy a commitment-tip service or transaction registry.

There is no multi-file atomic transaction. A failure after the private manifest is published preserves it. If the same witnessed history, source context and keys still hold, a fresh protected retry verifies the private intent and regenerates the exact public payload with its original salt/time. It does not create a second variant or overwrite either file. If history has advanced, retry in that old directory fails; preserve it for inspection and use a new authorized attempt. No automatic deletion, cleanup of unknown staging files or rebasing occurs. Ordinary temporary files are removed by the operation that created them.

Partial findings journal/registry/witness writes must first be resolved through the already implemented signed findings recovery process. Commitment preparation cannot bypass that process or choose a convenient old local history.

## Verification and future anchoring

`verify_prepared(..., expected_private_sha256=...)` requires an externally approved encrypted-manifest hash, both recovery keys and exact findings commitment-key recovery. It decrypts the pinned manifest, regenerates all keyed commitments and the root, and compares the saved public payload. It neither connects to a witness nor obtains new research readiness; its result explicitly says `latest_history_checked=False` and `findings_anchored=False`. It can verify a preserved old preparation after the findings journal has advanced. A caller-supplied untrusted hash alone is not an independent approval.

The pure `generate` API validates basic history structure but authenticates no signatures, custody, completeness or witness HEAD. Only the protected entry may represent preparation of a fresh verified selection. A fresh preparation context identifies the replayed original publication used by its readiness gate; it does not retroactively claim that every low-level stored finding was created through a protected producer. Operational routing must retain the already established protected capture/review boundary.

Later integration must validate the approved public payload/root and exact attempt digest, use a separate findings namespace on the private ledger, read back the committed record, anchor the approved private-ledger result on the public chain, and verify both chains/receipts/finality. No payload here contains transaction IDs or claims that either chain has accepted it. Actual submission, authorization, cross-chain linkage, retry deduplication and receipt reconciliation remain pending; original evidence anchors must remain untouched.

## Local validation

Tests use disposable stores/keys and invented evidence. They cover exact complete content, legacy and authorized reviews, fresh-salt unlinkability, private permissions/public field restrictions, deterministic same-attempt retries, all entry-content changes, public/proof tampering, odd nodes, original/encryption/lookup key separation and backup mismatch, externally pinned saved verification, interrupted output and witness failures, old-attempt refusal after new history, final-publication guards, path boundaries and actual loopback mutual TLS with a mocked original loader. These tests do not establish independently measured research accuracy or production security deployment.

Authority configuration, operational findings/commitment storage, witness deployment, findings anchoring on both chains, scoped UI and independent evaluation remain pending. No live research has run, and RPC 1 remains deferred.
