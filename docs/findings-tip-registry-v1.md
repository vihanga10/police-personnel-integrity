# Independent findings tip registry and guarded recovery V1

This is an additive trusted-backend integration for `FindingsJournal`, not a deployed service. `FindingsTipRegistry` owns a separate owner-only directory, separate AEAD encryption/lookup keys and separate Ed25519 registry and recovery signer domains. Writer, reviewer, registry and recovery public-key sets must be disjoint. Registry encryption/lookup secrets cannot overlap journal secrets, and registry/recovery signing seeds cannot reuse journal encryption/lookup keys. Primary and backup registry recovery must agree. No keys or directories are provisioned by the installer.

## Exact trusted selection

A trusted controller supplies the registry UUID, journal/ledger scope, paths, keys and latest independently retained `expected_registry_tip`: `{registry_id, sequence, entry_sha256}`. No endpoint or CLI accepts this configuration from users. `empty_tip` is only for separately authorized new registry enrollment, never a fallback after missing state. There is no latest-filename scan and no silent reset.

Each append-only encrypted signed registry entry pins exactly one additional findings-journal entry, its operation UUID, ledger UUID, registration timestamp, predecessor registry ciphertext SHA256 and the complete configured public-key-map digests. `select` replays the registry against the supplied independent pin and the complete findings chain against the signed current journal tip. Every registered operation, intermediate journal ciphertext pin and recording-time relationship must match. This preserves the findings/corrections/reviews and their original provenance without changing those journal files.

The registry is separate local storage with an independent key domain. It is not a remote independent witness. **Simultaneous rollback of registry, journal and independently retained latest pin cannot be detected here.** A test explicitly demonstrates that a complete old prefix can pass with an old pin, while the same rolled-back stores fail against the newest independently retained pin. Durable latest-tip witness integration and independent service protection remain pending; never advertise this local registry as a complete anti-rollback solution on its own.

## Guarded appends

`append_receipt` and `append_review` first verify the registered history, then call the existing journal's append-only API and register its new exact tip. Matching-content retries against the current registry pin return `ALREADY_REGISTERED` without writing. A stale registry pin, pending unregistered finding, changed retry, unknown artifact, signature/hash mismatch, scope drift or key-pin change blocks normal operations. Key rotation management is not implemented; changes require an explicit future migration rather than silently altering verification maps.

Cooperating adapter operations hold the registry directory lock; journal verification/publication takes the journal lock in registry-then-journal order. Direct journal writes remain possible for trusted backend foundation code, but become unregistered pending history and block adapter selections until authorized recovery. No distributed atomic transaction is claimed. The controller must independently durably retain a returned registry tip after successful publication; that independent retention service is not installed here.

## Two interrupted-write cases

1. Journal entry published, registry entry absent: ordinary selection fails. A trusted recovery issuer approves exactly the old independent registry tip, one pending complete journal tip and its operation UUID. Recovery replays the preserved prefix and pending journal, then appends a signed registry entry containing the recovery authorization.
2. Registry entry published, success response lost: recovery additionally names the exact pending registry tip. It verifies one additional registry entry and the matching finding/operation, and returns the surviving tip without rewriting either store. Returning that same already-surviving tip under the same still-valid inventory-bound authorization is idempotent.

`authorize_recovery` is a trusted issuer helper, not a user permission endpoint. A separate pinned recovery signer signs exact inventories of both directories, UUID/scope, old/pending pins, operation, configured key pins, issuance and expiry. It validates the candidate histories before issuing the authorization. Validity is bounded to at most 600 seconds. `recover` checks signature, scope, time, exact current inventories and precisely one pending advance. Expired/future/altered/foreign-key or operation-mismatched authorizations fail closed; two pending findings cannot be silently skipped. Inventory and freshness checks repeat immediately before registry publication. No entries are deleted or overwritten.

Historical replay validates a stored recovery authorization at its original registry registration time, not today's clock; expiry does not invalidate the recorded past recovery. A recovered already-published registry entry does not append an extra recovery-audit record. Controllers must retain that authorization in their protected operational audit if required; that audit-service integration remains pending. Unknown registry artifacts, including interrupted staging files, block operation and are preserved. This module does not authorize deleting them or repair incomplete/corrupt ciphertext.

Exclusive 0600 publication, fsync, dual-key recovery and signature verification protect complete entries. A failure after link or directory-fsync may leave a complete pending registry entry even though the caller saw an error. A new signed recovery authorization can reconcile it using explicit surviving ciphertext hashes; there is no expiry waiver or automatic local latestness selection.

## Semantics and access

Registration timestamps come from the current recorder clock and must not precede journal recording time or move backward. They are registration observations, not CSV event dates or invented historical system times. Review authorization continues to be signer-key allowlisting only; temporal role/delegation/scope verification remains pending. Registry authorization is also a configured recovery capability, not personnel action-date authority.

`select` returns sensitive plaintext to an authorized backend only. Summaries expose status and opaque encrypted-store pins, never officer IDs or evidence values. Stored comparisons retain reported-only semantics. `accepted_state=null` and `findings_anchored=false`; no finding becomes accepted truth because it is registered. Protected producer capture, scoped UI access, other finding types, independent research evaluation, salted HMAC findings commitments and dual-chain anchoring remain pending.

## Local development tests

Disposable fixtures cover restart and complete provenance selection, correction/review registration, idempotent retries, stale/missing/rolled-back history, signatures and ciphertext, domain separation, concurrent stale writers, pending findings, journal and registry lost responses, inventory-bound recovery, expiry/future/wrong-key/wrong-scope/operation/hash rejection, preserved prefix recovery, signed metadata mismatch before append, simultaneous rollback against old/new independent pins, staging failure, midflight inventory changes and encryption/signing key separation. Existing findings-journal and protected contradiction suites accompany the new tests.

No production registry, findings journal, independent latest-tip service, witness service, research schema, intake hook or keys are installed. No CSV, research database, wallet, RPC or blockchain operations are performed. RPC 1 remains deferred; no live research has run.
