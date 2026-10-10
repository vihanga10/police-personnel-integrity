# Protected contradiction findings capture V1

This trusted-backend adapter connects a fresh verified contradiction run to the encrypted findings journal, separate registry and independent latest-tip witness. It adds no CLI or user endpoint. It neither enables intake nor provisions any research storage, keys, certificates or services. It makes no database, CSV, wallet, RPC or blockchain changes. RPC 1 remains deferred.

## Entry and trust boundary

`capture_contradictions(args, repo, revision, recording, findings, **kwargs)` requires the exact configured recording mutual-TLS adapter and the findings adapter with fixture transport disabled. Transport scope, repository, signing key and provisioned profile pins must agree. It invokes the existing `load_verified_snapshot` full original-anchor replay and live-readiness checks once; there is no permit-only alternative or waiver. All keys, transports, storage paths and snapshot objects come from trusted backend configuration, never request payloads.

The internal `capture_loaded` entry accepts only a snapshot supplied by that full loader. Test fixtures use it with isolated in-process witnesses. It does not independently authenticate arbitrary caller-supplied catalog dictionaries. Never expose this internal entry or `fixture_transport` to a public API. Fresh readiness is required on every operational invocation, including retries. A fresh permit cannot extend the original permit's deadline during an invocation.

Required capture arguments: canonical officer, operation and finding UUIDs; a calendar `effective_on`; an aware UTC `known_at` within authenticated history coverage; and a new receipt destination in an existing owner-only directory outside the repository and all protected stores. The findings journal must use the producer's primary and backup encryption key maps. Recording and findings stores must be separate and nonoverlapping. A correction supplies the current finding head ciphertext hash as `supersedes` and an explicit reason, preserving its finding UUID. New operations require new UUIDs and receipt destinations.

## Verified intent and publication

Before producing a receipt, the adapter obtains fresh verified recording and findings selections. It rechecks baseline scope, original publication, context and source header policy against replayed evidence and matches all baseline source claims exactly. It recomputes both bitemporal reconstruction and contradiction comparison at the requested times.

An encrypted, writer-signed capture intent is published before producer execution. It binds the exact operation, finding, officer, ledger and registry; original source and publication digests; context; query times and digests; receipt path; exact findings predecessor; correction lineage and actual intent creation time. The intent file is `<destination>.capture-intent.encrypted.json`, with owner-only permissions. It is backend recovery metadata, not a personnel finding, database intake receipt or blockchain commitment.

The existing protected contradiction runner produces the dual-key encrypted receipt. Capture then validates its envelope and full result against the recomputed historical query/comparison, original replay context and current verified recording history. An older recording tip is permitted only when it remains a preserved ciphertext prefix with its checkpoint retained and the same historical result still recomputes. A change outside the requested historical view does not invent a new known-at date or invalidate preserved evidence arbitrarily.

The journal's backward-compatible `before_publish` callback is added only to receipt appends. Existing calls retain their behavior. This callback rechecks the permit, source digest/context/publication, recording witness pins, fresh recording selection, full receipt bytes/result and fresh findings witness predecessor after encrypted staging, immediately before the nonoverwriting journal publication. It is a trusted internal callback, not user-supplied executable input. Future integrations must not call capture while holding recording-store locks: capture can acquire recording locks while holding findings locks.

Existing findings registry/witness integration then verifies the journal chain, publishes the registry advance, fsyncs local directories, performs signed witness compare-and-swap and verifies the fresh acknowledged selection. No successful `CAPTURED` result is returned until this completes and the permit is checked again. Summaries contain no officer information, leave `accepted_state` unset and report `findings_anchored=False`. Sensitive full findings are accessible only through existing authorized backend selections; this package creates no UI access rules.

## Retries, interruptions and corrections

The signed intent keeps retries bound to the original request and predecessor. No intent means an already-existing receipt is refused. A changed request, context, comparison, receipt or predecessor cannot silently adopt an old receipt or rebase the capture.

If intent exists but producer output does not, identical retry can resume producer execution. If a complete receipt exists but no finding was appended, identical retry revalidates it before publication. A completed operation is returned as `ALREADY_CAPTURED` only after fresh witness-backed selection and exact equality of kind, finding UUID, full receipt digest/result, lineage and expected sequence. No duplicate entry is appended.

There is no distributed atomic transaction across receipt, journal, registry and witness. Interruptions can leave complete encrypted artifacts. They are retained. Journal-only or locally registered but unacknowledged findings block ordinary selection and require the existing separately signed inventory-pinned findings recovery authorization. After reconciliation, identical capture retries are safe. A witness commit with a lost response can be recognized by fresh HEAD without an extra append. Do not delete intents, guess latest filenames, reset enrollment, bypass expired permits or invent replacement operation metadata to clear a failure.

Corrections append a new entry for the same finding with the exact current finding head and explicit reason; stale predecessors cannot branch. Earlier findings and reviews remain intact. This adapter records algorithm output, not an accepted personnel fact. Personnel temporal authority for human reviewer decisions remains a separate pending integration.

## Validation and limits

Focused fixtures cover encrypted witnessed capture, unchanged retries, invalid scope/time/IDs, changed retry requests, preexisting receipt refusal, producer interruption, changed findings predecessor, final-publication guard failures, correction lineage, stale correction refusal, receipt/intent tampering, both phases of witness acknowledgment interruption, preserved earlier-known history and the public entry with two real loopback mutual-TLS services. The full snapshot loader is mocked in that transport fixture; actual live readiness is not claimed.

Existing findings, registry, witness, protected runner and contradiction suites are run for compatibility. Fixture passes establish development behavior, not independent accuracy, completeness or research validity. No production findings journal/registry or witness service is provisioned. Witness administrative independence and restore protection remain operational requirements; simultaneous rollback of both local stores and the witness itself is outside this core's protection. Authority/reconstruction producer capture, reviewer temporal authority, scoped UI, dual-chain findings commitments, independent evaluation and live integrated execution remain pending.
