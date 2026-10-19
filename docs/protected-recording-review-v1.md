# Protected recording metadata review

This additive backend adapter reviews an explicit selection of complete
`identity.source_assertion` rows against the original replayed catalog and
destination bindings. It does not execute research or issue an audit permit.

`review_recording_rows(args, repo, revision, rows, raw_ids, destination)` calls
the existing `load_verified_snapshot` before any review. Use the same arguments
and current full Git revision as existing protected algorithm runners. The
loader authenticates both recovery copies and reproduces the full anchored
snapshot. It still requires fresh live readiness; RPC 1 remains deferred for
local development. There is no offline bypass or newly fabricated permit.

`review_loaded_snapshot` is an internal trusted-runner boundary for an already
replayed snapshot, never an HTTP endpoint or user-supplied dictionary. The
permit by itself does not authenticate arbitrary catalog or binding inputs.
The adapter detects changes during processing; callers must not modify the
snapshot or selected rows concurrently. Local output paths are trusted backend
configuration, not remote request parameters.

Each selected raw ID must produce exactly one bound assertion row. Missing,
duplicate, extra or changed rows fail. This selection does not imply coverage
of all officers, all assertions or all corrections. Inputs from corrections
outside the old anchored snapshot cannot be added under its permit.

Both keys recover the sealed review exactly. The existing permit is checked at
entry, for every row, after encryption, and immediately before atomic
publication. Its original deadline is never extended. The destination must be
outside the repository, under an existing owner-only directory, without
symlinks. Publication uses a private temporary file and a non-overwriting hard
link. Failed validation produces no completed review. An I/O durability error
after the hard link may leave the complete file published; inspect it rather
than attempting to overwrite it.

The encrypted result explicitly reports:

- Database-reported transaction-start semantics.
- Visibility time not established.
- Complete history not established.
- Historical known-as-of queries not supported by this review.
- No accepted state.

PostgreSQL transaction start can precede commit/visibility. These timestamps
must not become historical intake receipts. This newly sealed review is
derived metadata, not evidence that the system knew a fact on an earlier date.
Real historical queries still need authenticated intake/version event receipts,
predecessor/correction lineage and independently justified history coverage.

Local tests use synthetic publication and chain-result fixtures adapted from
the supplied gate tests. Only the expected publication hash is patched to the
fixture hash. Actual gate checks, permit encryption, row fingerprinting,
AES-GCM and recovery run unchanged. The full database/chain loader is not
executed locally. These tests do not establish live readiness or source truth.

No CSV, database, wallet, RPC or blockchain writes are included. Existing
anchors are unchanged. Findings storage and findings anchoring remain separate
unfinished research work.
