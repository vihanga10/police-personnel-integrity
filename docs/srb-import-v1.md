# Guarded SRB import v1

## Scope and completed prerequisites

This local development CLI prepares or reconciles the reviewed BATCH-RAW-001
SRB evidence: 15,123 police-number rows, 10,971 restrictions and 150 overrides.
Prerequisites: migration c95e3a17bd40, the dedicated SRB Mongo account and
collections, and delivery checkpoint ddda777 with 117 unit tests and 15 real-driver
interruption cases passed on the operator's Mac. Independent durable SQL commit
recovery is exercised by SqlSrbLedger during the actual importer workflow.

## Gates and preservation

Default validation and --reconcile perform no database writes. --write is an
explicit, mutually exclusive mode; this package's next operator step is validation.
The CLI refuses dirty source, unreviewed batch fingerprints or row counts, changed
source/header/sequence, ambiguous subject NICs, unusable actor candidates, missing
or ambiguous source-qualified references, conflicting override subjects, station
mismatches and all structural review issues. It recovers every source row and
plan using primary and backup keys. Complete restriction/transfer/override snapshots
are checked before any write, including restriction override flags and explicit
bounded number-period intersections. Missing endpoints remain unknown.

SQL assertions and preparations are committed together, then the exact BSON is
inserted/read back in Mongo, then an immutable SQL completion receipt is appended.
Retries reuse existing ciphertext. Completed evidence missing in Mongo is an
integrity error, not an automatic repair. Unexpected preparations, orphan assertions
and orphan Mongo documents stop validation. Each row is replanned before delivery;
the SQL adapter independently rechecks originals, NICs, actors and linked records.
Private attempt journals contain opaque record IDs, keyed preflight fingerprints
held only in memory, policy/code hashes and aggregate outcomes; no personnel values.
All payloads stay encrypted and classification UNASSESSED. Number validity,
restriction effects, override authority and accepted intervals are not established
by import. Overrides are preserved and never automatically applied.

## Human authorization remains separate

This is a local development CLI, not an authenticated human intake endpoint.
The agreed application rule remains HQ Admin-only import/entry. Full RBAC/ABAC,
IGP approvals, scoped disclosure and human access logs remain pending. No user
viewing access is enabled by this command. Stage 2 remains in progress.

## Next operator step: read-only validation

Commit the reviewed new source after tests; run from backend:

```bash
uv run python -m app.identity.import_srbs \
    --batch-id BATCH-RAW-001 \
    --expected-archive-sha256 32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2 \
    --confirmation ../docs/intake-source-confirmation.json \
    --expected-confirmation-sha256 b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481 \
    --expected-number-rows 15123 \
    --expected-restriction-rows 10971 \
    --expected-override-rows 150 \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json" \
    --srb-credential-directory "$HOME/ResearchKeys/police-personnel-integrity/mongo-srb-v1" \
    --attempt-root "$HOME/ResearchEvidence/police-personnel-integrity/srb-import-attempts"
```

Expected coverage: 26,244 rows; zero structural review rows; observations
MISSING_END_NOT_EXPLICIT_OPEN_INTERVAL=10,774,
MISSING_REMOVAL_NOT_PROOF_OF_ACTIVE_RESTRICTION=10,137 and
OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED=150. Initially all deliveries are PLANNED.
Stop on any discrepancy. Inspect aggregate validation output before using --write.
After a completed write, use the same command with --reconcile and separately
check SQL/Mongo counts. Expected new SRB assertions/preparations/completions=26,244;
source assertions total=110,692; source systems=3; SRB Mongo counts=15,123/10,971/150.
Existing profile/service/history counts must remain unchanged.

## Local validation

140 focused tests passed in the package build environment. These unit tests do
not prove actual research batch import. The already completed Mac driver recovery
check verifies the delivery prerequisites; actual batch validation is next.
