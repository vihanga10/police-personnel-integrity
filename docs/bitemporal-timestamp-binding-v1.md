# Bound database recording timestamps

This additive development step verifies an actual `identity.source_assertion`
row against its exact previously captured full-row destination binding, checks
its source catalog and subject-role membership, and exports timestamp metadata
through the existing authenticated encryption and both-key recovery functions.

It does not change any existing algorithm or runner. It reads no database,
issues no permit, writes no receipt to disk, creates no evidence version, and
submits no blockchain transaction. RPC 1 remains deferred.

## Important evidence limit

The current source catalog omits `transaction_start` and `transaction_end`.
The destination artifact binds them inside the complete SQL row fingerprint.
The caller must supply that complete row; a claimed timestamp alone cannot be
verified against a hash. Catalog and binding inputs must first pass the existing
all-officer commitment replay. This module does not authenticate arbitrary
catalog dictionaries or arbitrary expected row hashes.

The supplied model defines `transaction_start` with PostgreSQL `func.now()`.
A transaction-start timestamp can precede commit and visibility. Verification
establishes the captured database-reported value, not the exact visibility
instant. Both `visibility_time_established` and `complete_history_established`
remain false. Receipt sealing authenticates this verified metadata; it does not
add evidence of source truth, commit time, completeness or legal authority.

The encrypted receipt is newly derived metadata, not a historical import receipt.
Its creation must never be backdated or used to fill missing recording history.
The actual fields `source_recorded_at`, `captured_at`, CSV effective dates, file
modification times, the current time and block timestamps are not substitutes.

Superseded and withdrawn database states are preserved as metadata. This release
does not infer predecessors or remove claims from historical answers based only
on the current assertion state.

## API and integration boundary

`verify_recording_timestamp(row, catalog_row, destination_bindings)` verifies
source identity, officer subject membership, catalog provenance, exact row bytes
through typed fingerprinting, and timestamp shape and ordering.

`seal_recording_receipt(record, crypto, backup, source_context)` encrypts verified
metadata with its exact payload digest and selected evidence context.

`open_recording_receipt(envelope, crypto, backup, expected_record, source_context)`
requires an independently verified expected record, exact context and both-key
recovery. It never trusts the envelope's own binding as an external expectation.

No live CLI is provided. Future protected integration must obtain complete rows
using the restricted read-only SQL account; validate the full original evidence
snapshot; check an actual fresh AlgorithmPermit before metadata processing, after
processing and immediately before private persistence; and retain source context.
All diagnostics must remain value-free, and saved metadata must stay encrypted.

Actual bitemporal history construction additionally needs authenticated intake or
version recording events, correction predecessor links and evidence of history
coverage. Existing archive integrity receipts and one collected snapshot do not
prove those. Reject unsupported historical knowledge dates instead of inventing
versions or claiming no evidence existed.

## Installation and checks

Extract `bitemporal-timestamp-binding-step.zip` in Downloads, outside the repo.
The installer requires a clean `feat/identity-resolution` branch, ancestor
`cecefb6`, and exact reviewed source dependencies. It adds only this new module,
its tests and this document. Existing targets are never overwritten.

```bash
cd "$HOME/Downloads/bitemporal-timestamp-binding-step"
python3 install.py --repository "$HOME/Developer/police-personnel-integrity" --check
python3 install.py --repository "$HOME/Developer/police-personnel-integrity"
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python -m pytest tests/test_bitemporal_timestamp_binding.py tests/test_bitemporal_reconstruction.py -q
```

Local fixture validation: 33 tests covering complete-row fingerprint changes,
missing timestamps, invalid intervals, provenance mismatches, subject membership,
actual AEAD, context mismatch, false assurance and recovery-key failures. These
checks establish local verifier behavior; they are not a live audit.
