# Multi-dataset intake pipeline v1

Status: implemented and tested offline (in-memory storage and ledger stand-ins,
real accounts, sessions, planners and acceptance rules). Live deployment of the
dedicated Fabric chaincode and Sepolia contract is pending and requires the
operator steps below.

## Scope

Fifteen officer datasets from `BATCH-RAW-001` gain the same controlled path as
`promotion_history.csv`. Promotions keep their existing pipeline and ledger
destinations; they also gain independent IGP row review.

| Dataset code | File | Effect of an accepted row |
| --- | --- | --- |
| TRANSFER_HISTORY | transfer_history.csv | Displayed posting (station, unit, division, province) from the effective date; a reported cancellation has no effect |
| POLICE_NUMBERS | officer_police_numbers.csv | Displayed number per number type from `valid_from` |
| RESTRICTIONS | officer_restrictions.csv | Listed as an accepted active restriction until removal or override |
| RESTRICTION_OVERRIDES | restriction_overrides.csv | Removes the overridden accepted restriction from the active list |
| SERVICE_INFORMATION | officer_service_information.csv | Accepted snapshot becomes the displayed service baseline (always needs IGP row review) |
| DEMOTIONS | _demotions_enacted.csv | Displayed rank from the punishment date (derived source; always needs IGP row review) |
| DUTY_PERIODS, FIREARMS, GOOD_CONDUCT, BAD_CONDUCT, EDUCATION, FAMILY, COMPLAINTS, OPERATIONS, COURT_CASES | remaining files | Record only; shown under each linked officer with its acceptance status |

Out of scope for v1: `officer_personal_information.csv` (new officer
registration needs identity resolution and new signed directory membership and
grants) and the two station reference files.

## Flow

1. **HQ preview.** An HQ_ADMIN importer selects the dataset and the represented
   source system (only those registered for that file in
   `file_source_mapping.json`). The exact header is required. Each row is
   validated by the reviewed planner for its file, with three lookups:
   exact-NIC subject and actor matches from the signed directory; the station
   index from the verified original `station_master.csv`; and cross-row
   references (overrides to restrictions and transfers) from the original
   archive and from earlier queued uploads. One row needing review blocks the
   whole batch.
2. **Duplicate and rewrite protection.** Every original row identity
   (146,081 across 15 files) is indexed from the checksum-verified archive. An
   upload that repeats an original or earlier row is a DUPLICATE and is not
   stored again. Changed content under an existing source identity is a
   SOURCE_ID_CONFLICT and blocks the batch.
3. **Independent IGP batch approval.** A configured IGP account, never the
   uploader, approves processing of the exact file digest and row set, rejects
   it, or requests changes. The approval is bound to the batch and re-checked
   against the reviewer's live account before every processing step.
4. **Delivery.** The worker seals each row (AES-GCM, dataset-scoped AEAD
   domain) and writes it to `personnel_intake.evidence` (PostgreSQL) and
   `police_personnel_intake.upload_events` (MongoDB). It uses a dedicated
   least-privilege writer, append-only triggers and validators, and exact
   ciphertext readback.
5. **Publication.** A dataset-coded commitment goes to the
   `personnel-intake-anchor-v1` Fabric chaincode and then to the
   `PersonnelIntakeAnchor` Sepolia contract. Fabric receives `dataset`,
   `publication_id`, `public_sha256`, `merkle_root` and
   `publication_commitment`. Sepolia additionally binds the Fabric destination,
   transaction ID and receipt digest. No personnel values or identifiers are
   published. Transactions are planned, retained and reconciled before any
   retry, so a lost acknowledgement never causes a duplicate publication.
6. **Availability.** After both chains verify, an append-only activation is
   recorded at its actual time. Uploaded transfers, numbers, restrictions,
   overrides, demotions and service rows then enter the officer's recording
   history. Earlier knowledge-boundary queries are unchanged.
7. **Row acceptance.** Each verified row is evaluated as ACCEPTED,
   PENDING_REVIEW or NOT_ACCEPTED. Every evaluation is appended to an encrypted
   decision journal with lineage, then written to the accountability log, which
   is anchored to Fabric.
8. **Independent IGP row review.** A PENDING_REVIEW row can be accepted or
   rejected by a configured IGP reviewer who is not the uploader. The reviewer
   must give a reason and an evidence reference. The review is bound to the
   exact evaluation digest, so any later evidence change voids it. Blocking
   issues can never be reviewed into acceptance.
9. **Display.** The officer page shows verified uploaded records grouped by
   dataset, each with its acceptance outcome and Fabric and Sepolia
   transaction references. `current_state` applies only accepted, currently
   effective changes, states the basis and acceptance reference of every
   changed field, and lists accepted future changes separately. Signed source
   profiles are never modified. Scope membership stays with the signed
   directory, so an accepted transfer never widens anyone's access.

## Acceptance rules

Every row needs IGP processing approval. Where the file reports an authority
action (transfers, restrictions, overrides, duty periods, firearms, good and
bad conduct, family attestation, complaints, operations), VALID authority from
a signed assessment is required; CANNOT_VERIFY leaves the row pending for
review, and INVALID makes it NOT_ACCEPTED.

Blocking (never reviewable): IGP_PROCESSING_APPROVAL_REQUIRED,
EFFECTIVE_DATE_REQUIRED, INTERVAL_ORDER_INVALID,
FROM_POSTING_DIFFERS_FROM_CURRENT_ACCEPTED_SEQUENCE,
EARLIER_POSTING_CHANGE_REQUIRES_REVIEW,
MULTIPLE_UPLOADED_TRANSFERS_AT_SAME_EFFECTIVE_DATE,
CONFLICTING_ORIGINAL_TRANSFER_AT_EFFECTIVE_DATE,
MULTIPLE_UPLOADED_NUMBERS_AT_SAME_EFFECTIVE_DATE,
OVERLAPPING_ORIGINAL_NUMBER_INTERVAL, OVERRIDDEN_RESTRICTION_NOT_FOUND,
UPSTREAM_PUNISHMENT_NOT_FOUND, DEMOTION_RANK_EVIDENCE_UNRESOLVED and
DEMOTION_MUST_DECREASE_RANK. For promotions: the rank-sequence, rank-direction,
same-date and original-conflict codes.

Reviewable: unassessed authority, SERVICE_STATUS_REQUIRES_REVIEW,
SERVICE_SNAPSHOT_REPLACEMENT_REQUIRES_REVIEW and
DERIVED_NON_INDEPENDENT_SOURCE.

## Separation of keys and destinations

The dataset intake key, chain-recovery key, Sepolia writer wallet, PostgreSQL
and MongoDB writers, Fabric writer attribute (`intake.anchor`) and runtime
source pins are all separate from the promotion, accountability, access and
workspace keys. The runtime refuses to start if any of them coincide.

## Operator steps (application stopped)

```bash
cd ~/Developer/police-personnel-integrity/backend
uv run python scripts/manage_dataset_pipeline.py initialize      # keys, writers, verified-archive baseline
uv run python scripts/manage_dataset_pipeline.py storage         # personnel_intake schema, Mongo collection, writers
uv run python scripts/manage_dataset_pipeline.py wallet          # new Sepolia writer; fund it with test ETH
uv run python scripts/manage_dataset_pipeline.py network
uv run python scripts/manage_dataset_pipeline.py public-preview
uv run python scripts/manage_dataset_pipeline.py public-deploy   # one signed deployment, retained journal
# Fabric: deploy personnel-intake-anchor-v1 and enrol the intake.anchor writer (to be scripted with Fabric running)
uv run python scripts/manage_dataset_pipeline.py configure
uv run python scripts/manage_dataset_pipeline.py enable
uv run python scripts/manage_promotion_pipeline.py refresh-pins  # after committing this source
```

## Test evidence (this revision)

- Backend: 3,872 passed and 89 skipped across the full suite. The 3 failures
  are operator-setup tests that require port 8443 to be free while the live
  application was running.
- Dataset pipeline, row review and HTTP boundary: 16 + 7 + 4 dedicated tests.
- Fabric intake chaincode: 4; intake gateway: 50; Sepolia contract, live
  adapter, gas cap and worker: 34 (local ganache EVM).
- Frontend: 140, including 4 dataset-import UI tests.
- Real-archive dry run (throwaway store): every sampled original row in all 15
  datasets was recognised as DUPLICATE on re-upload; 0 ambiguous identities.

## Limitations

These guarantees cover storage integrity, independent decisions and traceable
display. They do not establish source truth, independent custody, the lawful
authority of a reported action, or that a reviewer's judgement was correct.
Ledger verification shows that retained bytes match their commitments, not
that the facts are true. IGP row review is an accountable human decision,
recorded and anchored, but it is not automated proof of authority.
