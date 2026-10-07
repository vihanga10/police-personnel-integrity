# SRB activity evidence delivery v1

## Scope

Built on committed checkpoint `b977fc1` and applied revision `d06f4b28ce51`.
This step adds the coordinated activity delivery protocol, PostgreSQL adapter,
focused tests and an isolated real-driver checker. It adds no migration, CSV
import command, human authorization or actual research activity records.

Routes: officer_duty_periods.csv -> duty_periods;
officer_firearms_expertise.csv -> firearms_assessments;
good_conduct_register.csv -> good_conduct_records;
bad_conduct_register.csv -> bad_conduct_records.

## Source verification

The adapter rebuilds the planner from preserved source cells and verifies exact
coverage, parsed values, warning lists and candidate references. It independently
recovers the staged row using primary and backup keys; matches file headers,
source file hash, row/batch provenance and the source confirmation; validates
subject NIC ciphertext, its HMAC lookup and supporting assertion; re-discovers
nonempty actor NIC candidates; and recovers the referenced station source rows.
Station references remain source-scoped with UNKNOWN historical applicability.
Future importer preflight must validate the complete source/station snapshot and
all batch-level intake gates. This adapter is not an intake API.

Reported dates, scores, signatures, statuses and conduct descriptions remain
claims. Missing H2 values stay missing, original status text is preserved, and
TRUE/FALSE values remain boolean claims. No operational/court/complaint links
are accepted merely because a source cell mentions them. No authority finding,
accepted valid period, legal effect, competency or current state is reconstructed.
Structural errors stop delivery; unresolved semantics remain explicit warnings.
Classification remains UNASSESSED and human disclosure remains disabled.

## Delivery and recovery

1. Commit source assertion and exact sealed BSON preparation in one SQL
   transaction, using a source/policy advisory lock plus unique constraints.
2. Read the committed preparation from a fresh SQL connection before any Mongo
   insertion. Both key copies must recover the exact expected plan.
3. Insert the prepared document into its dedicated activity collection and
   verify full readback, including ciphertext and all opaque provenance headers.
4. Append the SQL completion receipt and verify its committed digest from a
   fresh connection.

Retry uses the existing SQL preparation, including its original IDs, timestamp,
nonce and ciphertext. Concurrent identical Mongo inserts require identical
readback; a duplicate-key exception alone is never success. Conflicting evidence
or receipts stop the workflow. A completed receipt with a missing Mongo document
is an integrity incident; it is not silently repaired. Read-only reconciliation
never inserts missing documents or receipts. No research update/delete is used.
The production SQL adapter accepts only police_identity_app on the pinned local
police_identity database, never migrator/postgres credentials.

## Verification

Focused tests cover four source routes, five uncertain-outcome boundaries,
idempotent retries, read-only reconciliation, missing/tampered evidence, rejected
state promotions, malformed candidate support, privileged account guards and
independent source/backup recovery. Inert unit sinks do not prove driver ACLs.

Run `scripts/check_activity_delivery.py` with separate bootstrap/service, history,
SRB and activity credential directories. It pins revision and reconciled counts;
requires empty research activity collections and delivery tables; verifies Mongo
contracts/technical roles; creates a freshly named isolated synthetic Mongo
namespace and restricted test account; and uses ephemeral keys and rollback-only
SQL fixtures. Twenty interruption cases cover four routes times five boundaries:
after SQL preparation, before/after Mongo insertion, and before/after SQL receipt.

The checker verifies exact replay, one Mongo document per source, completion and
reconciliation; rolls back SQL test transactions; removes only its isolated
synthetic Mongo namespace; and rechecks research counts and applied revision.
It never decrypts research personnel or uses production encryption keys.
Its SQL savepoints exercise transaction bodies, not independent durable commits.
The production adapter's fresh-connection commit paths must also be verified
through the forthcoming guarded importer and post-import reconciliation.

After successful unit and Mac driver checks, commit these sources. The guarded
activity importer follows as a separate step. Stage 2 remains in progress.
