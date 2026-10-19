"""Failure injection tests for recovery; these do not simulate real DB permissions."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest
from pymongo.errors import AutoReconnect, DuplicateKeyError

from app.identity.history_delivery import deliver, make_delivery, reconcile, collection_for
from app.identity.history_plan import ROUTES, plan_history
from app.identity.history_plan_crypto import open_history_plan, seal_history_plan
from app.security.identity_crypto import IdentityCrypto


class MemoryLedger:
    """Test-only durable boundary model; production requires real SQL constraints."""

    def __init__(self, fail=None):
        self.prepared = None
        self.receipts = {}
        self.fail = fail

    def interrupt(self, location):
        if self.fail == location:
            self.fail = None
            raise AutoReconnect("Injected uncertain acknowledgment")

    def prepare_once(self, proposed):
        if self.prepared is None:
            self.prepared = proposed
        self.interrupt("after_prepare_commit")
        return self.prepared

    def completion_digest(self, event_id):
        return self.receipts.get(event_id)

    def complete_once(self, prepared):
        self.interrupt("before_receipt_commit")
        event = prepared.document()["_id"]
        self.receipts.setdefault(event, prepared.document_sha256)
        self.interrupt("after_receipt_commit")
        return self.receipts[event]


class MemoryCollection:
    """Test insert/find surface only; there is deliberately no mutation API."""

    def __init__(self, fail=None):
        self.documents = []
        self.name = None
        self.fail = fail
        self.insert_calls = 0

    def find_one(self, query):
        return next((deepcopy(d) for d in self.documents if all(d.get(k) == v for k, v in query.items())), None)

    def insert_one(self, document):
        self.insert_calls += 1
        if self.fail == "before_mongo_insert":
            self.fail = None
            raise AutoReconnect("Injected connection loss")
        if self.documents:
            raise DuplicateKeyError("Injected unique-source conflict")
        self.documents.append(deepcopy(document))
        if self.fail == "after_mongo_insert":
            self.fail = None
            raise AutoReconnect("Injected uncertain acknowledgment")
        return type("Acknowledged", (), {"acknowledged": True})()


@pytest.fixture(params=["transfer_history.csv", "promotion_history.csv"])
def evidence(tmp_path, request):
    # Ephemeral keys and a small fixture; never load real identity credentials.
    encoded = base64.b64encode(b"k" * 32).decode()
    path = tmp_path / "test-keys.json"
    path.write_text(json.dumps({"active_encryption_key_version": "TEST",
                              "active_lookup_key_version": "TEST",
                              "encryption_keys": {"TEST": encoded}, "lookup_keys": {"TEST": encoded}}))
    crypto, backup = IdentityCrypto(path), IdentityCrypto(path)
    officer, raw = uuid4(), "a" * 64
    filename = request.param
    row = {name: "" for name in ROUTES[filename]}
    row.update(officer_nic_no="SYNTHETIC-TEST-NIC", to_rank="Inspector of Police",
               effective_date="2020-01-01", is_same_unit="FALSE")
    if filename == "transfer_history.csv":
        row.update(transfer_id="TEST-001", is_cancelled="TRUE", cancellation_ref="TEST-CANCEL",
                   cancellation_date="2020-02-01", days_in_previous_posting="-12")
    else:
        row.update(promotion_id="TEST-002", from_rank="Sub Inspector of Police")
    plan = plan_history(filename, row, officer_uid=officer, station_candidates={})
    cipher, version = seal_history_plan(crypto, plan, raw_record_id=raw, reference_evidence={"fixture": True})
    payload = open_history_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw)

    def candidate(value=payload):
        return make_delivery(crypto, backup, value, event_id=uuid4(), assertion_id=uuid4(),
                             recorded_at=datetime.now(timezone.utc))
    return crypto, backup, payload, candidate


def dispatch(ledger, mongo, evidence, proposed=None):
    crypto, backup, payload, candidate = evidence
    if mongo.name is None:
        mongo.name = collection_for(payload)
    return deliver(ledger, mongo, proposed or candidate(), crypto=crypto, backup=backup, expected_payload=payload)


@pytest.mark.parametrize("failure", ["after_prepare_commit", "before_mongo_insert", "after_mongo_insert",
                                     "before_receipt_commit", "after_receipt_commit"])
def test_retry_after_uncertain_outcomes_reuses_exact_ciphertext(evidence, failure):
    ledger = MemoryLedger(failure)
    mongo = MemoryCollection(failure)
    with pytest.raises(AutoReconnect):
        dispatch(ledger, mongo, evidence)
    committed = ledger.prepared
    # Retry has fresh candidate IDs/nonces; the committed SQL winner must prevail.
    dispatch(ledger, mongo, evidence)
    assert ledger.prepared == committed
    assert mongo.documents == [committed.document()]
    assert ledger.receipts == {committed.document()["_id"]: committed.document_sha256}
    assert dispatch(ledger, mongo, evidence) == "VERIFIED_EXISTING"
    assert len(mongo.documents) == len(ledger.receipts) == 1


def test_read_only_reconciliation_never_finishes_pending_import(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    prepared = ledger.prepare_once(candidate())
    mongo.name = collection_for(payload)
    kwargs = dict(crypto=crypto, backup=backup, expected_payload=payload)
    with pytest.raises(ValueError, match="Mongo evidence is missing"):
        reconcile(ledger, mongo, prepared, **kwargs)
    assert not mongo.documents and not ledger.receipts
    mongo.insert_one(prepared.document())
    with pytest.raises(ValueError, match="receipt is missing"):
        reconcile(ledger, mongo, prepared, **kwargs)
    assert not ledger.receipts and mongo.insert_calls == 1
    dispatch(ledger, mongo, evidence, prepared)
    assert reconcile(ledger, mongo, prepared, **kwargs) == "VERIFIED_EXISTING"
    assert mongo.insert_calls == 1


def test_completed_but_missing_mongo_record_is_not_silently_repaired(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    mongo.documents.clear()  # Simulated external tampering, not a production operation.
    with pytest.raises(ValueError, match="integrity review"):
        dispatch(ledger, mongo, evidence)
    assert mongo.insert_calls == 1 and not mongo.documents


def test_conflicting_stored_mongo_evidence_is_never_overwritten(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    mongo.documents[0]["source_assertion_uid"] = str(uuid4())
    corrupted = deepcopy(mongo.documents)
    with pytest.raises(ValueError, match="stop for review"):
        dispatch(ledger, mongo, evidence)
    assert mongo.documents == corrupted and mongo.insert_calls == 1


def test_corrupted_receipt_blocks_retry(evidence):
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    ledger.receipts[ledger.prepared.document()["_id"]] = "0" * 64
    with pytest.raises(ValueError, match="receipt differs"):
        dispatch(ledger, mongo, evidence)
    assert mongo.insert_calls == 1


def test_source_plan_change_blocks_delivery_of_old_preparation(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    ledger.prepare_once(candidate())
    mongo.name = collection_for(payload)
    changed = deepcopy(payload)
    changed["reference_evidence"] = {"fixture": "different source evidence"}
    with pytest.raises(ValueError, match="differs from source plan"):
        deliver(ledger, mongo, candidate(changed), crypto=crypto, backup=backup, expected_payload=changed)
    assert not mongo.documents and not ledger.receipts


def test_concurrent_identical_insert_is_verified(evidence):
    class RacingCollection(MemoryCollection):
        def insert_one(self, document):
            super().insert_one(document)
            raise DuplicateKeyError("Another worker inserted the prepared winner")
    ledger, mongo = MemoryLedger(), RacingCollection()
    assert dispatch(ledger, mongo, evidence) == "COMPLETED"
    assert len(ledger.receipts) == len(mongo.documents) == 1


def test_duplicate_error_without_identical_readback_cannot_complete(evidence):
    class ConflictingCollection(MemoryCollection):
        def insert_one(self, document):
            raise DuplicateKeyError("Unrelated primary-key collision")
    ledger, mongo = MemoryLedger(), ConflictingCollection()
    with pytest.raises(RuntimeError, match="not recovered"):
        dispatch(ledger, mongo, evidence)
    assert not ledger.receipts


def test_receipt_acknowledgment_without_readback_is_not_success(evidence):
    class BrokenLedger(MemoryLedger):
        def complete_once(self, prepared):
            return prepared.document_sha256
    ledger, mongo = BrokenLedger(), MemoryCollection()
    with pytest.raises(ValueError, match="receipt was not recovered"):
        dispatch(ledger, mongo, evidence)
    assert len(mongo.documents) == 1 and not ledger.receipts


@pytest.mark.parametrize("change", [
    {"snapshot_date": "2026-10-07"}, {"valid_from": "2020-01-01"},
    {"record_classification": "ORDINARY"}, {"authority_result": "VALID"},
    {"review_issues": ["UNRESOLVED_CONFLICT"]},
])
def test_unsupported_promotions_are_rejected_before_preparation(evidence, change):
    crypto, backup, payload, candidate = evidence
    with pytest.raises(ValueError):
        candidate(dict(payload, **change))


def test_review_flag_cannot_be_erased(evidence):
    crypto, backup, payload, candidate = evidence
    with pytest.raises(ValueError):
        candidate(dict(payload, needs_review=not payload["needs_review"]))


def test_wrong_collection_is_rejected_before_preparation(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    mongo.name = "service_status_events"
    with pytest.raises(ValueError, match="Wrong historical Mongo destination"):
        deliver(ledger, mongo, candidate(), crypto=crypto, backup=backup, expected_payload=payload)
    assert ledger.prepared is None and not mongo.documents


def test_negative_duration_stays_unknown_and_cancelled_claim_preserved(evidence):
    crypto, backup, payload, candidate = evidence
    if payload["filename"] != "transfer_history.csv":
        return
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    fields = {f["source_column"]: f for f in payload["fields"]}
    assert fields["days_in_previous_posting"]["source_value"] == "-12"
    assert fields["days_in_previous_posting"]["value"] is None
    assert fields["days_in_previous_posting"]["status"] == "REVIEW_REQUIRED"
    assert fields["is_cancelled"]["value"] is True
    changed = deepcopy(payload)
    changed["fields"] = [dict(f, value=12) if f["source_column"] == "days_in_previous_posting" else f for f in changed["fields"]]
    with pytest.raises(ValueError):
        candidate(changed)


@pytest.mark.parametrize("username", ["police_identity_migrator", "postgres"])
def test_production_ledger_rejects_privileged_sql_accounts(evidence, username):
    from sqlalchemy import create_engine, URL
    from app.identity.history_sql_ledger import HistorySourceBinding, SqlHistoryLedger
    crypto, backup, payload, _ = evidence
    engine = create_engine(URL.create("postgresql+psycopg", username=username, password="TEST_ONLY",
                                     host="127.0.0.1", port=5432, database="police_identity"))
    try:
        with pytest.raises(ValueError, match="Unexpected SQL application target"):
            SqlHistoryLedger(engine, crypto=crypto, backup=backup,
                binding=HistorySourceBinding("a"*64, uuid4(), "b"*64, "c"*40), expected_payload=payload)
    finally:
        engine.dispose()
