"""Failure injection tests for recovery; these do not simulate real DB permissions."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

import pytest
from pymongo.errors import AutoReconnect, DuplicateKeyError

from app.identity.srb_delivery import deliver, make_delivery, reconcile, collection_for
from app.identity.srb_plan import ROUTES, plan_srb, SourceReference
from app.identity.srb_plan_crypto import open_srb_plan, seal_srb_plan
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


@pytest.fixture(params=["officer_police_numbers.csv", "officer_restrictions.csv", "restriction_overrides.csv"])
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
    row.update(officer_nic_no="SYNTHETIC-TEST-NIC")
    actors, source_refs = {}, {}
    if filename == "officer_police_numbers.csv":
        row.update(police_no="00012", number_type="reported type", valid_from="2020-01-01")
    elif filename == "officer_restrictions.csv":
        row.update(restriction_id="TEST-R1", restriction_start_date="2020-01-01", restriction_record_date="2020-01-02", restriction_verifiable="TRUE")
    else:
        actor = uuid4()
        row.update(override_id="TEST-O1", restriction_id="TEST-R1", transfer_id="TEST-T1", override_reference="TEST-P1",
            override_ground="Source claim", override_reason="Original reason", override_authority_nic="ACTOR-NIC",
            override_authority_rank="Assistant Superintendent of Police", override_date="2020-02-01")
        actors = {"override_authority_nic": dict(candidate_state="EXACT_EVIDENCE_CANDIDATE", officer_uid=str(actor))}
        source_refs = {
            "restriction_id": [dict(filename="officer_restrictions.csv", raw_record_id="b" * 64, officer_uid=str(officer))],
            "transfer_id": [dict(filename="transfer_history.csv", raw_record_id="c" * 64, officer_uid=str(officer))],
        }
    refs = dict(fixture=True, actor_candidates=actors, source_reference_candidates=source_refs, station_matches={})
    plan = plan_srb(filename, row, officer_uid=officer, station_candidates={},
        actor_candidates={name: UUID(ref["officer_uid"]) for name, ref in actors.items()},
        reference_candidates={name: tuple(SourceReference(ref["filename"], ref["raw_record_id"], UUID(ref["officer_uid"])) for ref in candidates) for name, candidates in source_refs.items()})
    cipher, version = seal_srb_plan(crypto, plan, raw_record_id=raw, reference_evidence=refs)
    payload = open_srb_plan(crypto, cipher, key_version=version, filename=filename, officer_uid=officer, raw_record_id=raw)

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
    changed["reference_evidence"]["fixture"] = "different source evidence"
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
    with pytest.raises(ValueError, match="Wrong SRB Mongo destination"):
        deliver(ledger, mongo, candidate(), crypto=crypto, backup=backup, expected_payload=payload)
    assert ledger.prepared is None and not mongo.documents


def test_source_claims_are_not_promoted_to_current_state(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    assert payload["authority_result"] is None and payload["reconstructed_state"] is None
    assert payload["valid_from"] is payload["valid_to"] is None
    fields = {f["source_column"]: f for f in payload["fields"]}
    if payload["filename"] == "officer_police_numbers.csv":
        assert fields["police_no"]["value"] == "00012" and fields["valid_to"]["value"] is None
    elif payload["filename"] == "officer_restrictions.csv":
        assert fields["restriction_verifiable"]["value"] is True
        assert fields["restriction_removal_date"]["value"] is None
    else:
        assert "OVERRIDE_CLAIM_PRESERVED_NOT_APPLIED" in payload["observations"]
    changed = deepcopy(payload)
    changed["reconstructed_state"] = {"accepted": True}
    with pytest.raises(ValueError):
        candidate(changed)


@pytest.mark.parametrize("username", ["police_identity_migrator", "postgres"])
def test_production_ledger_rejects_privileged_sql_accounts(evidence, username):
    from sqlalchemy import URL
    from sqlalchemy.engine import Engine
    from sqlalchemy.engine.default import DefaultDialect
    from sqlalchemy.pool import NullPool
    from app.identity.srb_sql_ledger import SrbSourceBinding, SqlSrbLedger
    crypto, backup, payload, _ = evidence
    def forbidden_connection():
        raise AssertionError("Unit guard must reject the account before connecting.")
    # A real Engine with an inert dialect isolates the account guard from DB drivers.
    engine = Engine(NullPool(forbidden_connection), DefaultDialect(), URL.create(
        "postgresql+psycopg", username=username, password="TEST_ONLY",
        host="127.0.0.1", port=5432, database="police_identity"))
    try:
        with pytest.raises(ValueError, match="Unexpected SQL application target"):
            SqlSrbLedger(engine, crypto=crypto, backup=backup,
                binding=SrbSourceBinding("a"*64, uuid4(), "b"*64, "c"*40), expected_payload=payload)
    finally:
        engine.dispose()
