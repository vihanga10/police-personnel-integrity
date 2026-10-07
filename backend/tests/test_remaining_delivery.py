"""Failure injection tests for recovery; these do not simulate real DB permissions."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

import pytest
from pymongo.errors import AutoReconnect, DuplicateKeyError

from app.identity.remaining_delivery import deliver, make_delivery, reconcile, collection_for
from app.identity.remaining_delivery import ROUTES, identity_fields
from app.identity.remaining_plan import plan_remaining
from app.identity.remaining_plan_crypto import open_remaining_plan, seal_remaining_plan
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


@pytest.fixture(params=list(ROUTES))
def evidence(tmp_path,request):
    encoded=base64.b64encode(b'k'*32).decode()
    paths=[]
    for name in ('primary','backup'):
        path=tmp_path/(name+'.json')
        path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':encoded},lookup_keys={'TEST':encoded})))
        path.chmod(0o600);paths.append(path)
    crypto,backup=(IdentityCrypto(p) for p in paths)
    filename=request.param;row=dict.fromkeys(ROUTES[filename],'');raw='a'*64
    keys={'officer_education.csv':'ol_index','operations.csv':'operation_no','court_details.csv':'court_no','public_complaints.csv':'complaint_id','_demotions_enacted.csv':'punishment_id'}
    row[keys[filename]]='00012'
    subject=uuid4() if 'officer_nic_no' in row else None
    if subject: row['officer_nic_no']='SYNTHETIC-NIC'
    if filename=='public_complaints.csv': row['officer_nic_as_recorded']='UNKNOWN-NIC'
    refs={}
    for name in identity_fields(filename):
        state='EXACT_EVIDENCE_CANDIDATE' if name=='officer_nic_no' else 'NO_CANDIDATE_FOUND' if row[name] else 'UNUSABLE_NIC'
        refs[name]=dict(candidate_state=state,officer_uid=str(subject) if name=='officer_nic_no' else None)
    evidence=dict(fixture=True,identity_candidates=refs)
    plan=plan_remaining(filename,row,officer_uid=subject,identity_candidates={name:subject if name=='officer_nic_no' else None for name in refs})
    cipher,version=seal_remaining_plan(crypto,plan,raw_record_id=raw,reference_evidence=evidence)
    payload=open_remaining_plan(crypto,cipher,key_version=version,filename=filename,raw_record_id=raw)
    def candidate(value=payload):
        return make_delivery(crypto,backup,value,event_id=uuid4(),assertion_id=uuid4(),recorded_at=datetime.now(timezone.utc))
    return crypto,backup,payload,candidate


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
    with pytest.raises(ValueError, match="Wrong remaining HR/PF Mongo destination"):
        deliver(ledger, mongo, candidate(), crypto=crypto, backup=backup, expected_payload=payload)
    assert ledger.prepared is None and not mongo.documents


def test_source_claims_are_not_promoted_to_current_state(evidence):
    crypto, backup, payload, candidate = evidence
    ledger, mongo = MemoryLedger(), MemoryCollection()
    dispatch(ledger, mongo, evidence)
    assert payload["authority_result"] is None and payload["reconstructed_state"] is None
    assert payload["valid_from"] is payload["valid_to"] is None
    fields = {f["source_column"]: f for f in payload["fields"]}
    assert payload['effects_applied'] is False
    if payload['filename']=='public_complaints.csv':
        assert payload['needs_review'] is True
        assert fields['officer_nic_as_recorded']['source_value']=='UNKNOWN-NIC'
        assert fields['officer_nic_as_recorded']['status']=='REVIEW_REQUIRED'
    if payload['filename'] in {'operations.csv','court_details.csv'}:
        assert payload['officer_uid'] is None
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
    from app.identity.remaining_sql_ledger import RemainingSourceBinding, SqlRemainingLedger
    crypto, backup, payload, _ = evidence
    def forbidden_connection():
        raise AssertionError("Unit guard must reject the account before connecting.")
    # A real Engine with an inert dialect isolates the account guard from DB drivers.
    engine = Engine(NullPool(forbidden_connection), DefaultDialect(), URL.create(
        "postgresql+psycopg", username=username, password="TEST_ONLY",
        host="127.0.0.1", port=5432, database="police_identity"))
    try:
        with pytest.raises(ValueError, match="Unexpected SQL application target"):
            SqlRemainingLedger(engine, crypto=crypto, backup=backup,
                binding=RemainingSourceBinding("a"*64, uuid4(), "b"*64, "c"*40), expected_payload=payload)
    finally:
        engine.dispose()


@pytest.mark.parametrize('change', ['source_cell', 'parsed_value', 'issues', 'uncertainties', 'actor'])
def test_modified_plan_or_actor_support_is_rejected(evidence, change):
    """Claims and unresolved warnings cannot be rewritten before a delivery retry."""
    _, _, payload, candidate = evidence
    changed = deepcopy(payload)
    if change == 'source_cell':
        next(f for f in changed['fields'] if f['source_value'] == '00012')['source_value'] += '-changed'
    elif change == 'parsed_value':
        changed['fields'][0]['value'] = 'different'
    elif change == 'issues':
        changed['fields'][0]['issues'] = ['AUTHORITY_VALID']
    elif change == 'uncertainties':
        changed['uncertainties'] = []
    else:
        changed['reference_evidence']['identity_candidates']['not_a_source_actor'] = {
            'candidate_state': 'EXACT_EVIDENCE_CANDIDATE', 'officer_uid': str(uuid4())}
    with pytest.raises(ValueError):
        candidate(changed)


def test_real_driver_fixture_preflight_and_independent_source_recovery(tmp_path, monkeypatch):
    """Exercise all checker fixtures and real source verification using an inert SQL sink.

    Driver permissions and transactions are verified by the Mac checker, not here.
    """
    import importlib.util
    from pathlib import Path
    from sqlalchemy.sql.dml import Insert
    from sqlalchemy.sql.selectable import Select
    from app.identity import remaining_sql_ledger as sql
    from app.identity.inspect_service_plans import CONFIRMATION
    path = Path(__file__).resolve().parents[1] / 'scripts/check_remaining_delivery.py'
    spec = importlib.util.spec_from_file_location('remaining_driver_fixture_test', path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    key = base64.b64encode(b'x' * 32).decode()
    copies = []
    for filename in ('primary.json', 'backup.json'):
        key_path = tmp_path / filename
        key_path.write_text(json.dumps(dict(active_encryption_key_version='TEST', active_lookup_key_version='TEST',
            encryption_keys={'TEST': key}, lookup_keys={'TEST': key})))
        key_path.chmod(0o600)
        copies.append(IdentityCrypto(key_path))

    class Result:
        def __init__(self, value):
            self.value = value
        def scalar_one(self):
            return self.value
        def scalar_one_or_none(self):
            return self.value
        def mappings(self):
            return self
        def one(self):
            return deepcopy(self.value)

    class Sink:
        def __init__(self):
            self.rows = {}
            self.source_id = uuid4()
        def execute(self, statement):
            if isinstance(statement, Insert):
                row = dict(statement.compile().params)
                self.rows.setdefault(statement.table.fullname, []).append(row)
                return Result(None)
            assert isinstance(statement, Select)
            table = statement.get_final_froms()[0].fullname
            if table == 'identity.source_system':
                return Result(self.source_id)
            params = statement.compile().params
            if table == 'identity.officer' and len(list(statement.selected_columns)) == 1:
                return Result('REGISTERED')
            rows = self.rows[table]
            # The statements in source verification each select one row by its key.
            selected = [r for r in rows if all(r.get(k.rsplit('_', 1)[0]) == v for k, v in params.items())]
            assert len(selected) == 1, (table, tuple(params))
            row = dict(selected[0])
            row.setdefault('transaction_end', None)
            return Result(row)

    for filename in checker.ROUTES:
        sink = Sink()
        binding, payload, candidate = checker.fixture(sink, *copies, filename)
        assert binding.confirmation_sha256 == CONFIRMATION
        prepared = candidate()
        assert payload['needs_review'] is (filename in {'court_details.csv','public_complaints.csv'})
        # Actor discovery is modeled; NIC/source/backup recovery use the real verifier.
        def discovered_candidate(*args):
            # Match synthetic source observations without accepting unresolved actors.
            value = args[3].strip()
            if not value:
                return 'UNUSABLE_NIC', None
            if value.startswith('UNKNOWN-'):
                return 'NO_CANDIDATE_FOUND', None
            return 'EXACT_EVIDENCE_CANDIDATE', UUID(payload['officer_uid'])
        monkeypatch.setattr(sql, 'inspected_link', discovered_candidate)
        sql.check_source(sink, *copies, binding, prepared.document(), payload)
        # A payload cannot silently change the staged original while staying well-formed.
        altered = deepcopy(payload)
        source_key = {'officer_education.csv': 'ol_index', 'operations.csv': 'operation_no',
            'court_details.csv': 'court_no', 'public_complaints.csv': 'complaint_id', '_demotions_enacted.csv': 'punishment_id'}[filename]
        target = next(f for f in altered['fields'] if f['source_column'] == source_key)
        target['source_value'] = target['value'] = 'changed-source-key'
        with pytest.raises(ValueError, match='differ from staging'):
            sql.check_source(sink, *copies, binding, prepared.document(), altered)
