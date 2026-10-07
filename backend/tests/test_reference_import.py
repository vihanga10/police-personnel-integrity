"""Test read-only progress gates and CLI mode guards without real database access."""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID
from bson import BSON
import hashlib
import pytest
from app.identity import import_references
from app.identity.service_delivery import PreparedDelivery
from app.storage.check_reference_mongo import fixture as reference_fixture


def fixture():
    document, key, _ = reference_fixture("station_reference_records")
    return document, key


class Response:
    def __init__(self, value):
        self.value = value
    def mappings(self):
        return self
    def one_or_none(self):
        return self.value
    def scalar_one_or_none(self):
        return self.value


class ReadConnection:
    def __init__(self, saved, receipt):
        self.values = iter((saved, receipt))
        self.reads = 0
    def execute(self, statement):
        # Accidental persistence in state inspection is a test failure.
        assert statement.is_select
        self.reads += 1
        return Response(next(self.values))


class ReadCollection:
    def __init__(self, document):
        self.document = document
        self.name = "station_reference_records"
    def find_one(self, query):
        if self.document is None:
            return None
        assert self.document["raw_record_id"] == query["raw_record_id"]
        return self.document


@pytest.mark.parametrize("present,receipt,state", [
    (False, False, "PENDING_MONGO"), (True, False, "PENDING_RECEIPT"),
    (True, True, "VERIFIED_EXISTING"),
])
def test_saved_progress_inspection_has_no_write_path(present, receipt, state):
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    connection = ReadConnection({"delivery_id": UUID(document["_id"])}, prepared.document_sha256 if receipt else None)
    collection = ReadCollection(prepared.document() if present else None)
    binding = SimpleNamespace(raw_record_id=document["raw_record_id"])
    with patch.object(import_references, "assert_saved", return_value=prepared):
        actual, recovered = import_references.saved_state(connection, collection, crypto=None, backup=None, binding=binding, payload={"plan":{"filename": "station_master.csv"}})
    assert actual == state and recovered == prepared and connection.reads == 2


def test_unprepared_row_is_planned_without_creating_a_record():
    connection, collection = ReadConnection(None, None), ReadCollection(None)
    state, prepared = import_references.saved_state(connection, collection, crypto=None, backup=None,
        binding=SimpleNamespace(raw_record_id="a" * 64), payload={"plan":{"filename": "station_master.csv"}})
    assert (state, prepared, connection.reads) == ("PLANNED", None, 1)


def test_orphan_mongo_evidence_cannot_be_adopted_without_sql_preparation():
    document, _ = fixture()
    with pytest.raises(ValueError, match="no SQL preparation"):
        import_references.saved_state(ReadConnection(None, None), ReadCollection(document), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"plan":{"filename": "station_master.csv"}})


def test_missing_completed_mongo_evidence_requires_integrity_review():
    document, _ = fixture()
    encoded = bytes(BSON.encode(document))
    prepared = PreparedDelivery(encoded, hashlib.sha256(encoded).hexdigest())
    with patch.object(import_references, "assert_saved", return_value=prepared), pytest.raises(ValueError, match="integrity review"):
        import_references.saved_state(ReadConnection({}, prepared.document_sha256), ReadCollection(None), crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id=document["raw_record_id"]), payload={"plan":{"filename": "station_master.csv"}})


def cli_arguments():
    values = ["program", "--batch-id", import_references.BATCH, "--expected-archive-sha256", import_references.ARCHIVE,
              "--expected-confirmation-sha256", import_references.CONFIRMATION, "--expected-master-rows", "607", "--expected-sinhala-rows", "607"]
    for name in ("confirmation", "key-file", "backup-key-file", "reference-credential-directory", "attempt-root"):
        values += ["--" + name, "/test/" + name]
    return values


def test_default_mode_cannot_write_or_repair():
    with patch("sys.argv", cli_arguments()):
        args = import_references.arguments()
    assert args.write is False and args.reconcile is False


def test_write_and_reconciliation_cannot_be_combined():
    with patch("sys.argv", cli_arguments() + ["--write", "--reconcile"]), pytest.raises(SystemExit):
        import_references.arguments()


def test_unreviewed_batch_fingerprint_is_refused_before_connections():
    values = cli_arguments()
    values[values.index(import_references.ARCHIVE)] = "0" * 64
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_references.arguments()


def checkpoint_totals():
    observations={'MASTER:REPEATED_SINHALA_LABEL':2}
    for mode in import_references.MODES:
        observations[mode+':SINGLE_JOINT_CANDIDATE']=605
        observations[mode+':STRUCTURE_REVIEW_REQUIRED']=2
    return dict(import_references.EXPECTED_ROWS),{name:2 for name in import_references.ROUTES},observations


def test_verified_batch_counts_do_not_promote_truth():
    import_references.validate_batch_totals(*checkpoint_totals())


@pytest.mark.parametrize("index", [0, 1, 2])
def test_changed_counts_stop_preflight(index):
    values = list(checkpoint_totals())
    key = next(iter(values[index]))
    values[index][key] += 1
    with pytest.raises(ValueError):
        import_references.validate_batch_totals(*values)


def test_wrong_collection_is_rejected_without_a_database_read():
    connection = ReadConnection(None, None)
    collection = ReadCollection(None)
    collection.name = "service_status_events"
    with pytest.raises(ValueError, match="Wrong reference Mongo destination"):
        import_references.saved_state(connection, collection, crypto=None, backup=None,
            binding=SimpleNamespace(raw_record_id="a"*64), payload={"plan":{"filename": "station_master.csv"}})
    assert connection.reads == 0


@pytest.mark.parametrize("flag", ["--expected-master-rows", "--expected-sinhala-rows"])
def test_wrong_source_row_count_is_refused_before_connections(flag):
    values = cli_arguments()
    values[values.index(flag)+1] = "0"
    with patch("sys.argv", values), pytest.raises(SystemExit):
        import_references.arguments()


@pytest.mark.parametrize('filename',list(import_references.HEADERS))
def test_payload_dual_key_recovery_and_source_fingerprint(tmp_path,filename):
    import base64,json
    from dataclasses import asdict
    from uuid import uuid4
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    from app.identity.reference_plan import ReferenceCandidates
    from app.identity.station_vocabulary import HEADERS,MASTER,SINHALA,LABEL
    mod=import_references
    key=base64.b64encode(b'k'*32).decode();copies=[]
    for name in ('primary.json','backup.json'):
        path=tmp_path/name;path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':key},lookup_keys={'TEST':key})));copies.append(IdentityCrypto(path))
    master=dict.fromkeys(HEADERS[MASTER],'');master.update(station_code='00012',station_name='Example',station_name_si='උදාහරණ',division='Division',province='Province')
    sinhala=dict.fromkeys(HEADERS[SINHALA],'');sinhala.update({LABEL:'Example (උදාහරණ)','Division':'Division (අංශය)','Province ':'Province (පළාත)'})
    master_file,source_file=uuid4(),uuid4()
    master_sealed=seal_row(copies[0],batch_id=mod.BATCH,archive_path=MASTER,source_file_sha256='b'*64,source_row_number=1,columns=list(master),values=list(master.values()))
    row=master if filename==MASTER else sinhala
    file_id=master_file if filename==MASTER else source_file
    sealed=master_sealed if filename==MASTER else seal_row(copies[0],batch_id=mod.BATCH,archive_path=filename,source_file_sha256='b'*64,source_row_number=1,columns=list(row),values=list(row.values()))
    raw=dict(asdict(sealed),import_file_id=file_id)
    def metadata(name,fid,r):return dict(batch_id=mod.BATCH,archive_path=name,source_file_sha256='b'*64,import_file_id=fid,columns=list(r),column_count=len(r),expected_row_count=1)
    file=metadata(filename,file_id,row);master_metadata=metadata(MASTER,master_file,master)
    candidates=ReferenceCandidates([(master_sealed.raw_record_id,master)])
    args=SimpleNamespace(batch_id=mod.BATCH,expected_archive_sha256=mod.ARCHIVE,expected_confirmation_sha256=mod.CONFIRMATION)
    payload,binding,digest=mod.reference_payload(*copies,raw,file,args,'d'*40,master_metadata,candidates)
    assert {f['source_column']:f['source_value'] for f in payload['plan']['fields']}==row
    assert payload['plan']['accepted_station_uid'] is None and payload['plan']['linkage_accepted'] is False
    assert binding.master_import_file_id==master_file and payload['evidence']['source_system_code']=='POLICE_HR_IS'
    assert digest==mod.reference_payload(*copies,raw,file,args,'d'*40,master_metadata,candidates)[2]
    altered=dict(file,source_file_sha256='0'*64)
    with pytest.raises(ValueError):mod.reference_payload(*copies,raw,altered,args,'d'*40,master_metadata,candidates)


@pytest.mark.parametrize('mode,invalid,expected_result',[
    ('validation',False,0),('write',False,0),('write',True,1),('reconcile',False,1)])
def test_complete_importer_flow_preflights_all_sources_before_write(tmp_path,monkeypatch,mode,invalid,expected_result):
    """Actual crypto/protocol with inert SQL/Mongo boundaries and a small source set."""
    import base64,json
    from contextlib import nullcontext
    from dataclasses import asdict
    from uuid import uuid4
    from sqlalchemy.sql.selectable import Select
    from app.intake.staging_rows import seal_row
    from app.security.identity_crypto import IdentityCrypto
    from app.identity.station_vocabulary import MASTER,SINHALA,LABEL,HEADERS
    from app.staging.models import IntakeBatch,IntakeFile,RawRecord
    from app.identity.reference_sql_ledger import PREP
    mod=import_references;key=base64.b64encode(b'z'*32).decode();keys=[]
    for name in ('primary.json','backup.json'):
        path=tmp_path/name;path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',encryption_keys={'TEST':key},lookup_keys={'TEST':key})));path.chmod(0o600);keys.append(path)
    crypto=IdentityCrypto(keys[0]);files=[];raw_rows={}
    for filename in HEADERS:
        row=dict.fromkeys(HEADERS[filename],'')
        if filename==MASTER:row.update(station_code='00012',station_name='Example',station_name_si='උදාහරණ',division='Division',province='Province')
        else:row.update({LABEL:'Example (උදාහරණ)','Division':'Division (අංශය)','Province ':'Province (පළාත)'})
        file_id=uuid4();files.append(dict(batch_id=mod.BATCH,archive_path=filename,source_file_sha256='b'*64,import_file_id=file_id,columns=list(row),column_count=len(row),expected_row_count=1))
        raw=dict(asdict(seal_row(crypto,batch_id=mod.BATCH,archive_path=filename,source_file_sha256='b'*64,source_row_number=1,columns=list(row),values=list(row.values()))),import_file_id=file_id)
        if invalid and filename==SINHALA:raw['source_row_number']=2
        raw_rows[raw['raw_record_id']]=raw
    batch=dict(archive_sha256=mod.ARCHIVE,expected_file_count=2)
    class Result:
        def __init__(self,value):self.value=value
        def mappings(self):return self
        def scalars(self):return self
        def one(self):return self.value
        def all(self):return self.value
        def one_or_none(self):return self.value
        def __iter__(self):return iter(self.value)
    class Connection:
        def begin(self):return nullcontext()
        def execute(self,statement):
            if not isinstance(statement,Select):
                assert str(statement) in {'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY','SELECT current_user, current_database()'}
                return Result(('police_identity_app','police_identity'))
            table=statement.get_final_froms()[0].fullname
            if table==IntakeBatch.__table__.fullname:return Result(batch)
            if table==IntakeFile.__table__.fullname:return Result(files)
            if table==mod.ReferenceSourceAssertion.__table__.fullname:return Result([])
            if table==PREP.fullname:return Result(None if len(list(statement.selected_columns))==len(PREP.c) else [])
            assert table==RawRecord.__table__.fullname
            params=statement.compile().params
            if 'raw_record_id_1' in params:return Result(raw_rows[params['raw_record_id_1']])
            return Result([r for r in raw_rows.values() if r['import_file_id']==params['import_file_id_1']])
    class Engine:
        disposed=False
        def connect(self):return nullcontext(Connection())
        def dispose(self):self.disposed=True
    class Collection:
        def __init__(self,name):self.name=name;self.documents=[];self.inserts=0
        def find_one(self,query):return next((d for d in self.documents if all(d.get(k)==v for k,v in query.items())),None)
        def find(self,query,projection):return iter(self.documents)
        def insert_one(self,document):self.inserts+=1;self.documents.append(document);return SimpleNamespace(acknowledged=True)
    class Mongo:
        closed=False
        def __init__(self):self.collections={name:Collection(name) for name in mod.COLLECTION_POLICIES}
        def __getitem__(self,name):return self if name==mod.DATABASE else self.collections[name]
        def close(self):self.closed=True
    class Ledger:
        instances=[]
        def __init__(self,engine,**kwargs):self.prepared=None;self.receipt=None;self.instances.append(self)
        def prepare_once(self,proposed):self.prepared=proposed;return proposed
        def completion_digest(self,event):return self.receipt
        def complete_once(self,prepared):self.receipt=prepared.document_sha256;return self.receipt
    engine,mongo=Engine(),Mongo()
    args=SimpleNamespace(batch_id=mod.BATCH,expected_archive_sha256=mod.ARCHIVE,expected_confirmation_sha256=mod.CONFIRMATION,confirmation=tmp_path/'confirmation.json',
        key_file=keys[0],backup_key_file=keys[1],reference_credential_directory=tmp_path/'creds',attempt_root=tmp_path/'attempts',write=mode=='write',reconcile=mode=='reconcile')
    monkeypatch.setattr(mod,'arguments',lambda:args)
    monkeypatch.setattr(mod.subprocess,'check_output',lambda command,**kw:'' if command[-1]=='--porcelain' else 'd'*40)
    monkeypatch.setattr(mod,'Settings',lambda:SimpleNamespace(host='127.0.0.1',port=5432,name='police_identity',user='police_identity_app'))
    monkeypatch.setattr(mod,'create_identity_engine',lambda settings:engine)
    monkeypatch.setattr(mod,'private_key_file',IdentityCrypto)
    monkeypatch.setattr(mod,'verify_recovery',lambda *args:None)
    monkeypatch.setattr(mod,'reference_password',lambda directory:'TEST-ONLY')
    monkeypatch.setattr(mod,'reference_client',lambda password:mongo)
    monkeypatch.setattr(mod,'load_source_confirmation',lambda *args,**kw:SimpleNamespace(confirmation_sha256=mod.CONFIRMATION,source_for=lambda name:'POLICE_HR_IS'))
    monkeypatch.setattr(mod,'EXPECTED_ROWS',{name:1 for name in HEADERS})
    def small_totals(counts,reviews,observations):
        assert dict(counts)=={name:1 for name in HEADERS}
        assert dict(reviews)=={name:0 for name in HEADERS}
    monkeypatch.setattr(mod,'validate_batch_totals',small_totals)
    monkeypatch.setattr(mod,'SqlReferenceLedger',Ledger)
    assert mod.main()==expected_result
    assert engine.disposed and mongo.closed
    writes=2 if mode=='write' and not invalid else 0
    assert len(Ledger.instances)==sum(c.inserts for c in mongo.collections.values())==writes
    for ledger in Ledger.instances:assert ledger.receipt==ledger.prepared.document_sha256
    for path in args.attempt_root.glob('*/*.json'):
        content=path.read_text();assert 'Example' not in content and 'උදාහරණ' not in content and '00012' not in content
