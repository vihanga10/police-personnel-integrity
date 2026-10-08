"""Typed full-row bindings, exact BSON verification and missing-version guards."""
from datetime import date,datetime,timezone,timedelta
from decimal import Decimal
from uuid import uuid4
import hashlib
import pytest
from bson import BSON
from app.identity.destination_binding import typed,row_binding,verify_binding,DestinationInventory


@pytest.mark.parametrize('changed',[
    dict(cipher=b'changed'),dict(version_number=2),dict(source_assertion_id='different'),
    dict(record_state='SUPERSEDED'),dict(valid_to=date(2026,1,1)),dict(officer_uid=uuid4())])
def test_every_changed_content_and_metadata_field_changes_binding(changed):
    row=dict(id=uuid4(),cipher=b'protected',version_number=1,source_assertion_id='assertion',
        record_state='ASSERTED',valid_to=None,officer_uid=uuid4())
    original=row_binding('identity.fixture',['id'],row)
    altered=row_binding('identity.fixture',['id'],dict(row,**changed))
    assert original!=altered
    with pytest.raises(ValueError):verify_binding(original,altered)


def test_dictionary_order_and_utc_equivalence():
    a=dict(id=1,recorded_at=datetime(2026,1,1,tzinfo=timezone.utc),metadata={'b':2,'a':1})
    b=dict(metadata={'a':1,'b':2},recorded_at=a['recorded_at'].astimezone(timezone(timedelta(hours=5,minutes=30))),id=1)
    assert row_binding('fixture',['id'],a)==row_binding('fixture',['id'],b)


@pytest.mark.parametrize('a,b',[(1,True),(None,''),(uuid4(),'uuid'),(date(2026,1,1),'2026-01-01'),(Decimal('1'),1),(b'abc','abc')])
def test_types_never_collapse(a,b):assert typed(a)!=typed(b)


@pytest.mark.parametrize('value',[float('nan'),float('inf'),Decimal('NaN'),datetime(2026,1,1),object()])
def test_unsupported_or_ambiguous_types_rejected(value):
    with pytest.raises(ValueError):typed(value)


def test_binary_fingerprint_covers_full_bytes_and_length():
    assert typed(b'a')[1:]==[1,hashlib.sha256(b'a').hexdigest()]
    assert typed(memoryview(b'a'))==typed(b'a')
    assert typed(b'a')!=typed(b'aa')


def fixture():
    inv=DestinationInventory(['raw'],['officer'])
    inv.add_sql(row_binding('fixture',['id'],dict(id=1,value=b'cipher')),raw_id='raw')
    doc=dict(_id='event',raw_record_id='raw',cipher=b'protected')
    digest=hashlib.sha256(BSON.encode(doc)).hexdigest()
    inv.expect_mongo('collection','event','raw',digest)
    return inv,doc


def test_exact_bson_matches_and_binding_sorted():
    inv,doc=fixture();inv.add_mongo('collection',doc,BSON.encode)
    result=inv.finish()
    assert result['mongo_documents']==result['sql_records']==1
    assert len(result['raw_bindings']['raw'])==2


def test_mongo_missing_extra_duplicate_and_modified_rejected():
    inv,doc=fixture()
    with pytest.raises(ValueError):inv.finish()
    with pytest.raises(ValueError):inv.add_mongo('collection',dict(doc,_id='extra'),BSON.encode)
    with pytest.raises(ValueError):inv.add_mongo('collection',dict(doc,cipher=b'altered'),BSON.encode)
    inv.add_mongo('collection',doc,BSON.encode)
    with pytest.raises(ValueError):inv.add_mongo('collection',doc,BSON.encode)


def test_sql_duplicate_unknown_sources_and_missing_binding_rejected():
    inv=DestinationInventory(['raw'],['officer']);binding=row_binding('fixture',['id'],dict(id=1))
    with pytest.raises(ValueError):inv.add_sql(binding,raw_id='outside')
    with pytest.raises(ValueError):inv.add_sql(binding,officer_uid='outside')
    with pytest.raises(ValueError):inv.finish()
    inv.add_sql(binding,raw_id='raw')
    with pytest.raises(ValueError):inv.add_sql(binding,raw_id='raw')


def test_primary_key_table_and_column_set_are_bound():
    a=row_binding('one',['id'],dict(id=1,x=None))
    assert a!=row_binding('two',['id'],dict(id=1,x=None))
    assert a!=row_binding('one',['id'],dict(id=2,x=None))
    assert a!=row_binding('one',['id'],dict(id=1))
    with pytest.raises(ValueError):row_binding('one',['missing'],dict(id=1))


def test_mongo_wrong_raw_rejected():
    inv,doc=fixture()
    with pytest.raises(ValueError):inv.add_mongo('collection',dict(doc,raw_record_id='other'),BSON.encode)


def test_collector_binds_preparation_completion_and_live_source(monkeypatch):
    from app.identity import bind_evidence_destinations as collector
    from uuid import UUID
    raw='a'*64;assertion=uuid4();delivery=uuid4();file=uuid4();officer=uuid4()
    original=dict(columns=['x'],values=['private'])
    document=dict(_id=str(delivery),raw_record_id=raw,private_payload=b'protected')
    encoded=bytes(BSON.encode(document));digest=hashlib.sha256(encoded).hexdigest()
    rows={
        'identity.source_assertion':[dict(source_assertion_id=assertion,raw_record_id=raw)],
        'staging.service_delivery_preparation':[dict(delivery_id=delivery,raw_record_id=raw,source_assertion_id=assertion,document_bson=encoded,document_sha256=digest)],
        'staging.service_delivery_completion':[dict(delivery_id=delivery,document_sha256=digest)],
        'staging.intake_batch':[dict(batch_id='fixture')],
        'staging.intake_file':[dict(import_file_id=file)],
        'staging.raw_record':[dict(raw_record_id=raw,source_file_sha256='b'*64,source_row_number=1,import_file_id=file)]}
    monkeypatch.setattr(collector,'SQL_COUNTS',{name:1 for name in rows if name not in ('staging.intake_batch','staging.intake_file','staging.raw_record')})
    monkeypatch.setattr(collector,'ROWS',{'fixture.csv':1})
    monkeypatch.setattr(collector,'stored_row',lambda row:row)
    monkeypatch.setattr(collector,'open_row',lambda crypto,row:original)
    class Result:
        def __init__(self,data):self.data=data
        def mappings(self):return iter(self.data)
    class Connection:
        def execute(self,statement):return Result(rows[statement.get_final_froms()[0].fullname])
    catalog={raw:dict(original=original,delivery=dict(assertion_id=str(assertion)),
        provenance=dict(source_file_sha256='b'*64,source_row_number=1,import_file_id=str(file)))}
    inventory,counts=collector.collect_sql(Connection(),catalog,dict(bundles=[dict(officer_uid=str(officer))]),object(),object())
    inventory.add_mongo('service_status_events',document,BSON.encode)
    result=inventory.finish()
    assert result['sql_records']==6 and result['mongo_documents']==1
    assert len(result['raw_bindings'][raw])==5
    rows['staging.service_delivery_completion'][0]['document_sha256']='c'*64
    with pytest.raises(ValueError):collector.collect_sql(Connection(),catalog,dict(bundles=[dict(officer_uid=str(officer))]),object(),object())
