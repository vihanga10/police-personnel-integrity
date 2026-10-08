"""Typed complete-row fingerprints inside encrypted manifests, not public commitments."""
import hashlib
import json
import math
from datetime import date, datetime, timezone
from decimal import Decimal
from uuid import UUID

POLICY = "EVIDENCE_DESTINATION_BINDING_V1"


def require(condition, message):
    if not condition:raise ValueError(message)


def typed(value):
    # Type tags prevent UUID/text, dates/text, booleans/integers and null collisions.
    if value is None:return ['null']
    if type(value) is bool:return ['bool',value]
    if type(value) is int:return ['int',str(value)]
    if isinstance(value,str):return ['text',value]
    if isinstance(value,UUID):return ['uuid',str(value)]
    if isinstance(value,datetime):
        require(value.tzinfo is not None and value.utcoffset() is not None, 'Naive destination timestamp.')
        return ['timestamp',value.astimezone(timezone.utc).isoformat(timespec='microseconds')]
    if isinstance(value,date):return ['date',value.isoformat()]
    if isinstance(value,Decimal):
        require(value.is_finite(),'Nonfinite destination decimal.')
        return ['decimal',str(value)]
    if type(value) is float:
        require(math.isfinite(value),'Nonfinite destination float.')
        return ['float',value.hex()]
    if isinstance(value,(bytes,bytearray,memoryview)):
        raw=bytes(value)
        return ['bytes',len(raw),hashlib.sha256(raw).hexdigest()]
    if isinstance(value,(list,tuple)):return ['list',[typed(v) for v in value]]
    if isinstance(value,dict):
        require(all(isinstance(k,str) for k in value),'Invalid destination JSON keys.')
        return ['map',[[k,typed(value[k])] for k in sorted(value)]]
    raise ValueError('Unsupported destination value type.')


def row_binding(table, primary_keys, row):
    require(isinstance(table,str) and table and primary_keys and all(k in row and row[k] is not None for k in primary_keys), 'Destination primary key differs.')
    encoded=json.dumps([POLICY,table,typed(dict(row))],ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
    return dict(table=table,primary_key=[[k,typed(row[k])] for k in primary_keys],row_sha256=hashlib.sha256(encoded).hexdigest(),columns=sorted(row))


def slot(binding):
    return json.dumps([binding['table'],binding['primary_key']],separators=(',',':'))


def verify_binding(expected, actual):
    require(expected==actual,'Destination row version or content differs.')


class DestinationInventory:
    def __init__(self, raw_ids, officer_ids):
        self.raw={r:[] for r in raw_ids};self.officers={o:[] for o in officer_ids}
        self.shared=[];self.seen=set();self.assertions={};self.deliveries={};self.mongo={};self.mongo_seen=set()

    def add_sql(self,binding,raw_id=None,officer_uid=None):
        key=slot(binding)
        require(key not in self.seen,'Repeated destination primary key.')
        require(raw_id is None or raw_id in self.raw,'Destination outside reviewed source batch.')
        require(officer_uid is None or officer_uid in self.officers,'Destination outside officer universe.')
        self.seen.add(key)
        if raw_id is not None:self.raw[raw_id].append(binding)
        elif officer_uid is not None:self.officers[officer_uid].append(binding)
        else:self.shared.append(binding)

    def expect_mongo(self,collection,identifier,raw_id,digest):
        key=(collection,identifier)
        require(key not in self.mongo and raw_id in self.raw,'Mongo preparation coverage differs.')
        self.mongo[key]=(raw_id,digest)

    def add_mongo(self,collection,document,encode):
        key=(collection,document.get('_id'))
        require(key in self.mongo and key not in self.mongo_seen,'Unexpected or repeated Mongo document.')
        raw_id,digest=self.mongo[key]
        require(document.get('raw_record_id')==raw_id,'Mongo source binding differs.')
        actual=hashlib.sha256(encode(document)).hexdigest()
        require(actual==digest,'Mongo BSON differs from SQL preparation.')
        self.raw[raw_id].append(dict(store='mongodb',collection=collection,document_id=document['_id'],document_sha256=actual))
        self.mongo_seen.add(key)

    def finish(self):
        require(self.mongo_seen==set(self.mongo),'Prepared Mongo document missing.')
        require(all(records for records in self.raw.values()),'Source row has no destination binding.')
        order=lambda item:json.dumps(item,sort_keys=True,separators=(',',':'))
        return dict(policy=POLICY,raw_bindings={r:sorted(v,key=order) for r,v in sorted(self.raw.items())},
            officer_bindings={o:sorted(v,key=order) for o,v in sorted(self.officers.items())},shared_bindings=sorted(self.shared,key=order),
            sql_records=len(self.seen),mongo_documents=len(self.mongo_seen))
