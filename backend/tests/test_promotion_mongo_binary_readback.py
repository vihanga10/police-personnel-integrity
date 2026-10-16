"""Use real BSON encoding/decoding rather than an in-memory dict copy."""
import base64
import hashlib
from copy import deepcopy
from bson import BSON, Binary
import pytest
from app.intake.promotion_pipeline.delivery import MongoDestination, COLLECTION
from app.intake.promotion_pipeline.core import IntakeError

class Collection:
    name = COLLECTION
    def __init__(self): self.rows = {}; self.writes = 0
    def insert_one(self, value):
        self.writes += 1
        self.rows[value['_id']] = BSON.encode(value).decode()
    def insert_many(self, values, ordered=False):
        for value in values: self.insert_one(value)
    def find_one(self, query): return deepcopy(self.rows.get(query['_id']))
    def find(self, query):
        return [deepcopy(v) for k,v in self.rows.items() if k in query['_id']['$in']]

def document(number=1):
    blob = b'encrypted-fixture-' + bytes([number]) * 32
    return {'record_id':str(number)*64,'batch_id':'37391354-4a42-43ed-8c36-8d177417f76c',
            'ciphertext':base64.b64encode(blob).decode(),
            'ciphertext_sha256':hashlib.sha256(blob).hexdigest()}

def test_single_real_bson_roundtrip():
    collection = Collection(); destination = MongoDestination(collection); d = document()
    destination.put(d)
    assert type(collection.rows[d['record_id']]['ciphertext']) is bytes
    destination.verify(d)
    assert collection.writes == 1

def test_five_real_bson_roundtrips_readback_without_rewriting():
    collection = Collection(); destination = MongoDestination(collection)
    docs = [document(n) for n in range(1,6)]
    destination.put_many(docs)
    destination.verify_many(docs)
    for d in docs: destination.verify(d)
    assert collection.writes == 5

@pytest.mark.parametrize('change', ['ciphertext','batch_id','ciphertext_sha256','extra','subtype','missing'])
@pytest.mark.parametrize('many', [False,True])
def test_real_readback_still_rejects_every_changed_field(change,many):
    collection = Collection(); destination = MongoDestination(collection); d = document()
    destination.put(d); row = collection.rows[d['record_id']]
    if change == 'extra': row['unexpected'] = 'refuse'
    elif change == 'missing': del collection.rows[d['record_id']]
    elif change == 'subtype': row['ciphertext'] = Binary(row['ciphertext'], subtype=128)
    elif change == 'ciphertext': row['ciphertext'] += b'changed'
    else: row[change] = 'changed'
    with pytest.raises(IntakeError, match='MONGO_READBACK_DIFFERS'):
        if many: destination.verify_many([d])
        else: destination.verify(d)
    assert collection.writes == 1
