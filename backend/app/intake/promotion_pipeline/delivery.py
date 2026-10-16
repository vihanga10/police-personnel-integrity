"""Append-only destinations for new uploads, isolated from original batch tables.

The exact encrypted document is retained before either destination is called.
Ambiguous responses are reconciled by exact readback, not replacement writes.
"""
import base64
import hashlib
from .core import canonical, check, digest, opaque, publication

SQL_SCHEMA = '''
CREATE SCHEMA IF NOT EXISTS promotion_intake;
CREATE TABLE IF NOT EXISTS promotion_intake.evidence (
 record_id varchar(64) PRIMARY KEY,
 batch_id uuid NOT NULL,
 ciphertext bytea NOT NULL,
 ciphertext_sha256 varchar(64) NOT NULL,
 CHECK (record_id ~ '^[0-9a-f]{64}$'),
 CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
 CHECK (octet_length(ciphertext)>28)
);
'''
MONGO_DATABASE = 'police_promotion_intake'
COLLECTION = 'promotion_upload_events'

class PostgresDestination:
    def __init__(self, engine): self.engine = engine
    def put(self, document):
        from sqlalchemy import text
        with self.engine.begin() as c:
            c.execute(text('INSERT INTO promotion_intake.evidence(record_id,batch_id,ciphertext,ciphertext_sha256) VALUES(:id,CAST(:batch AS uuid),:cipher,:sha) ON CONFLICT(record_id) DO NOTHING'),
                {'id':document['record_id'],'batch':document['batch_id'],'cipher':base64.b64decode(document['ciphertext']),'sha':document['ciphertext_sha256']})
        self.verify(document)
    def put_many(self, documents):
        from sqlalchemy import text
        with self.engine.begin() as c:
            c.execute(text('INSERT INTO promotion_intake.evidence(record_id,batch_id,ciphertext,ciphertext_sha256) VALUES(:id,CAST(:batch AS uuid),:cipher,:sha) ON CONFLICT(record_id) DO NOTHING'),
                [{'id':d['record_id'],'batch':d['batch_id'],'cipher':base64.b64decode(d['ciphertext']),'sha':d['ciphertext_sha256']} for d in documents])
        self.verify_many(documents)
    def verify_many(self, documents):
        from sqlalchemy import text,bindparam
        wanted={d['record_id']:d for d in documents}
        check(len(wanted)==len(documents),'DUPLICATE_DELIVERY_ID')
        statement=text('SELECT record_id,batch_id,ciphertext,ciphertext_sha256 FROM promotion_intake.evidence WHERE record_id IN :ids').bindparams(bindparam('ids',expanding=True))
        with self.engine.connect() as c:rows=c.execute(statement,{'ids':list(wanted)}).fetchall()
        check(len(rows)==len(wanted),'SQL_READBACK_DIFFERS')
        for ident,batch,cipher,sha in rows:
            d=wanted[ident]
            check(str(batch)==d['batch_id'] and bytes(cipher)==base64.b64decode(d['ciphertext']) and sha==d['ciphertext_sha256'],'SQL_READBACK_DIFFERS')
    def verify(self, document):
        from sqlalchemy import text
        with self.engine.connect() as c:
            row = c.execute(text('SELECT batch_id,ciphertext,ciphertext_sha256 FROM promotion_intake.evidence WHERE record_id=:id'),{'id':document['record_id']}).fetchone()
        check(row is not None and str(row[0]) == document['batch_id'] and bytes(row[1]) == base64.b64decode(document['ciphertext']) and row[2] == document['ciphertext_sha256'], 'SQL_READBACK_DIFFERS')

class MongoDestination:
    def __init__(self, collection):
        check(collection.name == COLLECTION, 'MONGO_DESTINATION_DIFFERS')
        self.collection = collection
    def expected(self, document):
        # PyMongo decodes BSON binary subtype 0 to bytes. Encode bytes using
        # that same subtype so exact readback survives a real BSON round trip.
        return {'_id':document['record_id'],'batch_id':document['batch_id'],
                'ciphertext':base64.b64decode(document['ciphertext']),
                'ciphertext_sha256':document['ciphertext_sha256']}
    def put(self, document):
        from pymongo.errors import DuplicateKeyError
        try: self.collection.insert_one(self.expected(document))
        except DuplicateKeyError: pass
        self.verify(document)
    def put_many(self, documents):
        from pymongo.errors import BulkWriteError
        try:self.collection.insert_many([self.expected(d) for d in documents],ordered=False)
        except BulkWriteError as error:
            detail=error.details
            check(not detail.get('writeConcernErrors') and bool(detail.get('writeErrors')) and all(e.get('code')==11000 for e in detail['writeErrors']),'MONGO_BULK_WRITE_UNCERTAIN')
        self.verify_many(documents)
    def verify_many(self, documents):
        wanted={d['record_id']:self.expected(d) for d in documents}
        check(len(wanted)==len(documents),'DUPLICATE_DELIVERY_ID')
        rows=list(self.collection.find({'_id':{'$in':list(wanted)}}))
        check(len(rows)==len(wanted) and all(r==wanted.get(r['_id']) for r in rows),'MONGO_READBACK_DIFFERS')
    def verify(self, document):
        check(self.collection.find_one({'_id':document['record_id']}) == self.expected(document), 'MONGO_READBACK_DIFFERS')

def prepare(store, batch):
    saved = store.phase(batch['batch_id'], 'DOCUMENTS_PREPARED')
    if saved is not None: return saved
    documents = []
    for row in batch['rows']:
        if row['status'] != 'READY': continue
        record_id = opaque(store.key,'SOURCE_ID',row['source']['promotion_id'].strip())
        value = {'policy':'PROMOTION_SOURCE_ROW_V1','officer_uid':row['officer_uid'],
            'batch_id':batch['batch_id'],'file_sha256':batch['file_sha256'],'source_row':row['row'],
            'source':row['source'],'received_at':batch['received_at'],'source_reference':batch['source_reference'],
            'source_system':'PF_REGISTRY','source_custody':'UPLOADER_REPORTED','authority':'NOT_ASSESSED'}
        blob = store.seal('DELIVERY',record_id,value)
        documents.append({'record_id':record_id,'batch_id':batch['batch_id'],
            'ciphertext':base64.b64encode(blob).decode(),'ciphertext_sha256':hashlib.sha256(blob).hexdigest()})
    check(documents, 'NO_DELIVERY_ROWS')
    return store.phase(batch['batch_id'],'DOCUMENTS_PREPARED',{'documents':documents})

def reconcile(store, batch, documents, sql, mongo):
    rows = [r for r in batch['rows'] if r['status'] == 'READY']
    check(len(documents) == len(rows), 'DELIVERY_COUNT_DIFFERS')
    for row, d in zip(rows,documents,strict=True):
        check(d['batch_id'] == batch['batch_id'] and d['record_id'] == opaque(store.key,'SOURCE_ID',row['source']['promotion_id'].strip()), 'DELIVERY_BINDING_DIFFERS')
        blob = base64.b64decode(d['ciphertext'],validate=True)
        check(hashlib.sha256(blob).hexdigest() == d['ciphertext_sha256'], 'DELIVERY_DIGEST_DIFFERS')
        original = store.open('DELIVERY',d['record_id'],blob)
        check(original == {'policy':'PROMOTION_SOURCE_ROW_V1','officer_uid':row['officer_uid'],
            'batch_id':batch['batch_id'],'file_sha256':batch['file_sha256'],'source_row':row['row'],
            'source':row['source'],'received_at':batch['received_at'],'source_reference':batch['source_reference'],
            'source_system':'PF_REGISTRY','source_custody':'UPLOADER_REPORTED','authority':'NOT_ASSESSED'}, 'DELIVERY_PLAINTEXT_DIFFERS')
    for destination in (sql,mongo):
        if hasattr(destination,'verify_many'):destination.verify_many(documents)
        else:
            for d in documents:destination.verify(d)
    return {'documents_sha256':digest(documents),'row_count':len(documents)}

def process(store, batch_id, sql, mongo, chains, authorize):
    """One resumable batch. Exceptions preserve every retained prior phase.

    chains implements the pinned dual-chain retained-transaction coordinator;
    its callback invokes storage reconciliation at every signing/broadcast gate.
    """
    with store.worker_lock():
        batch = store.get(batch_id)
        check(store.phase(batch_id,'QUEUED') is not None, 'IMPORT_NOT_COMMITTED')
        authorize(batch)
        documents = prepare(store,batch)['documents']
        for phase, destination in (('SQL_STORED',sql),('MONGO_STORED',mongo)):
            authorize(batch)
            if store.phase(batch_id,phase) is None:
                if hasattr(destination,'put_many'):destination.put_many(documents)
                else:
                    for document in documents:destination.put(document)
                store.phase(batch_id,phase,{'documents_sha256':digest(documents)})
            else:
                if hasattr(destination,'verify_many'):destination.verify_many(documents)
                else:
                    for document in documents:destination.verify(document)
        expected = reconcile(store,batch,documents,sql,mongo)
        store.phase(batch_id,'STORAGE_VERIFIED',expected)
        payload, manifest = publication(store.key,batch)
        def boundary():
            authorize(batch)
            check(reconcile(store,batch,documents,sql,mongo) == expected, 'STORAGE_CHANGED')
        receipt = store.phase(batch_id,'CHAINS_VERIFIED')
        if receipt is None:
            result = chains(batch,payload,boundary)
            if result.get('status') != 'BOTH_CHAINS_VERIFIED':
                return {'status':'CHAIN_CONFIRMATION_PENDING','batch_id':batch_id}
            # Transport adapter authenticates exact tx bytes and both organization/
            # provider readbacks. Repeat the cross-layer binding before visibility.
            check(result['fabric']['payload'] == payload and result['fabric']['status'] == 'FINAL', 'FABRIC_RECEIPT_DIFFERS')
            check(result['public']['status'] == 'FINAL', 'PUBLIC_FINALITY_REQUIRED')
            pp = result['public']['payload']
            expected_public={'policy':'PROMOTIONS_PUBLIC_ANCHOR_V1','namespace':'promotions-anchor-v1',
                'publication_id':payload['publication_id'],'public_sha256':payload['public_sha256'],'merkle_root':payload['merkle_root'],
                'fabric_destination_sha256':digest(result['fabric']['destination']),
                'fabric_transaction_id':result['fabric']['transaction_id'],'fabric_receipt_sha256':digest(result['fabric'])}
            check(pp==expected_public,'PUBLIC_RECEIPT_DIFFERS')
            boundary()
            from datetime import datetime,timezone
            result={**result,'verification_observed_at':datetime.now(timezone.utc).isoformat()}
            receipt = store.phase(batch_id,'CHAINS_VERIFIED',result)
        boundary()
        store.phase(batch_id,'VISIBLE',{'publication':payload,'manifest_sha256':digest(manifest),
            'receipt_sha256':digest(receipt),'storage':expected})
        return {'status':'BOTH_CHAINS_VERIFIED','batch_id':batch_id}
