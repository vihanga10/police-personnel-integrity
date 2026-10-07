"""Strict encrypted station reference envelopes; classification and human access remain pending."""
from copy import deepcopy
import json
from datetime import timezone
from app.storage.mongo_contract import DATABASE, PROPERTIES as SERVICE_PROPERTIES

COLLECTION_POLICIES = {'station_reference_records': 'HR_STATION_REFERENCE_EVIDENCE_V1', 'station_sinhala_reference_records': 'HR_STATION_SINHALA_REFERENCE_EVIDENCE_V1'}
ROLE = 'reference_evidence_append_v1'
APP_USER = 'police_reference_app'


def properties(collection):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported reference collection.')
    # Reuse the established opaque envelope shape, with a distinct writer policy.
    result = deepcopy(SERVICE_PROPERTIES)
    # Station references are not officer records. All labels/codes stay encrypted.
    del result['officer_uid']
    result['writer_policy'] = {'enum': [COLLECTION_POLICIES[collection]]}
    return result


def validator(collection):
    fields = properties(collection)
    return {'$and': [
        {'$jsonSchema': {'bsonType': 'object', 'additionalProperties': False,
                        'required': list(fields), 'properties': fields}},
        # Binary length alone cannot establish encryption; recovery is a writer gate.
        {'$expr': {'$gte': [{'$cond': [
            {'$eq': [{'$type': '$payload_ciphertext'}, 'binData']},
            {'$binarySize': '$payload_ciphertext'}, 0]}, 29]}},
    ]}


def privileges(database=DATABASE):
    # A dedicated reference writer cannot modify reference or access previous evidence.
    return [{'resource': {'db': database, 'collection': name}, 'actions': ['find', 'insert']}
            for name in COLLECTION_POLICIES]


def encryption_context(collection, document):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported reference collection.')
    fields = ('_id', 'source_assertion_uid', 'raw_record_id',
              'writer_policy', 'schema_version', 'classification', 'payload_key_version')
    recorded = document['recorded_at']
    if recorded.utcoffset() is None:
        raise ValueError('An aware timestamp is required.')
    # Bind the destination as well as provenance; BSON timestamps retain milliseconds.
    timestamp = recorded.astimezone(timezone.utc).isoformat(timespec='milliseconds')
    return json.dumps(['MONGO_REFERENCE_EVIDENCE_V1', collection,
                       [document[f] for f in fields], timestamp], separators=(',', ':'))
