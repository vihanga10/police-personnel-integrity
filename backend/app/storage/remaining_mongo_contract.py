"""Strict encrypted remaining HR/PF envelopes; classification and human access remain pending."""
from copy import deepcopy
import json
from datetime import timezone
from app.storage.mongo_contract import DATABASE, PROPERTIES as SERVICE_PROPERTIES

COLLECTION_POLICIES = {'education_records': 'HR_EDUCATION_EVIDENCE_V1', 'operation_records': 'PF_OPERATION_EVIDENCE_V1', 'court_records': 'PF_COURT_EVIDENCE_V1', 'complaint_records': 'PF_COMPLAINT_EVIDENCE_V1', 'demotion_events': 'PF_DEMOTION_EVIDENCE_V1'}
ROLE = 'remaining_evidence_append_v1'
APP_USER = 'police_remaining_app'


def properties(collection):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported remaining collection.')
    # Reuse the established opaque envelope shape, with a distinct writer policy.
    result = deepcopy(SERVICE_PROPERTIES)
    # Multi-person events have no single subject; never fabricate an officer UID.
    if collection in {'operation_records', 'court_records'}:
        result['officer_uid'] = {'bsonType': 'null'}
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
    # A dedicated remaining writer cannot modify remaining or access previous evidence.
    return [{'resource': {'db': database, 'collection': name}, 'actions': ['find', 'insert']}
            for name in COLLECTION_POLICIES]


def encryption_context(collection, document):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported remaining collection.')
    fields = ('_id', 'officer_uid', 'source_assertion_uid', 'raw_record_id',
              'writer_policy', 'schema_version', 'classification', 'payload_key_version')
    recorded = document['recorded_at']
    if recorded.utcoffset() is None:
        raise ValueError('An aware timestamp is required.')
    # Bind the destination as well as provenance; BSON timestamps retain milliseconds.
    timestamp = recorded.astimezone(timezone.utc).isoformat(timespec='milliseconds')
    return json.dumps(['MONGO_REMAINING_EVIDENCE_V1', collection,
                       [document[f] for f in fields], timestamp], separators=(',', ':'))
