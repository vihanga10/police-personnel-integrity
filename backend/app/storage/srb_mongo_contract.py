"""Strict encrypted SRB envelopes; classification and human access remain pending."""
from copy import deepcopy
import json
from datetime import timezone
from app.storage.mongo_contract import DATABASE, PROPERTIES as SERVICE_PROPERTIES

COLLECTION_POLICIES = {'police_number_intervals': 'SRB_POLICE_NUMBER_EVIDENCE_V1',
                       'restriction_records': 'SRB_RESTRICTION_EVIDENCE_V1',
                       'restriction_overrides': 'SRB_OVERRIDE_EVIDENCE_V1'}
ROLE = 'srb_evidence_append_v1'
APP_USER = 'police_srb_app'


def properties(collection):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported SRB collection.')
    # Reuse the established opaque envelope shape, with a distinct writer policy.
    result = deepcopy(SERVICE_PROPERTIES)
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
    # A dedicated SRB writer cannot modify SRB or access service evidence.
    return [{'resource': {'db': database, 'collection': name}, 'actions': ['find', 'insert']}
            for name in COLLECTION_POLICIES]


def encryption_context(collection, document):
    if collection not in COLLECTION_POLICIES:
        raise ValueError('Unsupported SRB collection.')
    fields = ('_id', 'officer_uid', 'source_assertion_uid', 'raw_record_id',
              'writer_policy', 'schema_version', 'classification', 'payload_key_version')
    recorded = document['recorded_at']
    if recorded.utcoffset() is None:
        raise ValueError('An aware timestamp is required.')
    # Bind the destination as well as provenance; BSON timestamps retain milliseconds.
    timestamp = recorded.astimezone(timezone.utc).isoformat(timespec='milliseconds')
    return json.dumps(['MONGO_SRB_EVIDENCE_V1', collection,
                       [document[f] for f in fields], timestamp], separators=(',', ':'))
