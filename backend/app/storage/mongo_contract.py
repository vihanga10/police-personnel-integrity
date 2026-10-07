"""Storage contract only: human authorization and SQL linkage are separate gates."""
from copy import deepcopy

DATABASE = "police_operations"
COLLECTION = "service_status_events"
ROLE = "service_evidence_append_v1"
APP_USER = "police_operations_app"

# Only opaque provenance and encrypted content may be stored in this collection.
# BSON validation cannot prove encryption: authenticated recovery is a writer gate.
_UUID = {"bsonType": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}
_HEX = {"bsonType": "string", "pattern": "^[0-9a-f]{64}$"}
PROPERTIES = {
    "_id": _UUID,
    "officer_uid": _UUID,
    "source_assertion_uid": _UUID,
    "raw_record_id": _HEX,
    "writer_policy": {"enum": ["HR_SERVICE_EVIDENCE_V1"]},
    "schema_version": {"bsonType": "int", "enum": [1]},
    "classification": {"enum": ["UNASSESSED"]},
    "recorded_at": {"bsonType": "date"},
    "payload_ciphertext": {"bsonType": "binData"},
    "payload_key_version": {"bsonType": "string", "minLength": 1, "maxLength": 128},
}


def validator():
    """Strict shape plus a length guard for nonce, tag and nonempty ciphertext."""
    return {"$and": [
        {"$jsonSchema": {"bsonType": "object", "additionalProperties": False,
                         "required": list(PROPERTIES), "properties": deepcopy(PROPERTIES)}},
        # Guard the expression independently; query evaluation order is unspecified.
        {"$expr": {"$gte": [{"$cond": [
            {"$eq": [{"$type": "$payload_ciphertext"}, "binData"]},
            {"$binarySize": "$payload_ciphertext"}, 0]}, 29]}},
    ]}


def privileges(database=DATABASE):
    """An app may append/read evidence, never mutate it or bypass validation."""
    return [{"resource": {"db": database, "collection": COLLECTION},
             "actions": ["find", "insert"]}]


def encryption_context(document):
    """Bind ciphertext to immutable routing/provenance, including the event ID."""
    import json
    fields = ("_id", "officer_uid", "source_assertion_uid", "raw_record_id",
              "writer_policy", "schema_version", "classification", "payload_key_version")
    # BSON dates have millisecond precision; bind the persisted representation.
    from datetime import timezone
    timestamp = document["recorded_at"].astimezone(timezone.utc).isoformat(timespec="milliseconds")
    return json.dumps(["MONGO_SERVICE_EVIDENCE_V1", [document[f] for f in fields], timestamp],
                      separators=(",", ":"))
