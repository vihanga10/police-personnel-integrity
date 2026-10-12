"""Current web access policy; never historical action authority or chain approval."""
import base64
import json
import re
import time
import unicodedata
from uuid import UUID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

POLICY = 'SCOPED_PERSONNEL_ACCESS_V1'
RETAINED_DIRECTORY_POLICY = 'GENERATED_RETAINED_DIRECTORY_V1'
ROLES = {'IGP': {'ALL'}, 'HQ_ADMIN': {'ALL'}, 'SDIG': {'PROVINCE'},
         'DIG': {'DISTRICT', 'DIVISION'}, 'SSP': {'DISTRICT', 'DIVISION'},
         'SP': {'DISTRICT', 'DIVISION'}, 'STATION_OIC': {'STATION'}}
LEVELS = ('PROVINCE', 'DISTRICT', 'DIVISION', 'STATION')

class AccessError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)

def require(value, message='Invalid administrative input'):
    if not value:
        raise ValueError(message)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()

def uid(value):
    require(type(value) is str and str(UUID(value)) == value, 'Canonical UUID required')
    return value

def label(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}', value), 'Canonical scope ID required')
    return value

def username(value):
    require(type(value) is str and re.fullmatch('[a-z][a-z0-9_.-]{2,63}', value), 'Canonical login required')
    return value

def name(value):
    require(type(value) is str and 1 <= len(value) <= 300 and
            not any(unicodedata.category(c).startswith('C') and c not in ('\u200c','\u200d') for c in value), 'Name input invalid')
    return ' '.join(unicodedata.normalize('NFKC', value).casefold().split())

def signed(envelope, keys, kind, *, now=None):
    """Only configured administrators sign enrollment/membership, not HTTP clients."""
    now = time.time() if now is None else now
    require(type(envelope) is dict and set(envelope) == {'key_id', 'payload', 'signature'}, 'Signed envelope required')
    require(type(envelope['key_id']) is str and envelope['key_id'] in keys, 'Unknown authority')
    p = envelope['payload']
    require(type(p) is dict and p.get('kind') == kind, 'Wrong administrative domain')
    if p.get('policy') == RETAINED_DIRECTORY_POLICY:
        require(kind == 'DIRECTORY' and p.get('record_origin') == 'GENERATED_RESEARCH_RECORDS' and
                p.get('expires_at') is None and type(p.get('issued_at')) is int and p['issued_at'] <= now,
                'Retained generated directory required')
    else:
        require(p.get('policy') == POLICY, 'Wrong administrative domain')
        require(type(p.get('issued_at')) is int and type(p.get('expires_at')) is int and
                p['issued_at'] <= now < p['expires_at'] <= p['issued_at'] + 86400, 'Current bounded administrative grant required')
    require(type(envelope['signature']) is str, 'Signature required')
    Ed25519PublicKey.from_public_bytes(keys[envelope['key_id']]).verify(
        base64.b64decode(envelope['signature'], validate=True), encoded(p))
    return p

def account(envelope, keys, *, now=None):
    p = signed(envelope, keys, 'ACCOUNT', now=now)
    require(set(p) == {'policy', 'kind', 'issued_at', 'expires_at', 'user_id', 'username', 'role',
                      'scope_type', 'scope_id', 'version', 'active', 'review_reference'}, 'Account fields differ')
    uid(p['user_id']); username(p['username']); label(p['review_reference'])
    require(type(p['version']) is int and p['version'] > 0 and type(p['active']) is bool, 'Account version invalid')
    require(p['role'] in ROLES and p['scope_type'] in ROLES[p['role']], 'Role/scope forbidden')
    if p['scope_type'] == 'ALL':
        require(p['scope_id'] is None, 'ALL scope must not carry an ID')
    else:
        label(p['scope_id'])
    return p

def permitted(grant, officer):
    """Membership is server-owned; unresolved membership never grants scoped access."""
    level = grant['scope_type']
    return level == 'ALL' or officer['membership'].get(level) == grant['scope_id']

def projection(officer):
    return {'officer_uid': officer['officer_uid'], 'names': list(officer['names']),
            'nic': officer['nic'], 'identity_status': 'REPORTED_CANDIDATE_NOT_ACCEPTED',
            'source_raw_id': officer['source_raw_id'], 'projection': 'OFFICER_NAME_NIC'}
