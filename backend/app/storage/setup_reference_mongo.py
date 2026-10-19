"""Create empty protected reference stores without modifying imported evidence."""
import argparse
from app.storage.reference_mongo_connection import reference_password, reference_client
from app.storage.reference_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges, validator
from app.storage.mongo_connection import client, load_credentials
from app.storage.setup_mongo import verify_role
from app.storage import setup_remaining_mongo as previous
from app.storage.remaining_mongo_contract import APP_USER as REMAINING_USER, ROLE as REMAINING_ROLE, privileges as remaining_privileges
from app.storage.remaining_mongo_connection import remaining_password, remaining_client

EXISTING_COUNTS = dict(previous.EXISTING_COUNTS, education_records=6596, operation_records=19554,
                       court_records=9538, complaint_records=998, demotion_events=8)
ACCOUNT_DEFINITIONS = (
    (previous.SERVICE_USER, previous.SERVICE_ROLE, previous.service_privileges),
    (previous.HISTORY_USER, previous.HISTORY_ROLE, previous.history_privileges),
    (previous.SRB_USER, previous.SRB_ROLE, previous.srb_privileges),
    (previous.ACTIVITY_USER, previous.ACTIVITY_ROLE, previous.activity_privileges),
    (REMAINING_USER, REMAINING_ROLE, remaining_privileges), (APP_USER, ROLE, privileges),
)
INDEXES = {'_id_': ([('_id', 1)], False),
           'uq_source_policy': ([('raw_record_id', 1), ('writer_policy', 1)], True),
           'uq_source_assertion': ([('source_assertion_uid', 1)], True)}


def verify_reference_collection(database, name):
    info = list(database.list_collections(filter={'name': name}))
    options = dict(validator=validator(name), validationLevel='strict', validationAction='error')
    if len(info) != 1 or info[0]['type'] != 'collection' or info[0]['options'] != options:
        raise RuntimeError('Reference collection contract differs; no modification permitted.')
    indexes = list(database[name].list_indexes())
    if len(indexes) != len(INDEXES):
        raise RuntimeError('Reference index count differs.')
    for index in indexes:
        if index['name'] not in INDEXES or (list(index['key'].items()), index.get('unique', False)) != INDEXES[index['name']]:
            raise RuntimeError('Reference index definition differs.')
        if any(k in index for k in ('expireAfterSeconds', 'partialFilterExpression', 'sparse', 'hidden', 'collation')):
            raise RuntimeError('Reference index behavior differs.')


def create_reference_collection(database, name):
    database.create_collection(name, validator=validator(name), validationLevel='strict', validationAction='error')
    for index, (keys, unique) in INDEXES.items():
        if index != '_id_':
            database[name].create_index(keys, unique=unique, name=index)


def verify_accounts(database, *, require_reference):
    """Do not call an older inventory gate that cannot recognize this new account.

    Require exact roles, inherited-role absence and user assignments for all six
    technical accounts. Never repair or broaden an existing role automatically.
    """
    roles = database.command('rolesInfo', 1)['roles']
    users = database.command('usersInfo', 1)['users']
    if any(r['role'] not in {r for _, r, _ in ACCOUNT_DEFINITIONS} for r in roles) or any(u['user'] not in {u for u, _, _ in ACCOUNT_DEFINITIONS} for u in users):
        raise RuntimeError('Unexpected research roles or accounts.')
    for user, role, expected_privileges in ACCOUNT_DEFINITIONS:
        found_roles = [r for r in roles if r['role'] == role]
        found_users = [u for u in users if u['user'] == user]
        required = user != APP_USER or require_reference
        if (required and (len(found_roles) != 1 or len(found_users) != 1)) or len(found_roles) > 1 or len(found_users) > 1:
            raise RuntimeError('Required technical role/account differs.')
        if found_roles:
            verify_role(database, role, expected_privileges())
        if found_users and found_users[0]['roles'] != [{'role': role, 'db': DATABASE}]:
            raise RuntimeError('Unexpected application role assignment.')
    return any(r['role'] == ROLE for r in roles), any(u['user'] == APP_USER for u in users)


def verify_existing(database):
    previous.verify_existing(database)
    for name in ('education_records', 'operation_records', 'court_records', 'complaint_records', 'demotion_events'):
        previous.verify_remaining_collection(database, name)
    if any(database[name].count_documents({}) != count for name, count in EXISTING_COUNTS.items()):
        raise RuntimeError('Previously reconciled counts differ.')


def arguments(parser):
    for name in ('bootstrap', 'history', 'srb', 'activity', 'remaining', 'reference'):
        parser.add_argument('--' + name + '-credential-directory', required=True)
    return parser.parse_args()


def credentials(args, *, create_reference=False):
    previous.separate_directories(args.bootstrap_credential_directory, args.history_credential_directory,
        args.srb_credential_directory, args.activity_credential_directory, args.remaining_credential_directory, args.reference_credential_directory)
    root, service = load_credentials(args.bootstrap_credential_directory)
    history = previous.history_password(args.history_credential_directory)
    srb = previous.srb_password(args.srb_credential_directory)
    activity = previous.activity_password(args.activity_credential_directory)
    remaining = remaining_password(args.remaining_credential_directory)
    reference = reference_password(args.reference_credential_directory, create=create_reference)
    return root, service, history, srb, activity, remaining, reference


def existing_readers(secrets):
    service, history, srb, activity, remaining = secrets
    return ((client, service, ('service_status_events',)),
        (previous.history_client, history, ('transfer_events', 'promotion_events')),
        (previous.srb_client, srb, ('police_number_intervals', 'restriction_records', 'restriction_overrides')),
        (previous.activity_client, activity, ('duty_periods', 'firearms_assessments', 'good_conduct_records', 'bad_conduct_records')),
        (remaining_client, remaining, ('education_records', 'operation_records', 'court_records', 'complaint_records', 'demotion_events')))


def main():
    args = arguments(argparse.ArgumentParser(description=__doc__))
    root, *passwords = credentials(args, create_reference=True)
    reference_secret = passwords[-1]
    with client(root, bootstrap=True) as bootstrap:
        if not bootstrap.server_info()['version'].startswith('8.0.'):
            raise RuntimeError('Unexpected Mongo server version.')
        database = bootstrap[DATABASE]
        verify_existing(database)
        has_role, has_user = verify_accounts(database, require_reference=False)
        names = set(database.list_collection_names())
        if not set(EXISTING_COUNTS) <= names or not names <= {*EXISTING_COUNTS, *COLLECTION_POLICIES}:
            raise RuntimeError('Unexpected research collections.')
        # Authenticate every existing account before creating new Mongo resources.
        for factory, password, collections in existing_readers(passwords[:-1]):
            with factory(password) as reader:
                if any(reader[DATABASE][name].count_documents({}) != EXISTING_COUNTS[name] for name in collections):
                    raise RuntimeError('Existing application credential/count differs.')
        if has_user:
            with reference_client(reference_secret) as reader:
                # Check the authenticated identity before adding any resources.
                status = reader.admin.command('connectionStatus')
                if status['authInfo']['authenticatedUsers'] != [{'user': APP_USER, 'db': DATABASE}]:
                    raise RuntimeError('Existing reference credential identity differs.')
        for name in COLLECTION_POLICIES:
            if name in names:
                verify_reference_collection(database, name)
                if database[name].count_documents({}) != 0:
                    raise RuntimeError('Reference setup requires empty reference stores.')
        for name in COLLECTION_POLICIES:
            if name not in names:
                create_reference_collection(database, name)
            verify_reference_collection(database, name)
        if not has_role:
            database.command('createRole', ROLE, privileges=privileges(), roles=[])
        if not has_user:
            database.command('createUser', APP_USER, pwd=reference_secret, roles=[{'role': ROLE, 'db': DATABASE}])
        verify_accounts(database, require_reference=True)
        with reference_client(reference_secret) as reader:
            if any(reader[DATABASE][name].count_documents({}) != 0 for name in COLLECTION_POLICIES):
                raise RuntimeError('Unexpected reference evidence count.')
        verify_existing(database)
    print('Reference Mongo storage setup: PASSED')
    print('station_reference_records: 0 | station_sinhala_reference_records: 0')
    print('Existing service/history/SRB/activity/remaining counts and contracts unchanged.')
    print('Dedicated reference account has find/insert access only to the two reference collections.')
    print('No reference import, accepted station linkage or human access grants; no existing evidence changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Reference setup stopped: ' + type(error).__name__ + '. Review before importing reference evidence.') from None
