"""Add empty protected history stores without altering imported service evidence."""
import argparse
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.history_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges, validator
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import APP_USER as SERVICE_USER, ROLE as SERVICE_ROLE, privileges as service_privileges
from app.storage.setup_mongo import verify_collection as verify_service_collection, verify_role


def verify_history_collection(database, name):
    info = list(database.list_collections(filter={'name': name}))
    expected_options = {'validator': validator(name), 'validationLevel': 'strict', 'validationAction': 'error'}
    if len(info) != 1 or info[0]['type'] != 'collection' or info[0]['options'] != expected_options:
        raise RuntimeError('Historical collection contract differs; no modification permitted.')
    expected = {'_id_': ([('_id', 1)], False),
                'uq_source_policy': ([('raw_record_id', 1), ('writer_policy', 1)], True),
                'officer_evidence': ([('officer_uid', 1), ('recorded_at', 1)], False)}
    indexes = list(database[name].list_indexes())
    if len(indexes) != len(expected):
        raise RuntimeError('Historical index count differs.')
    for index in indexes:
        if index['name'] not in expected or (list(index['key'].items()), index.get('unique', False)) != expected[index['name']]:
            raise RuntimeError('Historical index definition differs.')
        if any(k in index for k in ('expireAfterSeconds', 'partialFilterExpression', 'sparse', 'hidden', 'collation')):
            raise RuntimeError('Historical index behavior differs.')


def create_history_collection(database, name):
    database.create_collection(name, validator=validator(name), validationLevel='strict', validationAction='error')
    database[name].create_index([('raw_record_id', 1), ('writer_policy', 1)], unique=True, name='uq_source_policy')
    database[name].create_index([('officer_uid', 1), ('recorded_at', 1)], name='officer_evidence')


def verify_accounts(database, *, require_history):
    roles = database.command('rolesInfo', 1)['roles']
    users = database.command('usersInfo', 1)['users']
    if any(r['role'] not in {SERVICE_ROLE, ROLE} for r in roles) or any(u['user'] not in {SERVICE_USER, APP_USER} for u in users):
        raise RuntimeError('Unexpected research accounts or roles.')
    verify_role(database, SERVICE_ROLE, service_privileges())
    for user, role in ((SERVICE_USER, SERVICE_ROLE), (APP_USER, ROLE)):
        selected = [u for u in users if u['user'] == user]
        if user == SERVICE_USER or require_history:
            if len(selected) != 1:
                raise RuntimeError('Required research account is missing.')
        if selected and selected[0]['roles'] != [{'role': role, 'db': DATABASE}]:
            raise RuntimeError('Unexpected account role assignment.')
    history_roles = [r for r in roles if r['role'] == ROLE]
    if history_roles:
        verify_role(database, ROLE, privileges())
    elif require_history:
        raise RuntimeError('Historical writer role is missing.')
    return bool(history_roles), any(u['user'] == APP_USER for u in users)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-credential-directory', required=True)
    parser.add_argument('--history-credential-directory', required=True)
    args = parser.parse_args()
    from pathlib import Path
    if Path(args.bootstrap_credential_directory).expanduser().resolve() == Path(args.history_credential_directory).expanduser().resolve():
        raise ValueError('Use a separate private history credential directory.')
    root, service_password = load_credentials(args.bootstrap_credential_directory)
    password = history_password(args.history_credential_directory, create=True)
    with client(root, bootstrap=True) as bootstrap:
        if not bootstrap.server_info()['version'].startswith('8.0.'):
            raise RuntimeError('Unexpected Mongo server version.')
        database = bootstrap[DATABASE]
        verify_service_collection(database)
        has_role, has_user = verify_accounts(database, require_history=False)
        names = set(database.list_collection_names())
        if not {'service_status_events'} <= names or not names <= {'service_status_events', *COLLECTION_POLICIES}:
            raise RuntimeError('Unexpected research collections.')
        before = database.service_status_events.count_documents({})
        if before != 6596:
            raise RuntimeError('Service count differs from the reconciled checkpoint.')
        # Preflight ALL existing history contracts before creating anything new.
        for name in COLLECTION_POLICIES:
            if name in names:
                verify_history_collection(database, name)
                if database[name].count_documents({}) != 0:
                    raise RuntimeError('History foundation setup requires empty history stores.')
        for name in COLLECTION_POLICIES:
            if name not in names:
                create_history_collection(database, name)
            verify_history_collection(database, name)
        if not has_role:
            database.command('createRole', ROLE, privileges=privileges(), roles=[])
        if not has_user:
            database.command('createUser', APP_USER, pwd=password, roles=[{'role': ROLE, 'db': DATABASE}])
        verify_accounts(database, require_history=True)
        # Existing accounts/passwords/roles and service evidence are never replaced.
        with history_client(password) as history:
            for name in COLLECTION_POLICIES:
                if history[DATABASE][name].count_documents({}) != 0:
                    raise RuntimeError('Unexpected historical evidence count.')
        with client(service_password) as service:
            if service[DATABASE].service_status_events.count_documents({}) != before:
                raise RuntimeError('Service count changed during setup.')
    print('Historical Mongo storage setup: PASSED')
    print('service_status_events: 6596 | transfer_events: 0 | promotion_events: 0')
    print('Dedicated history account has find/insert access only to the two history collections.')
    print('No historical imports or human access grants; no existing evidence changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('History setup stopped: ' + type(error).__name__ + '. Review before importing evidence.') from None
