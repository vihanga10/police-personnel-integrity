"""Add empty remaining stores; preserve reconciled service/history/SRB evidence and accounts."""
import argparse
from pathlib import Path
from app.storage.remaining_mongo_connection import remaining_password, remaining_client
from app.storage.remaining_mongo_contract import APP_USER, COLLECTION_POLICIES, DATABASE, ROLE, privileges, validator
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import APP_USER as SERVICE_USER, ROLE as SERVICE_ROLE, privileges as service_privileges
from app.storage.history_mongo_connection import history_password, history_client
from app.storage.history_mongo_contract import APP_USER as HISTORY_USER, ROLE as HISTORY_ROLE, privileges as history_privileges
from app.storage.setup_history_mongo import verify_history_collection
from app.storage.setup_mongo import verify_collection as verify_service_collection, verify_role
from app.storage.srb_mongo_connection import srb_password, srb_client
from app.storage.srb_mongo_contract import APP_USER as SRB_USER, ROLE as SRB_ROLE, privileges as srb_privileges
from app.storage.setup_srb_mongo import verify_srb_collection
from app.storage.activity_mongo_contract import APP_USER as ACTIVITY_USER, ROLE as ACTIVITY_ROLE, privileges as activity_privileges
from app.storage.activity_mongo_connection import activity_password, activity_client
from app.storage.setup_activity_mongo import verify_activity_collection

# These are the reconciled research collections, not disposable test databases.
EXISTING_COUNTS = {'service_status_events': 6596, 'transfer_events': 33316, 'promotion_events': 13974,
                   'police_number_intervals': 15123, 'restriction_records': 10971, 'restriction_overrides': 150, 'duty_periods': 3138, 'firearms_assessments': 30348,
                   'good_conduct_records': 2779, 'bad_conduct_records': 370}


def verify_remaining_collection(database, name):
    info = list(database.list_collections(filter={'name': name}))
    expected_options = {'validator': validator(name), 'validationLevel': 'strict', 'validationAction': 'error'}
    if len(info) != 1 or info[0]['type'] != 'collection' or info[0]['options'] != expected_options:
        raise RuntimeError('Remaining collection contract differs; no modification permitted.')
    expected = {'_id_': ([('_id', 1)], False),
                'uq_source_policy': ([('raw_record_id', 1), ('writer_policy', 1)], True),
                'officer_evidence': ([('officer_uid', 1), ('recorded_at', 1)], False)}
    indexes = list(database[name].list_indexes())
    if len(indexes) != len(expected):
        raise RuntimeError('Remaining index count differs.')
    for index in indexes:
        if index['name'] not in expected or (list(index['key'].items()), index.get('unique', False)) != expected[index['name']]:
            raise RuntimeError('Remaining index definition differs.')
        if any(k in index for k in ('expireAfterSeconds', 'partialFilterExpression', 'sparse', 'hidden', 'collation')):
            raise RuntimeError('Remaining index behavior differs.')


def create_remaining_collection(database, name):
    database.create_collection(name, validator=validator(name), validationLevel='strict', validationAction='error')
    database[name].create_index([('raw_record_id', 1), ('writer_policy', 1)], unique=True, name='uq_source_policy')
    database[name].create_index([('officer_uid', 1), ('recorded_at', 1)], name='officer_evidence')


def verify_accounts(database, *, require_remaining):
    """Require exact existing technical roles; never widen service/history permissions."""
    roles = database.command('rolesInfo', 1)['roles']
    users = database.command('usersInfo', 1)['users']
    if any(r['role'] not in {SERVICE_ROLE, HISTORY_ROLE, SRB_ROLE, ACTIVITY_ROLE, ROLE} for r in roles) or any(u['user'] not in {SERVICE_USER, HISTORY_USER, SRB_USER, ACTIVITY_USER, APP_USER} for u in users):
        raise RuntimeError('Unexpected research accounts or roles.')
    verify_role(database, SERVICE_ROLE, service_privileges())
    verify_role(database, HISTORY_ROLE, history_privileges())
    verify_role(database, SRB_ROLE, srb_privileges())
    verify_role(database, ACTIVITY_ROLE, activity_privileges())
    for user, role in ((SERVICE_USER, SERVICE_ROLE), (HISTORY_USER, HISTORY_ROLE), (SRB_USER, SRB_ROLE), (ACTIVITY_USER, ACTIVITY_ROLE), (APP_USER, ROLE)):
        selected = [u for u in users if u['user'] == user]
        if user != APP_USER or require_remaining:
            if len(selected) != 1:
                raise RuntimeError('Required application account is missing.')
        if selected and selected[0]['roles'] != [{'role': role, 'db': DATABASE}]:
            raise RuntimeError('Unexpected account role assignment.')
    remaining_roles = [r for r in roles if r['role'] == ROLE]
    if remaining_roles:
        verify_role(database, ROLE, privileges())
    elif require_remaining:
        raise RuntimeError('Remaining writer role is missing.')
    return bool(remaining_roles), any(u['user'] == APP_USER for u in users)


def verify_existing(database):
    """Read-only contract and count checks for all previously imported evidence."""
    verify_service_collection(database)
    for name in ('transfer_events', 'promotion_events'):
        verify_history_collection(database, name)
    for name in ('police_number_intervals', 'restriction_records', 'restriction_overrides'):
        verify_srb_collection(database, name)
    for name in ('duty_periods', 'firearms_assessments', 'good_conduct_records', 'bad_conduct_records'):
        verify_activity_collection(database, name)
    if any(database[name].count_documents({}) != expected for name, expected in EXISTING_COUNTS.items()):
        raise RuntimeError('Existing counts differ from the reconciled checkpoints.')


def separate_directories(*directories):
    paths = [Path(d).expanduser().resolve() for d in directories]
    if len(set(paths)) != len(paths):
        raise ValueError('Use separate bootstrap, history, SRB, activity and remaining credential directories.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-credential-directory', required=True)
    parser.add_argument('--history-credential-directory', required=True)
    parser.add_argument('--srb-credential-directory', required=True)
    parser.add_argument('--remaining-credential-directory', required=True)
    parser.add_argument('--activity-credential-directory', required=True)
    args = parser.parse_args()
    separate_directories(args.bootstrap_credential_directory, args.history_credential_directory, args.srb_credential_directory, args.activity_credential_directory, args.remaining_credential_directory)
    root, service_password = load_credentials(args.bootstrap_credential_directory)
    history_secret = history_password(args.history_credential_directory)
    srb_secret = srb_password(args.srb_credential_directory)
    activity_secret = activity_password(args.activity_credential_directory)
    password = remaining_password(args.remaining_credential_directory, create=True)
    with client(root, bootstrap=True) as bootstrap:
        if not bootstrap.server_info()['version'].startswith('8.0.'):
            raise RuntimeError('Unexpected Mongo server version.')
        database = bootstrap[DATABASE]
        verify_existing(database)
        has_role, has_user = verify_accounts(database, require_remaining=False)
        names = set(database.list_collection_names())
        if not set(EXISTING_COUNTS) <= names or not names <= {*EXISTING_COUNTS, *COLLECTION_POLICIES}:
            raise RuntimeError('Unexpected research collections.')
        # Authenticate existing application credentials before creating new resources.
        with client(service_password) as service:
            if service[DATABASE].service_status_events.count_documents({}) != 6596:
                raise RuntimeError('Service account count differs.')
        with history_client(history_secret) as history:
            for name in ('transfer_events', 'promotion_events'):
                if history[DATABASE][name].count_documents({}) != EXISTING_COUNTS[name]:
                    raise RuntimeError('History account count differs.')
        with srb_client(srb_secret) as srb:
            for name in ('police_number_intervals', 'restriction_records', 'restriction_overrides'):
                if srb[DATABASE][name].count_documents({}) != EXISTING_COUNTS[name]:
                    raise RuntimeError('SRB account count differs.')
        with activity_client(activity_secret) as activity:
            for name in ('duty_periods', 'firearms_assessments', 'good_conduct_records', 'bad_conduct_records'):
                if activity[DATABASE][name].count_documents({}) != EXISTING_COUNTS[name]:
                    raise RuntimeError('Activity account count differs.')
        for name in COLLECTION_POLICIES:
            if name in names:
                verify_remaining_collection(database, name)
                if database[name].count_documents({}) != 0:
                    raise RuntimeError('Remaining foundation requires empty remaining stores.')
        for name in COLLECTION_POLICIES:
            if name not in names:
                create_remaining_collection(database, name)
            verify_remaining_collection(database, name)
        if not has_role:
            database.command('createRole', ROLE, privileges=privileges(), roles=[])
        if not has_user:
            database.command('createUser', APP_USER, pwd=password, roles=[{'role': ROLE, 'db': DATABASE}])
        verify_accounts(database, require_remaining=True)
        with remaining_client(password) as srb:
            for name in COLLECTION_POLICIES:
                if srb[DATABASE][name].count_documents({}) != 0:
                    raise RuntimeError('Unexpected remaining evidence count.')
        verify_existing(database)
    print('Remaining Mongo storage setup: PASSED')
    print('education_records: 0 | operation_records: 0 | court_records: 0 | complaint_records: 0 | demotion_events: 0')
    print('Existing service/history/SRB/activity counts and contracts unchanged.')
    print('Dedicated remaining account has find/insert access only to the five remaining collections.')
    print('No officer import or human access grants; no existing evidence changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Remaining setup stopped: ' + type(error).__name__ + '. Review before importing evidence.') from None
