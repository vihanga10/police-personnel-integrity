"""Bootstrap only the dedicated, empty research collection; never replace evidence."""
import argparse
from app.storage.mongo_connection import client, load_credentials
from app.storage.mongo_contract import APP_USER, COLLECTION, DATABASE, ROLE, privileges, validator


def verify_role(database, name, expected):
    result = database.command("rolesInfo", name, showPrivileges=True)["roles"]
    if len(result) != 1 or result[0]["roles"] or result[0]["privileges"] != expected:
        raise RuntimeError("Unexpected role definition; no permissions were changed.")


def verify_collection(database):
    info = list(database.list_collections(filter={"name": COLLECTION}))
    if len(info) != 1 or info[0]["type"] != "collection":
        raise RuntimeError("Unexpected collection.")
    options = info[0]["options"]
    if options != {"validator": validator(), "validationLevel": "strict", "validationAction": "error"}:
        raise RuntimeError("Existing collection options differ; refusing modification.")
    indexes = list(database[COLLECTION].list_indexes())
    expected = {"_id_": ([("_id", 1)], False),
                "uq_source_policy": ([("raw_record_id", 1), ("writer_policy", 1)], True),
                "officer_evidence": ([("officer_uid", 1), ("recorded_at", 1)], False)}
    if len(indexes) != len(expected):
        raise RuntimeError("Unexpected index count.")
    for index in indexes:
        if index["name"] not in expected or (list(index["key"].items()), index.get("unique", False)) != expected[index["name"]]:
            raise RuntimeError("Unexpected index definition.")
        if any(k in index for k in ("expireAfterSeconds", "partialFilterExpression", "sparse", "hidden", "collation")):
            raise RuntimeError("Unexpected index behavior.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential-directory", required=True)
    args = parser.parse_args()
    root, app = load_credentials(args.credential_directory)
    with client(root, bootstrap=True) as bootstrap:
        bootstrap.admin.command("ping")
        if bootstrap.server_info()["version"] != "8.0.32":
            raise RuntimeError("Unexpected server version.")
        database = bootstrap[DATABASE]
        names = database.list_collection_names()
        if names and names != [COLLECTION]:
            raise RuntimeError("Unexpected research collections; stop for review.")
        if names and database[COLLECTION].count_documents({}):
            raise RuntimeError("Foundation setup requires an empty collection; evidence was not changed.")
        roles = database.command("rolesInfo", 1)["roles"]
        users = database.command("usersInfo", 1)["users"]
        if any(r["role"] != ROLE for r in roles) or any(u["user"] != APP_USER for u in users):
            raise RuntimeError("Unexpected database accounts or roles.")
        # Check existing permissions before any new schema/account creation.
        if roles:
            verify_role(database, ROLE, privileges())
        if users and users[0]["roles"] != [{"role": ROLE, "db": DATABASE}]:
            raise RuntimeError("Unexpected application role assignment.")
        if not names:
            database.create_collection(COLLECTION, validator=validator(), validationLevel="strict", validationAction="error")
            database[COLLECTION].create_index([("raw_record_id", 1), ("writer_policy", 1)], unique=True, name="uq_source_policy")
            database[COLLECTION].create_index([("officer_uid", 1), ("recorded_at", 1)], name="officer_evidence")
        verify_collection(database)
        if not roles:
            database.command("createRole", ROLE, privileges=privileges(), roles=[])
        if not users:
            database.command("createUser", APP_USER, pwd=app, roles=[{"role": ROLE, "db": DATABASE}])
        verify_role(database, ROLE, privileges())
    # A successful privileged setup is insufficient: independently authenticate the app.
    with client(app) as application:
        if application[DATABASE][COLLECTION].count_documents({}) != 0:
            raise RuntimeError("Unexpected evidence count.")
    print("Mongo foundation setup: PASSED")
    print("Database: police_operations | collection: service_status_events | documents: 0")
    print("No officer records imported. Human RBAC/ABAC and service writer remain pending.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Driver exceptions can contain command documents; keep secrets out of output.
        reason = str(error) if type(error) is RuntimeError else type(error).__name__
        raise SystemExit("Mongo setup stopped: " + reason + " No existing evidence was replaced.") from None
