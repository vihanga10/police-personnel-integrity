"""Additive dataset-intake destinations; existing users, promotion and personnel collections are untouched.

SQL setup runs in one transaction. Mongo setup records each intended command
before sending it, reconciles exact existing objects and never repeats an
uncertain absent-object command automatically.
"""
import hashlib
from pathlib import Path
from app.intake.promotion_pipeline.core import check, canonical
from app.intake.promotion_pipeline.chain_worker import write_private
from .runtime import COLLECTION, MONGO_DATABASE, WRITER
from app.access.store import private

USER=WRITER
ROLE='personnel_intake_append_only'
SQL_SCHEMA='''
CREATE SCHEMA IF NOT EXISTS personnel_intake;
CREATE TABLE IF NOT EXISTS personnel_intake.evidence (
 record_id varchar(64) PRIMARY KEY,
 batch_id uuid NOT NULL,
 ciphertext bytea NOT NULL,
 ciphertext_sha256 varchar(64) NOT NULL,
 CHECK (record_id ~ '^[0-9a-f]{64}$'),
 CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
 CHECK (octet_length(ciphertext)>28)
);
'''
DATABASE=MONGO_DATABASE
VALIDATOR={'$jsonSchema':{'bsonType':'object','required':['_id','batch_id','ciphertext','ciphertext_sha256'],
    'additionalProperties':False,'properties':{'_id':{'bsonType':'string','pattern':'^[0-9a-f]{64}$'},
    'batch_id':{'bsonType':'string','pattern':'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'},
    'ciphertext':{'bsonType':'binData'},'ciphertext_sha256':{'bsonType':'string','pattern':'^[0-9a-f]{64}$'}}}}
OPTIONS={'validator':VALIDATOR,'validationLevel':'strict','validationAction':'error'}
PRIVILEGES=[{'resource':{'db':DATABASE,'collection':COLLECTION},'actions':['find','insert']}]
SQL_TRIGGER='''CREATE FUNCTION personnel_intake.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'uploaded source evidence is append-only'; END; $$;
CREATE TRIGGER personnel_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
ON personnel_intake.evidence FOR EACH STATEMENT EXECUTE FUNCTION personnel_intake.reject_change();'''

def postgres(connection,password,*,existing=False):
    """Caller supplies a private administrator connection, never a password URI."""
    from psycopg import sql
    check(type(password) is str and len(password)>=32,'SQL_PASSWORD_INVALID')
    with connection.transaction():
        with connection.cursor() as c:
            c.execute('SELECT current_database(),current_user')
            database,owner=c.fetchone();check(database=='police_identity','SQL_DATABASE_DIFFERS')
            c.execute("SELECT pg_advisory_xact_lock(8147912)")
            c.execute("SELECT 1 FROM pg_namespace WHERE nspname='personnel_intake'")
            present=c.fetchone() is not None
            c.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(USER,))
            role=c.fetchone() is not None
            if existing:
                check(present and role,'SQL_PROVISIONING_INCOMPLETE')
                # The database revokes CONNECT from PUBLIC; the dedicated writer needs it explicitly.
                c.execute(sql.SQL('GRANT CONNECT ON DATABASE police_identity TO {}').format(sql.Identifier(USER)))
                verify_postgres(c,owner)
                return
            check(not present and not role,'SQL_DESTINATION_ALREADY_EXISTS_RECONCILE_REQUIRED')
            c.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS').format(sql.Identifier(USER),sql.Literal(password)))
            c.execute(SQL_SCHEMA)
            c.execute(SQL_TRIGGER)
            c.execute('REVOKE ALL ON SCHEMA personnel_intake FROM PUBLIC')
            c.execute('REVOKE ALL ON personnel_intake.evidence FROM PUBLIC')
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA personnel_intake TO {}').format(sql.Identifier(USER)))
            c.execute(sql.SQL('GRANT SELECT,INSERT ON personnel_intake.evidence TO {}').format(sql.Identifier(USER)))
            c.execute(sql.SQL('GRANT CONNECT ON DATABASE police_identity TO {}').format(sql.Identifier(USER)))
            verify_postgres(c,owner)

def verify_postgres(c,owner):
    c.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname=%s',(USER,))
    check(c.fetchone()==(False,False,False,False,False,False,True),'SQL_WRITER_ROLE_DIFFERS')
    c.execute("SELECT has_database_privilege(%s,'police_identity','CONNECT')",(USER,))
    check(c.fetchone()[0] is True,'SQL_WRITER_CONNECT_MISSING')
    c.execute('SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=%s)',(USER,))
    check(c.fetchone()[0]==0,'SQL_WRITER_MEMBERSHIP_DIFFERS')
    c.execute("SELECT column_name,data_type,is_nullable,character_maximum_length FROM information_schema.columns WHERE table_schema='personnel_intake' AND table_name='evidence' ORDER BY ordinal_position")
    check(c.fetchall()==[('record_id','character varying','NO',64),('batch_id','uuid','NO',None),('ciphertext','bytea','NO',None),('ciphertext_sha256','character varying','NO',64)],'SQL_DESTINATION_COLUMNS_DIFFER')
    c.execute("SELECT tgname,tgenabled,tgtype FROM pg_trigger WHERE tgrelid='personnel_intake.evidence'::regclass AND NOT tgisinternal")
    check(c.fetchall()==[('personnel_evidence_immutable','O',58)],'SQL_IMMUTABILITY_TRIGGER_DIFFERS')
    c.execute("SELECT prosrc,prosecdef,prorettype::regtype::text,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='personnel_intake.reject_change()'::regprocedure")
    body,security,returns,language=c.fetchone()
    check(body.strip()=="BEGIN RAISE EXCEPTION 'uploaded source evidence is append-only'; END;" and security is False and returns=='trigger' and language=='plpgsql','SQL_IMMUTABILITY_FUNCTION_DIFFERS')
    c.execute("SELECT contype,convalidated,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='personnel_intake.evidence'::regclass")
    import re
    constraints=c.fetchall()
    normalized=lambda text:re.sub(r"[\s()]|::text",'',text)
    expected={('p',True,'PRIMARYKEYrecord_id'),('c',True,"CHECKrecord_id~'^[0-9a-f]{64}$'"),('c',True,"CHECKciphertext_sha256~'^[0-9a-f]{64}$'"),('c',True,'CHECKoctet_lengthciphertext>28')}
    check(len(constraints)==4 and {(kind,valid,normalized(definition)) for kind,valid,definition in constraints}==expected,'SQL_DESTINATION_CONSTRAINTS_DIFFER')
    for permission,expected in [('SELECT',True),('INSERT',True),('UPDATE',False),('DELETE',False),('TRUNCATE',False),('REFERENCES',False),('TRIGGER',False)]:
        c.execute("SELECT has_table_privilege(%s,'personnel_intake.evidence',%s)",(USER,permission))
        check(c.fetchone()[0] is expected,'SQL_WRITER_PRIVILEGES_DIFFER')
    c.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname IN ('identity','staging') AND (has_table_privilege(%s,c.oid,'INSERT') OR has_table_privilege(%s,c.oid,'UPDATE') OR has_table_privilege(%s,c.oid,'DELETE') OR has_table_privilege(%s,c.oid,'TRUNCATE'))",(USER,USER,USER,USER))
    check(c.fetchone()[0]==0,'SQL_WRITER_CAN_CHANGE_ORIGINAL_DATA')
    c.execute("SELECT tableowner FROM pg_tables WHERE schemaname='personnel_intake' AND tablename='evidence'")
    check(c.fetchone()==(owner,),'SQL_DESTINATION_OWNER_DIFFERS')

def verify_collection(database):
    info=list(database.list_collections(filter={'name':COLLECTION}))
    check(len(info)==1 and info[0]['type']=='collection' and info[0]['options']==OPTIONS,'MONGO_DESTINATION_CONTRACT_DIFFERS')
    indexes=list(database[COLLECTION].list_indexes())
    check(len(indexes)==1 and indexes[0]['name']=='_id_' and list(indexes[0]['key'].items())==[('_id',1)] and not any(k in indexes[0] for k in ['expireAfterSeconds','partialFilterExpression','sparse']),'MONGO_DESTINATION_INDEX_DIFFERS')

def role_info(database):
    result=database.command('rolesInfo',{'role':ROLE,'db':DATABASE},showPrivileges=True)
    roles=result['roles']
    check(len(roles)<=1,'MONGO_ROLE_AMBIGUOUS')
    if not roles:return False
    r=roles[0]
    check(r['roles']==[] and r['privileges']==PRIVILEGES,'MONGO_WRITER_ROLE_DIFFERS')
    return True

def user_info(database):
    result=database.command('usersInfo',{'user':USER,'db':DATABASE})
    users=result['users'];check(len(users)<=1,'MONGO_USER_AMBIGUOUS')
    if not users:return False
    check(users[0]['roles']==[{'role':ROLE,'db':DATABASE}],'MONGO_WRITER_USER_DIFFERS')
    return True

def mongo(database,password,journal,*,authenticate):
    check(database.name==DATABASE and type(password) is str and len(password)>=32,'MONGO_SETUP_INPUT_DIFFERS')
    journal=private(journal,directory=True)
    def retained_step(name,present,execute,verify):
        value={'policy':'PERSONNEL_INTAKE_MONGO_SETUP_STEP_V1','step':name,'database':DATABASE,'collection':COLLECTION,'user':USER,'role':ROLE}
        attempt=journal/(name+'-attempt.json');done=journal/(name+'-verified.json')
        if present():
            # Existing objects are trusted only if this setup retained its own
            # attempt, preventing accidental adoption of another user's role.
            check(attempt.exists(),'MONGO_DESTINATION_ALREADY_EXISTS')
            check(private(attempt).read_bytes()==canonical(value),'MONGO_SETUP_JOURNAL_DIFFERS')
            verify();write_private(done,value);return
        check(not attempt.exists() and not done.exists(),'MONGO_SETUP_UNCERTAIN_RECONCILE_REQUIRED')
        write_private(attempt,value)
        execute();verify();write_private(done,value)
    retained_step('collection',lambda:bool(list(database.list_collections(filter={'name':COLLECTION}))),lambda:database.create_collection(COLLECTION,**OPTIONS),lambda:verify_collection(database))
    retained_step('role',lambda:role_info(database),lambda:database.command('createRole',ROLE,privileges=PRIVILEGES,roles=[]),lambda:check(role_info(database),'MONGO_ROLE_MISSING'))
    retained_step('user',lambda:user_info(database),lambda:database.command('createUser',USER,pwd=password,roles=[{'role':ROLE,'db':DATABASE}],mechanisms=['SCRAM-SHA-256']),lambda:check(user_info(database),'MONGO_USER_MISSING'))
    # A matching public user record does not prove that the retained password is
    # its password. Authenticate using only the dedicated writer credentials.
    authenticate(password)
    return {'status':'PERSONNEL_INTAKE_MONGO_DESTINATION_VERIFIED','collection':COLLECTION}
