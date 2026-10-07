"""Read-only final Stage 2 storage review of the received nineteen-file batch.

Run exact source/receipt coverage, all eight encrypted reconciliations and final
count gates. No import/write option exists. Private journals contain summaries,
never source cells, payloads or key material. This is not a human access grant.
"""
import argparse
from datetime import datetime,timezone
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4
from sqlalchemy import select,text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_service_plans import BATCH,ARCHIVE,CONFIRMATION
from app.identity.source_coverage import ROWS
from app.identity.inspect_stage2_coverage import ROWS as ALL_ROWS
from app.intake.registration_receipt import save_receipt
from app.storage.mongo_connection import load_credentials
from app.storage.reference_mongo_connection import reference_password,reference_client
from app.storage.setup_reference_mongo import existing_readers,EXISTING_COUNTS
from app.storage.reference_mongo_contract import DATABASE
from app.storage.history_mongo_connection import history_password
from app.storage.srb_mongo_connection import srb_password
from app.storage.activity_mongo_connection import activity_password
from app.storage.remaining_mongo_connection import remaining_password
from scripts.check_reference_storage import CHECKPOINT

POLICY='STAGE2_FINAL_STORAGE_REVIEW_V1'
SQL_COUNTS=dict(CHECKPOINT,**{
    'identity.reference_source_assertion':1214,'staging.reference_delivery_preparation':1214,'staging.reference_delivery_completion':1214,
    'identity.officer_name_version':6596,'identity.officer_address_version':6596,'identity.officer_demographic_version':6596,
    'identity.officer_physical_profile_version':6596,'identity.officer_previous_employment_version':1187,
    'identity.officer_restricted_profile_version':6596,'identity.officer_contact_version':13192})
MONGO_COUNTS=dict(EXISTING_COUNTS,station_reference_records=607,station_sinhala_reference_records=607)
# Fixed commands: users cannot substitute a module or enable a database write.
PIPELINES=(
    ('PROFILE','import_profiles',None,('--expected-rows','6596','--phone-region','LK')),
    ('SERVICE','import_services','service',('--expected-rows','6596')),
    ('HISTORY','import_histories','history',('--expected-transfer-rows','33316','--expected-promotion-rows','13974')),
    ('SRB','import_srbs','srb',('--expected-number-rows','15123','--expected-restriction-rows','10971','--expected-override-rows','150')),
    ('ACTIVITY','import_activities','activity',('--expected-duty-rows','3138','--expected-firearms-rows','30348','--expected-good-conduct-rows','2779','--expected-bad-conduct-rows','370')),
    ('REMAINING','import_remaining','remaining',('--expected-education-rows','6596','--expected-operation-rows','19554','--expected-court-rows','9538','--expected-complaint-rows','998','--expected-demotion-rows','8')),
    ('FAMILY','import_families',None,('--expected-rows','6596')),
    ('REFERENCE','import_references','reference',('--expected-master-rows','607','--expected-sinhala-rows','607')),
)
# Eight pipelines cover all nineteen received files.


def require(condition,message):
    if not condition:raise ValueError(message)


def arguments():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('key-file','backup-key-file','credential-root','attempt-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    return parser.parse_args()


def credential_directories(root):
    return {name:root/('mongo-v1' if name=='service' else 'mongo-'+name+'-v1')
        for name in ('service','history','srb','activity','remaining','reference')}


def commands(args,repository,journal):
    """Build argument arrays only; no shell interpretation or inherited write flag."""
    keys=['--key-file',str(args.key_file),'--backup-key-file',str(args.backup_key_file)]
    result=[('COVERAGE',[sys.executable,'-u','-m','app.identity.inspect_stage2_coverage',*keys])]
    directories=credential_directories(args.credential_root)
    common=['--batch-id',BATCH,'--expected-archive-sha256',ARCHIVE,'--confirmation',str(repository/'docs/intake-source-confirmation.json'),
        '--expected-confirmation-sha256',CONFIRMATION,*keys,'--reconcile']
    for name,module,credential,counts in PIPELINES:
        command=[sys.executable,'-u','-m','app.identity.'+module,*common,*counts,'--attempt-root',str(journal/name.lower())]
        if credential:
            flag='mongo' if credential=='service' else credential
            command+=['--'+flag+'-credential-directory',str(directories[credential])]
        result.append((name,command))
    return result


def check_counts(credential_root):
    """Count-only read access after all encrypted row reconciliations succeed."""
    settings=Settings()
    require((settings.host,settings.port,settings.name,settings.user)==('127.0.0.1',5432,'police_identity','police_identity_app'),'Unexpected SQL application target.')
    engine=create_identity_engine(settings)
    try:
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user, current_database()')).one())==('police_identity_app','police_identity'),'Unexpected connected SQL target.')
                for table,count in SQL_COUNTS.items():
                    actual=connection.execute(text('SELECT count(*) FROM '+table)).scalar_one()
                    require(actual==count,'Final SQL count differs: '+table)
                    print(table+': '+str(actual)+' | expected='+str(count),flush=True)
                for table in ('identity.remaining_source_assertion','identity.reference_source_assertion'):
                    require(connection.execute(text('SELECT count(*) FROM '+table+" WHERE classification <> 'UNASSESSED'")).scalar_one()==0,'Unexpected classification determination.')
                for filename in ('station_master.csv','sri_lanka_police_stations_sinhala.csv'):
                    require(connection.execute(text("SELECT count(*) FROM staging.reference_delivery_preparation WHERE source_file_name=:name AND review_state='STRUCTURAL_REVIEW_REQUIRED'"),{'name':filename}).scalar_one()==2,'Reference review evidence changed.')
    finally:engine.dispose()
    directories=credential_directories(credential_root)
    # Load private credentials without using the bootstrap account for a connection.
    _,service=load_credentials(directories['service'])
    passwords=[service,history_password(directories['history']),srb_password(directories['srb']),activity_password(directories['activity']),remaining_password(directories['remaining'])]
    readers=(*existing_readers(passwords),(reference_client,reference_password(directories['reference']),('station_reference_records','station_sinhala_reference_records')))
    checked=set()
    for factory,password,names in readers:
        with factory(password) as reader:
            for name in names:
                actual=reader[DATABASE][name].count_documents({})
                require(actual==MONGO_COUNTS[name],'Final Mongo count differs: '+name)
                print(DATABASE+'.'+name+': '+str(actual)+' | expected='+str(MONGO_COUNTS[name]),flush=True)
                checked.add(name)
    require(checked==set(MONGO_COUNTS),'Mongo collection coverage differs.')
    return dict(sql_tables=len(SQL_COUNTS),mongo_collections=len(checked))


def main():
    args=arguments();journal=None;completed=[];sequence=0
    try:
        repository=Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git','-C',str(repository),'status','--porcelain'],text=True).strip(),'Commit reviewed source before running the review.')
        revision=subprocess.check_output(['git','-C',str(repository),'rev-parse','HEAD'],text=True).strip()
        require(re.fullmatch('[0-9a-f]{40}',revision) is not None,'Unexpected code revision.')
        require(args.key_file.resolve()!=args.backup_key_file.resolve(),'Separate key copies required.')
        for path in (args.credential_root,args.attempt_root):
            require(not any(p.is_symlink() for p in (path.absolute(),*path.absolute().parents)),'Private paths must not traverse symlinks.')
        root=args.attempt_root.expanduser().absolute()
        require(not root.resolve().is_relative_to(repository),'Keep review evidence outside Git.')
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        require(not root.stat().st_mode&0o077,'Review attempt root must be owner-only.')
        journal=root/str(uuid4());journal.mkdir(mode=0o700)
        def event(kind,**extra):
            nonlocal sequence
            sequence+=1
            save_receipt(dict(policy=POLICY,event=kind,sequence=sequence,code_revision=revision,batch_id=BATCH,
                archive_sha256=ARCHIVE,confirmation_sha256=CONFIRMATION,recorded_at=datetime.now(timezone.utc).isoformat(),**extra),journal/f'{sequence:08d}.json')
        event('STARTED');print('Stage 2 review attempt directory:',journal,flush=True)
        for name,command in commands(args,repository,journal):
            event('CHECK_STARTED',check=name)
            print('Stage 2 review check:',name,flush=True)
            # Child progress remains visible. Only fixed read-only CLIs are run.
            result=subprocess.run(command,cwd=repository/'backend',check=False)
            require(result.returncode==0,'Read-only review failed: '+name)
            completed.append(name);event('CHECK_PASSED',check=name)
        counts=check_counts(args.credential_root)
        event('PASSED',completed_checks=completed,received_files=len(ALL_ROWS),received_rows=sum(ALL_ROWS.values()),**counts)
        print('Stage 2 received-batch storage review: PASSED',flush=True)
        print('Received files:',len(ALL_ROWS),'| personnel rows:',sum(ROWS.values()),'| reference rows: 1214 | total rows:',sum(ALL_ROWS.values()))
        print('Exact SQL row coverage, encrypted destination reconciliation and final SQL/Mongo counts passed.')
        print('Unresolved claims remain preserved; classification and candidate mappings remain unassessed.')
        print('No database writes or plaintext exports. Human access, data-use authorization and Stage 3 research verification remain separate.')
        return 0
    except (Exception,KeyboardInterrupt) as error:
        if journal is not None:
            try:save_receipt(dict(policy=POLICY,event='STOPPED',error_type=type(error).__name__,completed_checks=completed),journal/'STOPPED.json')
            except Exception:print('Review stop journal could not be saved.')
        print('Stage 2 review stopped:',type(error).__name__)
        if type(error) is ValueError:print(str(error))
        print('Stage 2 is not marked complete. No write/import mode was requested.')
        return 1


if __name__=='__main__':raise SystemExit(main())
