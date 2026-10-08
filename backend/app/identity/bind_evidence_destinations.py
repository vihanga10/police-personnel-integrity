"""Bind a passed v2 bundle attempt to exact live destination versions; read-only."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
from sqlalchemy import select,text
from bson import BSON
from database import create_identity_engine
from settings import Settings
from app.db.base import Base
from app.db.staging_base import StagingBase
import app.models
from app.staging.models import IntakeBatch,IntakeFile,RawRecord
from app.identity.register_profiles import private_key_file,verify_recovery
from app.identity.evidence_bundle_v2 import open_artifact,seal_artifact,BundleInventory
from app.identity.inspect_stage2_coverage import ROWS,SOURCES
from app.identity.inspect_service_plans import BATCH,ARCHIVE,CONFIRMATION
from app.identity.review_stage2 import SQL_COUNTS, MONGO_COUNTS, check_counts, credential_directories
from app.identity.destination_binding import POLICY,DestinationInventory,row_binding,require
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.intake.registration_receipt import save_receipt
from app.storage.mongo_connection import load_credentials
from app.storage.history_mongo_connection import history_password
from app.storage.srb_mongo_connection import srb_password
from app.storage.activity_mongo_connection import activity_password
from app.storage.remaining_mongo_connection import remaining_password
from app.storage.reference_mongo_connection import reference_password,reference_client
from app.storage.setup_reference_mongo import existing_readers
from app.storage.reference_mongo_contract import DATABASE


def private_path(path, directory=False):
    path=path.expanduser().absolute()
    require(not any(p.is_symlink() for p in (path,*path.parents)),'Private path traverses symlink.')
    require(path.is_dir() if directory else path.is_file(),'Private artifact path missing.')
    require(not path.stat().st_mode & 0o077,'Private artifact permissions differ.')
    return path


def load_attempt(directory,crypto,backup):
    directory=private_path(directory,True)
    summary=json.loads(private_path(directory/'PASSED.json').read_text())
    require(summary.get('status')=='PASSED' and summary.get('policy')=='OFFICER_EVIDENCE_BUNDLE_FOUNDATION_V2' and
        summary.get('officers')==6596 and summary.get('received_rows')==167865 and summary.get('artifact_count')==20,'Passed v2 foundation required.')
    def read(name):
        envelope=json.loads(private_path(directory/name).read_text())
        binding=envelope['binding']
        payload=open_artifact(crypto,envelope,binding)
        require(open_artifact(backup,envelope,binding)==payload,'Artifact backup recovery differs.')
        return binding,payload
    binding,manifest=read('officer-manifests.encrypted.json')
    snap=manifest['snapshot']
    require(binding==dict(snapshot=snap,artifact='OFFICER_MANIFESTS'),'Manifest envelope context differs.')
    require((snap['batch_id'],snap['archive_sha256'],snap['confirmation_sha256'])==(BATCH,ARCHIVE,CONFIRMATION),'Bundle snapshot differs.')
    officers=[x['officer_uid'] for x in manifest['bundles']]
    require(len(officers)==len(set(officers))==6596,'Bundle officer universe differs.')
    inventory=BundleInventory(officers,ROWS);catalog={}
    for index,filename in enumerate(sorted(ROWS)):
        binding,payload=read('catalog-%02d.encrypted.json'%index)
        require(binding==dict(snapshot=snap,artifact='SOURCE_CATALOG',filename=filename) and payload['filename']==filename,'Catalog context differs.')
        require(len(payload['rows'])==ROWS[filename],'Catalog row count differs.')
        for row in payload['rows']:
            raw=row['raw_record_id'];require(raw not in catalog,'Repeated catalog source row.')
            require(row['classification']=='UNASSESSED','Catalog classification differs.')
            links=row['candidate_links']
            require(all(x['state']=='CANDIDATE_NOT_ACCEPTED' for x in links),'Candidate state differs.')
            inventory.add(filename,raw,row['original'],row['provenance'],[(x['officer_uid'],x['role']) for x in links])
            inventory.bind_receipt(raw,row['delivery'],row['assertion']);catalog[raw]=dict(row,filename=filename)
    expected=inventory.finish(snap);expected['court_membership_policy']='COURT_PARTICIPANT_MEMBERSHIP_V1'
    require(expected==manifest,'Catalog and officer manifest membership differ.')
    return manifest,catalog


def collect_sql(connection,catalog,manifest,crypto,backup):
    registry=dict(Base.metadata.tables);registry.update(StagingBase.metadata.tables)
    expected=dict(SQL_COUNTS)
    expected.update({'staging.intake_batch':1,'staging.intake_file':len(ROWS),'staging.raw_record':sum(ROWS.values())})
    require(set(expected)<=set(registry),'Destination model registry incomplete.')
    tables=sorted(expected,key=lambda n:(0 if n in ('identity.source_assertion','identity.remaining_source_assertion','identity.reference_source_assertion') else 1 if n.endswith('_preparation') else 2,n))
    officers={b['officer_uid'] for b in manifest['bundles']};inventory=DestinationInventory(catalog,officers)
    counts={};assertions={};preparations={};completions={}
    for name in tables:
        table=registry[name];count=0
        for row in connection.execute(select(table).execution_options(yield_per=500)).mappings():
            count+=1;data=dict(row);raw=data.get('raw_record_id');officer=str(data['officer_uid']) if data.get('officer_uid') is not None else None
            if name in ('identity.source_assertion','identity.remaining_source_assertion','identity.reference_source_assertion'):
                require(raw in catalog,'Assertion outside source catalogs.')
                assertions[str(data['source_assertion_id'])]=raw
            if raw is None and data.get('source_assertion_id') is not None:
                raw=assertions.get(str(data['source_assertion_id']))
                require(raw is not None,'Destination assertion source missing.')
            if name.endswith('_preparation'):
                delivery=str(data['delivery_id']);require(delivery not in preparations,'Repeated delivery identity.')
                require(data['source_assertion_id']==__import__('uuid').UUID(catalog[raw]['delivery']['assertion_id']),'Prepared assertion differs from bundle.')
                digest=hashlib.sha256(bytes(data['document_bson'])).hexdigest()
                require(digest==data['document_sha256'],'SQL prepared BSON digest differs.')
                document=BSON(bytes(data['document_bson'])).decode()
                collection=data.get('mongo_collection','service_status_events')
                require(collection in MONGO_COUNTS and document['_id']==delivery,'Prepared Mongo route differs.')
                inventory.expect_mongo(collection,delivery,raw,digest)
                preparations[delivery]=(raw,digest)
            if name.endswith('_completion'):
                delivery=str(data['delivery_id']);require(delivery in preparations,'Completion preparation missing.')
                raw,digest=preparations[delivery]
                require(data['document_sha256']==digest,'Completion digest differs.')
                completions[delivery]=digest
            if name=='staging.raw_record':
                require(raw in catalog,'Staging row outside catalogs.')
                original=open_row(crypto,stored_row(data))
                require(original==open_row(backup,stored_row(data)) and
                    dict(columns=original['columns'],values=original['values'])==catalog[raw]['original'],'Live source differs from encrypted bundle.')
                prov=catalog[raw]['provenance']
                require(data['source_file_sha256']==prov['source_file_sha256'] and data['source_row_number']==prov['source_row_number'] and str(data['import_file_id'])==prov['import_file_id'],'Live source provenance differs.')
            inventory.add_sql(row_binding(name,[c.name for c in table.primary_key.columns],data),raw,officer)
        require(count==expected[name],'Destination SQL count differs: '+name);counts[name]=count
        print('SQL binding progress:',name,'| rows=',count,flush=True)
    require(set(preparations)==set(completions),'Prepared delivery lacks completion.')
    return inventory,counts


def collect_mongo(inventory,root):
    dirs=credential_directories(root);_,service=load_credentials(dirs['service'])
    passwords=[service,history_password(dirs['history']),srb_password(dirs['srb']),activity_password(dirs['activity']),remaining_password(dirs['remaining'])]
    readers=(*existing_readers(passwords),(reference_client,reference_password(dirs['reference']),('station_reference_records','station_sinhala_reference_records')))
    checked=set()
    for factory,password,names in readers:
        with factory(password) as reader:
            for name in names:
                count=0
                for document in reader[DATABASE][name].find({}):
                    inventory.add_mongo(name,document,lambda d:bytes(BSON.encode(d)));count+=1
                require(count==MONGO_COUNTS[name],'Mongo destination count differs: '+name);checked.add(name)
                print('Mongo binding progress:',name,'| documents=',count,flush=True)
    require(checked==set(MONGO_COUNTS),'Mongo destination coverage differs.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('key-file','backup-key-file','credential-root','bundle-attempt','output-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();engine=None;attempt=None
    try:
        repo=Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(),'Commit binding source before execution.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        require(args.key_file.resolve()!=args.backup_key_file.resolve(),'Separate key copies required.')
        crypto,backup=private_key_file(args.key_file),private_key_file(args.backup_key_file);verify_recovery(crypto,backup)
        manifest,catalog=load_attempt(args.bundle_attempt,crypto,backup)
        output=args.output_root.expanduser().absolute()
        require(not any(x.is_symlink() for x in (output,*output.parents)) and not output.resolve().is_relative_to(repo),'Unsafe binding output root.')
        output.mkdir(mode=0o700,parents=True,exist_ok=True);private_path(output,True)
        attempt=output/str(uuid4());attempt.mkdir(mode=0o700)
        save_receipt(dict(policy=POLICY,status='STARTED'),attempt/'STARTED.json')
        print('Destination binding attempt directory:',attempt,flush=True)
        result=subprocess.run([sys.executable,'-u','-m','app.identity.review_stage2','--key-file',str(args.key_file),
            '--backup-key-file',str(args.backup_key_file),'--credential-root',str(args.credential_root),
            '--attempt-root',str(attempt/'reconciliation')],cwd=repo/'backend')
        require(result.returncode==0,'Fresh destination reconciliation failed.')
        settings=Settings();require((settings.host,settings.port,settings.name,settings.user)==('127.0.0.1',5432,'police_identity','police_identity_app'),'Unexpected SQL target.')
        engine=create_identity_engine(settings)
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user,current_database()')).one())==('police_identity_app','police_identity'),'Connected SQL target differs.')
                inventory,counts=collect_sql(connection,catalog,manifest,crypto,backup)
                collect_mongo(inventory,args.credential_root)
                bindings=inventory.finish()
        check_counts(args.credential_root)
        bindings.update(source_snapshot=manifest['snapshot'],source_bundle_policy=manifest['policy'],
            source_attempt_id=args.bundle_attempt.name,collector_revision=revision,collected_at=datetime.now(timezone.utc).isoformat(),sql_table_counts=counts)
        binding=dict(artifact='DESTINATION_BINDINGS',destination_policy=POLICY,source_snapshot=manifest['snapshot'],collector_revision=revision)
        envelope=seal_artifact(crypto,backup,bindings,binding)
        save_receipt(envelope,attempt/'destination-bindings.encrypted.json')
        summary=dict(policy=POLICY,status='PASSED',source_rows=len(catalog),officers=len(manifest['bundles']),
            sql_tables=len(counts),sql_records=bindings['sql_records'],mongo_collections=len(MONGO_COUNTS),mongo_documents=bindings['mongo_documents'],code_revision=revision)
        save_receipt(summary,attempt/'PASSED.json')
        print('Read-only destination-version binding: PASSED');print(json.dumps(summary,sort_keys=True))
        print('Exact SQL full-row fingerprints and SQL/Mongo BSON matches preserved in encrypted artifact; both keys recovered it.')
        print('No database writes, officer commitments, blockchain writes, audit results or permission changes.')
        return 0
    except Exception as error:
        if attempt is not None:save_receipt(dict(policy=POLICY,status='STOPPED',error_type=type(error).__name__),attempt/'STOPPED.json')
        print('Destination binding stopped:',type(error).__name__)
        if type(error) is ValueError:print(str(error))
        return 1
    finally:
        if engine is not None:engine.dispose()


if __name__=='__main__':raise SystemExit(main())
