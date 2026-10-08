"""Read-only court participant grammar review with aggregate output only."""
import argparse
import json
from pathlib import Path, PurePosixPath
from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_service_plans import BATCH, ARCHIVE, CONFIRMATION
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.inspect_stage2_coverage import require, routing_contract
from app.identity.court_participant_structure import CourtStructureReport
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file',type=Path,required=True)
    parser.add_argument('--backup-key-file',type=Path,required=True)
    args=parser.parse_args();engine=None
    try:
        require(args.key_file.resolve()!=args.backup_key_file.resolve(), 'Separate recovery keys required.')
        crypto, backup=private_key_file(args.key_file),private_key_file(args.backup_key_file)
        verify_recovery(crypto,backup)
        repository=Path(__file__).resolve().parents[3]
        routing=routing_contract(json.loads((repository/'docs/field-routing.json').read_text()))
        settings=Settings()
        require((settings.host,settings.port,settings.name,settings.user)==('127.0.0.1',5432,'police_identity','police_identity_app'), 'Unexpected SQL application target.')
        engine=create_identity_engine(settings);report=CourtStructureReport()
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user, current_database()')).one())==('police_identity_app','police_identity'), 'Connected target differs.')
                batch=connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id==BATCH)).mappings().one()
                files=connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id==BATCH)).mappings().all()
                names=[PurePosixPath(f['archive_path']).name for f in files]
                require(batch['archive_sha256']==ARCHIVE and len(names)==19 and len(set(names))==19 and set(names)==set(routing), 'Registered batch differs.')
                confirmation=load_source_confirmation(repository/'docs/intake-source-confirmation.json',expected_batch_id=BATCH,
                    expected_archive_sha256=ARCHIVE,expected_filenames=set(names),allowed_source_codes={'PF_REGISTRY','POLICE_HR_IS','SRB'})
                require(confirmation.confirmation_sha256==CONFIRMATION and confirmation.source_for('court_details.csv')=='PF_REGISTRY', 'Source confirmation differs.')
                file=next(f for f in files if PurePosixPath(f['archive_path']).name=='court_details.csv')
                require(file['expected_row_count']==9538 and set(file['columns'])==routing['court_details.csv'] and len(file['columns'])==len(set(file['columns'])), 'Court file contract differs.')
                rows=connection.execute(select(RawRecord.__table__).where(RawRecord.import_file_id==file['import_file_id'])
                    .order_by(RawRecord.source_row_number).execution_options(yield_per=500)).mappings()
                for count,raw in enumerate(rows,1):
                    require(raw['source_row_number']==count and all(raw[k]==file[k] for k in ('batch_id','archive_path','source_file_sha256','import_file_id')), 'Court row provenance differs.')
                    original=open_row(crypto,stored_row(raw))
                    require(original==open_row(backup,stored_row(raw)) and original['columns']==file['columns'], 'Court row recovery differs.')
                    values=dict(zip(original['columns'],original['values'],strict=True))
                    report.add(values['participate_officers_details'])
                require(report.rows==9538, 'Court row count differs.')
        print('Read-only court participant structure review: PASSED')
        print(json.dumps(report.report(),sort_keys=True))
        print('Grammar observations only; no participant identity, historical role or linkage accepted.')
        print('Original court evidence and existing encrypted bundle attempts remain unchanged.')
        print('No database writes, Mongo connection, saved plaintext, personnel values or blockchain writes.')
        return 0
    except Exception as error:
        print('Court participant review stopped:',type(error).__name__)
        if type(error) is ValueError:print(str(error))
        return 1
    finally:
        if engine is not None:engine.dispose()


if __name__=='__main__':raise SystemExit(main())
