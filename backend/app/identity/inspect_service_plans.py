"""Read-only BATCH-RAW-001 service transformation/encryption planning.

Run from the research backend directory. Displays aggregate counts only.
Does not create MongoDB, classify records, import events or authorize access.
"""
import argparse
import json
import hmac
from collections import Counter
from pathlib import Path, PurePosixPath
import sys

BACKEND = Path(__file__).resolve().parents[2]

from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.register_profiles import private_key_file, verify_recovery
from app.identity.normalization import normalize_identifier, IdentifierInputError
from app.identity.candidate_lookup import find_identifier_candidates
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.models import OfficerIdentifierVersion, SourceAssertion
from app.identity.registration_service import evidence_context
from app.identity.normalization import NORMALIZATION_PROFILE
from app.identity.service_plan import plan_service, validate_service_routing
from app.identity.service_plan_crypto import seal_service_plan, open_service_plan
from app.identity.station_reference import load_staged_station_index

BATCH = 'BATCH-RAW-001'
ARCHIVE = '32f47c60b43ee1bce8887f3dd67bc07c6a83ed4c59f2f152c7cff933d905b1f2'
CONFIRMATION = 'b58bee4f05a607d8dbfe543c9d60ac483e8f66456b72ab64f7f6fe564bd8e481'
FILENAME = 'officer_service_information.csv'
CATEGORIES = ('entry_rank', 'current_rank', 'current_rank_category',
              'entry_unit_type', 'current_unit_type', 'enrollment_type', 'service_status')
DATE_FIELDS = ('date_of_enlistment', 'daily_paid_commencement_date',
               'pensionable_post_appointment_date', 'pensionable_post_confirmation_date',
               'first_posted_date', 'current_posted_to_unit_date', 'retirement_date')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verified_nic_evidence(connection,crypto,backup,identifier,candidates):
    references = []
    for evidence in candidates.evidence:
        if (evidence.registry_state != 'REGISTERED' or evidence.record_state not in {'ASSERTED','ACCEPTED'}
            or evidence.assertion_state != 'ACTIVE' or evidence.transaction_end is not None):
            continue
        saved = connection.execute(select(OfficerIdentifierVersion.__table__).where(
            OfficerIdentifierVersion.identifier_version_id == evidence.identifier_version_id
        )).mappings().one()
        assertion = connection.execute(select(SourceAssertion.__table__).where(
            SourceAssertion.source_assertion_id == evidence.source_assertion_id
        )).mappings().one()
        require(saved['officer_uid'] == assertion['officer_uid'] == evidence.officer_uid,
            'NIC assertion/officer binding differs.')
        require(saved['identifier_type'] == 'NIC' and saved['normalization_profile'] == NORMALIZATION_PROFILE
            and assertion['assertion_type'] == 'IDENTIFIER_NIC', 'NIC evidence kind differs.')
        kwargs = dict(key_version=saved['encryption_key_version'],context=evidence_context('IDENTIFIER',evidence.identifier_version_id))
        value = crypto.decrypt(saved['identifier_value_ciphertext'],**kwargs)
        require(value == backup.decrypt(saved['identifier_value_ciphertext'],**kwargs) == identifier.value.encode(), 'Exact NIC evidence recovery differs.')
        digest,_ = crypto.lookup_hmac(identifier.value,identifier_type='NIC',key_version=saved['lookup_key_version'])
        require(hmac.compare_digest(digest,saved['identifier_lookup_hmac']), 'NIC evidence lookup binding differs.')
        kwargs = dict(key_version=assertion['encryption_key_version'],context=evidence_context('ASSERTION',evidence.source_assertion_id))
        claim = crypto.decrypt_assertion(assertion['asserted_value_ciphertext'],**kwargs)
        require(claim == backup.decrypt_assertion(assertion['asserted_value_ciphertext'],**kwargs), 'NIC assertion backup recovery differs.')
        require((claim.get('normalized_value'),claim.get('identifier_type'),claim.get('normalization_profile'),
            claim.get('raw_record_id'),claim.get('source_confirmation_sha256'),claim.get('source_column')) ==
            (identifier.value,'NIC',NORMALIZATION_PROFILE,assertion['raw_record_id'],CONFIRMATION,'officer_nic_no'), 'NIC assertion binding differs.')
        require(normalize_identifier(claim.get('reported_value'),identifier_type='NIC').value == identifier.value, 'NIC original/normalized evidence differs.')
        require(assertion['transaction_end'] is None, 'NIC assertion is closed.')
        references.append(dict(identifier_version_id=str(evidence.identifier_version_id),source_assertion_id=str(evidence.source_assertion_id),
            linkage_method='EXACT_ENCRYPTED_NIC_EVIDENCE_MATCH',historical_eligibility='UNASSESSED'))
    return references

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--backup-key-file', type=Path, required=True)
    args = parser.parse_args()
    engine = None
    try:
        require(args.key_file.resolve() != args.backup_key_file.resolve(), 'Use separate primary and backup key files.')
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        settings = Settings()
        require((settings.host, settings.port, settings.name, settings.user) ==
                ('127.0.0.1',5432,'police_identity','police_identity_app'), 'Unexpected database configuration.')
        engine = create_identity_engine(settings)
        validate_service_routing(json.loads((BACKEND.parent/'docs/field-routing.json').read_text()))
        counts = {name:Counter() for name in CATEGORIES}
        field_statuses,plan_issues = Counter(),Counter()
        planned = rows_requiring_review = 0
        missing, identity, milestones = Counter(), Counter(), Counter()
        source_ids, officer_ids = set(), set()
        duplicate_sources = duplicate_officers = total = 0
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user, current_database()')).one()) ==
                        ('police_identity_app','police_identity'), 'Unexpected connected account/database.')
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                require(batch['archive_sha256'] == ARCHIVE, 'Archive fingerprint differs.')
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = {PurePosixPath(f['archive_path']).name for f in files}
                require(len(files) == batch['expected_file_count'] and len(names) == len(files), 'Source membership differs.')
                confirmed = load_source_confirmation(BACKEND.parent/'docs/intake-source-confirmation.json',
                    expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE,
                    expected_filenames=names, allowed_source_codes={'PF_REGISTRY','POLICE_HR_IS','SRB'})
                require(confirmed.confirmation_sha256 == CONFIRMATION, 'Confirmation fingerprint differs.')
                source = confirmed.source_for(FILENAME)
                require(source == 'POLICE_HR_IS','Service supplying source differs from the observed contract.')
                stations,station_provenance = load_staged_station_index(connection,crypto,backup,batch_id=BATCH)
                chosen = [f for f in files if PurePosixPath(f['archive_path']).name == FILENAME]
                require(len(chosen) == 1, 'Expected exactly one registered service file.')
                file = chosen[0]
                required = set(CATEGORIES+DATE_FIELDS) | {'service_id','officer_nic_no'}
                require(required.issubset(file['columns']), 'Service headers lack required fields.')
                query = select(RawRecord.__table__).where(RawRecord.import_file_id == file['import_file_id']).order_by(RawRecord.source_row_number)
                for number, raw in enumerate(connection.execute(query).mappings(),1):
                    require(raw['source_row_number'] == number, 'Service row sequence has a gap.')
                    require(all(raw[name] == file[name] for name in ('batch_id','archive_path','source_file_sha256')), 'Service row source binding differs.')
                    payload = open_row(crypto,stored_row(raw))
                    require(payload == open_row(backup,stored_row(raw)) and payload['columns'] == file['columns'], 'Service header or backup recovery differs.')
                    row = dict(zip(payload['columns'],payload['values'],strict=True))
                    total += 1
                    for name, value in row.items():
                        if not value.strip():
                            missing[name] += 1
                    for name in CATEGORIES:
                        # Aggregate source vocabularies, never officer-level records.
                        label = row[name].strip() or '<MISSING>'
                        counts[name][label] += 1
                    sid = row['service_id'].strip()
                    if sid:
                        duplicate_sources += sid in source_ids
                        source_ids.add(sid)
                    for name in DATE_FIELDS:
                        value = row[name].strip()
                        if value:
                            import re
                            from datetime import date
                            try:
                                require(re.fullmatch(r'\d{4}-\d{2}-\d{2}',value) is not None, 'Not ISO date text.')
                                date.fromisoformat(value)
                            except (ValueError,RuntimeError):
                                milestones[name+':REQUIRES_DATE_FORMAT_REVIEW'] += 1
                            else:
                                milestones[name+':ISO_CALENDAR_DATE'] += 1
                    try:
                        nic = normalize_identifier(row['officer_nic_no'],identifier_type='NIC')
                    except IdentifierInputError:
                        identity['UNUSABLE_NIC'] += 1
                    else:
                        candidates = find_identifier_candidates(connection,crypto,nic)
                        identity[candidates.status] += 1
                        if candidates.status == 'SINGLE_CANDIDATE':
                            officer = candidates.officer_uids[0]
                            duplicate_officers += officer in officer_ids
                            officer_ids.add(officer)
                            identifier_refs = verified_nic_evidence(connection,crypto,backup,nic,candidates)
                            if not identifier_refs:
                                identity['NO_USABLE_NIC_EVIDENCE'] += 1
                                continue
                            plan = plan_service(row,officer_uid=officer,station_candidates=stations.candidates)
                            references = dict(service_source=dict(batch_id=BATCH,raw_record_id=raw['raw_record_id'],
                                import_file_id=str(raw['import_file_id']),source_file_sha256=raw['source_file_sha256'],
                                source_row_number=number,reported_source_system_code=source,confirmation_sha256=CONFIRMATION),
                                identifier_evidence=identifier_refs,station_source=station_provenance,station_matches={})
                            for item in plan.fields:
                                field_statuses[item.status] += 1
                                for issue in item.issues:
                                    plan_issues[item.source_column+':'+issue] += 1
                                if item.source_column in {'first_posted_police_station_code','current_station_code'} and item.status == 'PARSED':
                                    references['station_matches'][item.source_column] = dict(station_code=item.value,
                                        raw_record_id=stations.source_rows[item.value],historical_applicability='UNKNOWN')
                            for issue in plan.review_issues+plan.uncertainties:
                                plan_issues[issue] += 1
                            binding = dict(officer_uid=officer,raw_record_id=raw['raw_record_id'])
                            ciphertext,version = seal_service_plan(crypto,plan,reference_evidence=references,**binding)
                            primary = open_service_plan(crypto,ciphertext,key_version=version,**binding)
                            recovered = open_service_plan(backup,ciphertext,key_version=version,**binding)
                            require(primary == recovered,'Service plan encrypted recovery differs.')
                            planned += 1
                            rows_requiring_review += plan.needs_review
                require(total == file['expected_row_count'], 'Service source count differs.')
        print('Read-only service planning and encrypted recovery: PASSED')
        print('Service rows planned:',planned)
        print('Rows requiring field/consistency review:',rows_requiring_review)
        print('Field status counts:',dict(sorted(field_statuses.items())))
        print('Issue/uncertainty counts:',dict(sorted(plan_issues.items())))
        print('Reported supplying source:',source)
        print('Registered service rows:',total)
        print('Headers:',len(file['columns']))
        print('Missing field counts:',dict(sorted(missing.items())))
        print('Identity candidate counts:',dict(sorted(identity.items())))
        print('Distinct single-candidate officers:',len(officer_ids))
        print('Repeated service identifiers:',duplicate_sources)
        print('Repeated single-candidate officers:',duplicate_officers)
        for name in CATEGORIES:
            print('Source vocabulary counts:',name,dict(sorted(counts[name].items())))
        print('Date format counts:',dict(sorted(milestones.items())))
        print('Snapshot applicability remains UNKNOWN. ISO parsing does not establish date semantics.')
        print('Exact NIC evidence verified for planned rows; historical identifier eligibility remains unassessed.')
        print('Planning success is not import readiness, source truth, authorization or current-state verification.')
        print('No database writes, saved plaintext, personnel-level output or classification changes.')
        return 0
    except Exception as error:
        print('Service inspection stopped:',type(error).__name__)
        if isinstance(error,RuntimeError):
            print(str(error))
        print('No database writes were requested.')
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
