"""Aggregate-only inspection of duration review cases; no evidence changes."""
import argparse
from collections import Counter
from datetime import date
from decimal import Decimal
import json
from pathlib import Path, PurePosixPath
import re
from sqlalchemy import select, text
from database import create_identity_engine
from settings import Settings
from app.identity.inspect_history_sources import HEADERS
from app.identity.inspect_service_plans import ARCHIVE, BATCH, CONFIRMATION
from app.identity.register_profiles import private_key_file, verify_recovery
from app.intake.source_confirmation import load_source_confirmation
from app.intake.staging_rows import open_row
from app.intake.staging_store import stored_row
from app.staging.models import IntakeBatch, IntakeFile, RawRecord

FILENAME = 'transfer_history.csv'


def duration_shape(original):
    """Return fixed labels only: untrusted source text must never reach output."""
    value = original.strip()
    if not value:
        return 'MISSING'
    if re.fullmatch(r'[0-9]{1,12}', value):
        return 'ACCEPTED_NONNEGATIVE_INTEGER'
    if re.fullmatch(r'-[0-9]{1,12}', value):
        return 'NEGATIVE_INTEGER' if int(value) < 0 else 'SIGNED_ZERO'
    if re.fullmatch(r'\+[0-9]{1,12}', value):
        return 'EXPLICIT_PLUS_INTEGER'
    if re.fullmatch(r'[+-]?[0-9]{1,12}\.[0-9]{1,8}', value):
        number = Decimal(value)
        return ('NEGATIVE_' if number < 0 else 'NONNEGATIVE_') + ('INTEGRAL_DECIMAL' if number == number.to_integral_value() else 'FRACTIONAL_DECIMAL')
    if re.fullmatch(r'[0-9]+', value):
        return 'DIGIT_COUNT_EXCEEDS_POLICY'
    return 'OTHER_TEXT'


def reported_date_pair(row):
    # These are this event's dates, not the start/end of the previous posting.
    # Do not derive a corrected duration by subtracting them.
    values = []
    for name in ('departure_date', 'arrival_date'):
        value = row[name].strip()
        if not value:
            return 'DATE_PAIR_INCOMPLETE'
        if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value) is None:
            return 'DATE_PAIR_UNPARSEABLE'
        try:
            values.append(date.fromisoformat(value))
        except ValueError:
            return 'DATE_PAIR_UNPARSEABLE'
    return 'ARRIVAL_BEFORE_DEPARTURE' if values[1] < values[0] else 'ARRIVAL_EQUALS_DEPARTURE' if values[1] == values[0] else 'ARRIVAL_AFTER_DEPARTURE'


def flag_shape(value):
    text = value.strip()
    return text if text in {'TRUE', 'FALSE'} else 'MISSING' if not text else 'UNMAPPED'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--backup-key-file', type=Path, required=True)
    args = parser.parse_args()
    engine = None
    try:
        if args.key_file.resolve() == args.backup_key_file.resolve():
            raise ValueError('Use separate primary and backup keys.')
        crypto, backup = private_key_file(args.key_file), private_key_file(args.backup_key_file)
        verify_recovery(crypto, backup)
        settings = Settings()
        if (settings.host, settings.port, settings.name, settings.user) != ('127.0.0.1', 5432, 'police_identity', 'police_identity_app'):
            raise ValueError('Unexpected SQL application target.')
        engine = create_identity_engine(settings)
        counts, review_context = Counter(), Counter()
        total = reviewed = 0
        with engine.connect() as connection:
            with connection.begin():
                # SQL enforces read-only execution, including a consistent snapshot.
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                if tuple(connection.execute(text('SELECT current_user, current_database()')).one()) != ('police_identity_app', 'police_identity'):
                    raise ValueError('Unexpected connected SQL target.')
                batch = connection.execute(select(IntakeBatch.__table__).where(IntakeBatch.batch_id == BATCH)).mappings().one()
                files = connection.execute(select(IntakeFile.__table__).where(IntakeFile.batch_id == BATCH)).mappings().all()
                names = {PurePosixPath(f['archive_path']).name for f in files}
                if batch['archive_sha256'] != ARCHIVE or len(files) != batch['expected_file_count'] or len(names) != len(files):
                    raise ValueError('Registered source membership differs.')
                repo = Path(__file__).resolve().parents[3]
                confirmation = load_source_confirmation(repo / 'docs/intake-source-confirmation.json',
                    expected_batch_id=BATCH, expected_archive_sha256=ARCHIVE, expected_filenames=names,
                    allowed_source_codes={'PF_REGISTRY', 'POLICE_HR_IS', 'SRB'})
                if confirmation.confirmation_sha256 != CONFIRMATION or confirmation.source_for(FILENAME) != 'PF_REGISTRY':
                    raise ValueError('Source confirmation differs.')
                selected = [f for f in files if PurePosixPath(f['archive_path']).name == FILENAME]
                if len(selected) != 1:
                    raise ValueError('Transfer source membership differs.')
                file = selected[0]
                if tuple(file['columns']) != HEADERS[FILENAME] or file['expected_row_count'] != 33316:
                    raise ValueError('Transfer source contract differs.')
                query = select(RawRecord.__table__).where(RawRecord.import_file_id == file['import_file_id']).order_by(RawRecord.source_row_number)
                for number, raw in enumerate(connection.execute(query).mappings(), 1):
                    if raw['source_row_number'] != number or any(raw[f] != file[f] for f in ('batch_id', 'archive_path', 'source_file_sha256', 'import_file_id')):
                        raise ValueError('Transfer row sequence/binding differs.')
                    original = open_row(crypto, stored_row(raw))
                    if original != open_row(backup, stored_row(raw)) or original['columns'] != file['columns']:
                        raise ValueError('Transfer backup/header recovery differs.')
                    row = dict(zip(original['columns'], original['values'], strict=True))
                    shape = duration_shape(row['days_in_previous_posting'])
                    counts[shape] += 1
                    total += 1
                    if shape not in {'MISSING', 'ACCEPTED_NONNEGATIVE_INTEGER'}:
                        reviewed += 1
                        review_context['is_cancelled:' + flag_shape(row['is_cancelled'])] += 1
                        review_context['is_same_unit:' + flag_shape(row['is_same_unit'])] += 1
                        review_context['reported_event_dates:' + reported_date_pair(row)] += 1
                if total != 33316 or reviewed != 30:
                    raise ValueError('Coverage/review count differs from the verified planner checkpoint.')
        print('Read-only transfer duration inspection: PASSED')
        print('Transfer rows inspected:', total)
        print('Duration review rows:', reviewed)
        print('Duration format counts:', json.dumps(dict(sorted(counts.items()))))
        print('Review-row context counts:', json.dumps(dict(sorted(review_context.items()))))
        print('Formats and event-date relationships do not establish the previous posting duration or a correction.')
        print('No database writes, Mongo connection, personnel values or classification changes.')
        return 0
    except Exception as error:
        print('Transfer duration inspection stopped:', type(error).__name__)
        if type(error) is ValueError:
            print(str(error))
        print('No database writes requested.')
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
