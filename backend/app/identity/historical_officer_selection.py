"""Private exact-NIC candidate selection; no identity acceptance or disclosure API."""
from dataclasses import dataclass, field
import getpass
import hmac
import warnings
from uuid import UUID

from sqlalchemy import text
from database import create_identity_engine
from settings import Settings
from app.identity.historical_reconstruction import require
from app.identity.inspect_history_sources import inspected_link
from app.identity.normalization import normalize_identifier, NORMALIZATION_PROFILE

POLICY = 'HISTORICAL_OFFICER_SELECTION_V1'


@dataclass(frozen=True)
class Selection:
    # Selection metadata belongs only in encrypted reconstruction artifacts.
    officer_uid: str = field(repr=False)
    profile_raw_ids: tuple[str, ...] = field(repr=False)
    policy: str = POLICY
    method: str = 'EXACT_VERIFIED_NIC_AND_ANCHORED_PROFILE_CANDIDATE'
    normalization_profile: str = NORMALIZATION_PROFILE
    historical_identity: str = 'UNASSESSED'
    linkage_accepted: bool = False


def read_private_nic():
    """Refuse an echoing fallback; the NIC must never enter shell arguments."""
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        value = getpass.getpass('Enter officer NIC privately (hidden): ')
    require(isinstance(value, str) and len(value) <= 64, 'Private NIC input differs.')
    return normalize_identifier(value, identifier_type='NIC').value


def select_candidate(connection, crypto, backup, nic, manifest, catalog):
    """Verify live encrypted NIC evidence and its exact anchored PF profile link.

    Earlier/later NIC formats and case variants are not guessed equivalent.
    A candidate is not an accepted historical identity at the query date.
    """
    require(isinstance(nic, str) and len(nic) <= 64, 'Private NIC input differs.')
    normalized = normalize_identifier(nic, identifier_type='NIC')
    # This existing verifier checks retained candidates and primary/backup recovery.
    state, officer = inspected_link(connection, crypto, backup, normalized.value, {})
    require(state == 'EXACT_EVIDENCE_CANDIDATE' and officer is not None,
        'A single exact verified NIC candidate is required.')
    officer_uid = str(officer)
    require(str(UUID(officer_uid)) == officer_uid, 'Candidate officer UUID differs.')
    universe = {b['officer_uid'] for b in manifest['bundles']}
    require(officer_uid in universe, 'Candidate is outside the anchored officer universe.')
    query_digest, _ = crypto.lookup_hmac(normalized.value, identifier_type='NIC')
    matches = []
    for raw, row in catalog.items():
        if row['filename'] != 'officer_personal_information.csv':
            continue
        original = row['original']
        columns, values = original['columns'], original['values']
        require(len(columns) == len(set(columns)) == len(values) and
            all(isinstance(v, str) for v in columns + values) and 'officer_nic_no' in columns,
            'Anchored profile column shape differs.')
        reported = normalize_identifier(values[columns.index('officer_nic_no')], identifier_type='NIC')
        profile_digest, _ = crypto.lookup_hmac(reported.value, identifier_type='NIC')
        if not hmac.compare_digest(query_digest, profile_digest):
            continue
        require(raw == row['raw_record_id'] and row['classification'] == 'UNASSESSED' and
            row['delivery']['complete'] is True, 'Anchored profile provenance differs.')
        subject_links = [x for x in row['candidate_links'] if x['role'] == 'officer_nic_no']
        require(len(subject_links) == 1 and subject_links[0]['state'] == 'CANDIDATE_NOT_ACCEPTED',
            'Anchored profile subject is unresolved or ambiguous.')
        matches.append((raw, subject_links[0]['officer_uid']))
    # Enforce one profile and one officer; do not silently collapse conflicting rows.
    require(len(matches) == 1 and matches[0][1] == officer_uid,
        'Exact anchored profile and live NIC candidate must agree.')
    return Selection(officer_uid, (matches[0][0],))


def select_from_sql(crypto, backup, nic, manifest, catalog):
    """Use the restricted local application login in a read-only SQL snapshot."""
    settings = Settings()
    require((settings.host, settings.port, settings.name, settings.user) ==
        ('127.0.0.1', 5432, 'police_identity', 'police_identity_app'), 'Unexpected SQL selection target.')
    engine = create_identity_engine(settings)
    try:
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
                require(tuple(connection.execute(text('SELECT current_user, current_database()')).one()) ==
                    ('police_identity_app', 'police_identity'), 'Unexpected connected SQL identity.')
                return select_candidate(connection, crypto, backup, nic, manifest, catalog)
    finally:
        engine.dispose()
