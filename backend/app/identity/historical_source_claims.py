"""Extract reported temporal claims from the existing protected source catalog.

This adapter does not authenticate an inventory or authorize research execution.
The next runner must validate the complete inventory and original commitments,
authenticate encrypted artifacts, and require a fresh audit permit first.
"""
from datetime import date
import re
from app.identity.historical_reconstruction import Claim, require
from app.identity.evidence_bundle_v2 import canonical
from app.identity.protected_commitment import digest
from app.identity.history_plan import ROUTES as HISTORY
from app.identity.service_plan import ROUTES as SERVICE
from app.identity.srb_plan import ROUTES as SRB
from app.identity.remaining_plan import ROUTES as REMAINING

# Reuse the established source schemas so changed or missing columns fail closed.
HEADERS = {**{k: set(v) for k, v in HISTORY.items()},
    'officer_service_information.csv': set(SERVICE),
    **{k: set(v) for k, v in SRB.items()},
    '_demotions_enacted.csv': set(REMAINING['_demotions_enacted.csv'])}


# Parse only the inspected ISO date syntax; never guess day/month order.
def reported_date(text):
    if not text.strip():
        return None, ('REPORTED_DATE_MISSING',)
    try:
        require(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', text.strip()), 'Date format differs.')
        return date.fromisoformat(text.strip()), ()
    except ValueError:
        return None, ('REPORTED_DATE_INVALID',)


def source_claims(officer_uid, catalog, raw_bindings):
    """Only subject-role candidate edges feed state; recording actors never do.

    Preserve full original row/provenance through its catalog reference, field
    spellings through JSON values, and a fingerprint of all destination versions.
    Unsupported sources remain in the anchored catalog; they are not state claims.
    """
    claims = []
    for raw, item in sorted(catalog.items()):
        filename = item['filename']
        if filename not in HEADERS:
            continue
        require(raw == item['raw_record_id'] and re.fullmatch('[0-9a-f]{64}', raw), 'Source row binding differs.')
        # An officer mentioned as recorder or authority is not necessarily the subject.
        links = [x for x in item['candidate_links'] if x['officer_uid'] == officer_uid and x['role'] == 'officer_nic_no']
        if not links:
            continue
        require(len(links) == 1 and links[0]['state'] == 'CANDIDATE_NOT_ACCEPTED', 'Subject membership differs.')
        require(item['classification'] == 'UNASSESSED' and item['delivery']['complete'] is True,
            'Source state differs.')
        original = item['original']
        columns, values = original['columns'], original['values']
        require(len(columns) == len(set(columns)) == len(values) and set(columns) == HEADERS[filename]
            and all(isinstance(x, str) for x in columns + values), 'Source column preservation differs.')
        row = dict(zip(columns, values))
        require(bool(raw_bindings.get(raw)), 'Destination versions missing.')
        # Tie each claim to every captured destination version for its original row.
        fingerprint = digest(raw_bindings[raw])
        # Full source text stays in the private reference, including original date spellings.
        reference = canonical(dict(raw_record_id=raw, filename=filename,
            original=original, provenance=item['provenance'], assertion=item['assertion']))

        # Build one dimension-specific claim while preserving missing values for review.
        def add(dimension, fields, start_field=None, end_field=None, mode='EVENT', issues=()):
            if not any(row[f].strip() for f in fields):
                # A missing required state value is retained as a blocking review.
                value = canonical({f: row[f] for f in fields})
                issues = (*issues, 'REPORTED_VALUE_MISSING')
            else:
                value = canonical({f: row[f] for f in fields})
            start, start_issues = reported_date(row[start_field]) if start_field else (None, ())
            end, end_issues = (None, ())
            if end_field and row[end_field].strip():
                end, end_issues = reported_date(row[end_field])
            if start and end and end < start:
                issues = (*issues, 'INVERTED_REPORTED_PERIOD')
                # Preserve original dates in reference; do not create a valid interval.
                start = end = None
            claims.append(Claim(raw + ':' + dimension + ':' + ','.join(fields), officer_uid,
                dimension, value, reference, fingerprint, mode, start, end,
                tuple(sorted(set((*issues, *start_issues, *end_issues))))))

        # These routes describe source reports, not accepted outcomes of personnel actions.
        if filename == 'promotion_history.csv':
            add('rank', ('to_rank',), 'effective_date')
            # Arrival and unit identity semantics are not approved.
            add('posting', ('to_unit_name',), 'new_unit_arrive_date', issues=('PROMOTION_POSTING_SEMANTICS_UNASSESSED',))
        elif filename == 'transfer_history.csv':
            # Cancellation evidence prevents automatic application of a transfer.
            issues = ('TRANSFER_CANCELLATION_OR_FLAG_UNASSESSED',) if row['is_cancelled'].strip() != 'FALSE' or row['cancellation_date'].strip() or row['cancellation_ref'].strip() else ()
            add('rank', ('to_rank',), 'effective_date', issues=issues)
            add('posting', ('to_station_code', 'to_station_name', 'to_unit_type', 'to_unit_name'),
                'arrival_date', issues=(*issues, 'POSTING_DATE_AND_UNIT_IDENTITY_UNASSESSED'))
        elif filename == 'officer_police_numbers.csv':
            add('police_number', ('police_no', 'number_type'), 'valid_from', 'valid_to', 'INTERVAL')
        elif filename == 'officer_restrictions.csv':
            add('restrictions', ('restriction_id', 'restriction_category', 'restriction_effect', 'restriction_scope'),
                'restriction_start_date', 'restriction_removal_date', 'INTERVAL')
        # An override claim requires later authority and scope checks before any effect.
        elif filename == 'restriction_overrides.csv':
            add('restrictions', ('restriction_id', 'override_id', 'override_ground'), 'override_date',
                mode='REVIEW', issues=('OVERRIDE_AUTHORITY_SCOPE_AND_LINKAGE_UNASSESSED',))
        elif filename == '_demotions_enacted.csv':
            add('rank', ('floor_rank',), 'punishment_date', mode='REVIEW',
                issues=('DEMOTION_FLOOR_NOT_ACCEPTED_RESULTING_RANK',))
        # Current HR labels have no accepted historical applicability date.
        else:
            add('rank', ('entry_rank',), 'date_of_enlistment', issues=('ENLISTMENT_NOT_ACCEPTED_RANK_EFFECTIVE_DATE',))
            add('rank', ('current_rank',), mode='SNAPSHOT')
            add('police_number', ('entry_police_no',), mode='SNAPSHOT')
            add('police_number', ('current_police_no',), mode='SNAPSHOT')
            add('posting', ('current_station_code', 'current_station', 'current_unit_name'), mode='SNAPSHOT')
            add('posting', ('first_posted_police_station_code', 'first_posted_police_station_name', 'entry_unit_name'),
                'first_posted_date', issues=('INITIAL_POSTING_IDENTITY_AND_DATE_UNASSESSED',))
            add('service_status', ('service_status',), mode='SNAPSHOT')
    return tuple(claims)
