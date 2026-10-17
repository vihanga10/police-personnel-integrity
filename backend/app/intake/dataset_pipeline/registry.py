"""Supported officer CSV datasets for controlled HQ upload, one spec per file.

A spec states how a row is identified, which officers it concerns, which
reviewed planner validates it and which personnel effect an *accepted* row may
have. Nothing here accepts a row; acceptance is evaluated separately after
independent approval, verified storage and dual-chain publication.
"""
from dataclasses import dataclass
import re
from uuid import UUID
from app.identity.court_membership import parse_court_participants
from app.identity.inspect_history_sources import HEADERS as HISTORY_HEADERS
from app.identity.inspect_srb_sources import HEADERS as SRB_HEADERS
from app.identity.inspect_srb_activity_sources import HEADERS as ACTIVITY_HEADERS
from app.identity.inspect_remaining_sources import HEADERS as REMAINING_HEADERS
from app.identity.reported_authority_actions import ROUTES as AUTHORITY_ROUTES
from app.identity.service_plan import ROUTES as SERVICE_ROUTES

POLICY = 'PERSONNEL_DATASET_REGISTRY_V1'
NIC = re.compile(r'(?:[0-9]{9}[VX]|[0-9]{12})')

# Personnel effect of an accepted row. Only dated effects change current state,
# and only once their reported effective date has arrived.
EFFECTS = ('RECORD', 'RANK', 'POSTING', 'POLICE_NUMBER', 'RESTRICTION',
           'RESTRICTION_OVERRIDE', 'SERVICE_SNAPSHOT')


@dataclass(frozen=True)
class Dataset:
    filename: str
    code: str
    label: str
    columns: tuple
    key_columns: tuple          # () means content-addressed rows (no source ID)
    subject_columns: tuple      # NIC columns whose resolved officers the row concerns
    source_systems: tuple       # represented systems an uploader may declare
    evidence_role: str
    effect: str
    effective_column: str | None
    display_date_column: str | None
    actor_columns: tuple = ()   # NIC columns resolved as actor candidates, never authority

    @property
    def multi_subject(self):
        return 'officer_nic_no' not in self.subject_columns

    @property
    def authority_actions(self):
        return tuple(kind for kind, _, _ in AUTHORITY_ROUTES.get(self.filename, ()))


def _spec(filename, code, label, columns, keys, systems, role, effect, effective, display,
          subjects=('officer_nic_no',), actors=()):
    columns = tuple(columns)
    assert len(set(columns)) == len(columns) and set(keys) <= set(columns) and set(subjects) <= set(columns)
    assert effect in EFFECTS and (effective is None or effective in columns)
    return Dataset(filename, code, label, columns, tuple(keys), tuple(subjects), tuple(systems), role,
                   effect, effective, display, tuple(actors))


DATASETS = {d.filename: d for d in (
    _spec('transfer_history.csv', 'TRANSFER_HISTORY', 'Transfers', HISTORY_HEADERS['transfer_history.csv'],
          ('transfer_id',), ('PF_REGISTRY', 'POLICE_HR_IS'), 'SOURCE_REPRESENTATION', 'POSTING',
          'effective_date', 'effective_date'),
    _spec('officer_police_numbers.csv', 'POLICE_NUMBERS', 'Police numbers', SRB_HEADERS['officer_police_numbers.csv'],
          ('officer_nic_no', 'number_type', 'police_no', 'valid_from'), ('SRB',), 'SOURCE_REPRESENTATION',
          'POLICE_NUMBER', 'valid_from', 'valid_from'),
    _spec('officer_restrictions.csv', 'RESTRICTIONS', 'Restrictions', SRB_HEADERS['officer_restrictions.csv'],
          ('restriction_id',), ('SRB',), 'SOURCE_REPRESENTATION', 'RESTRICTION', 'restriction_start_date',
          'restriction_start_date', actors=('restriction_recorded_officer_nic', 'restriction_removed_officer_nic')),
    _spec('restriction_overrides.csv', 'RESTRICTION_OVERRIDES', 'Restriction overrides',
          SRB_HEADERS['restriction_overrides.csv'], ('override_id',), ('SRB',), 'SOURCE_REPRESENTATION',
          'RESTRICTION_OVERRIDE', 'override_date', 'override_date', actors=('override_authority_nic',)),
    _spec('officer_service_information.csv', 'SERVICE_INFORMATION', 'Service information', tuple(SERVICE_ROUTES),
          ('service_id',), ('POLICE_HR_IS',), 'SOURCE_REPRESENTATION', 'SERVICE_SNAPSHOT', None, None),
    _spec('officer_duty_periods.csv', 'DUTY_PERIODS', 'Duty periods', ACTIVITY_HEADERS['officer_duty_periods.csv'],
          ('period_id',), ('SRB',), 'SOURCE_REPRESENTATION', 'RECORD', None, 'period_from',
          actors=('period_recorded_by_authority_nic',)),
    _spec('officer_firearms_expertise.csv', 'FIREARMS', 'Firearms assessments',
          ACTIVITY_HEADERS['officer_firearms_expertise.csv'], ('gun_record_id',), ('SRB',), 'SOURCE_REPRESENTATION',
          'RECORD', None, 'h1_practice_date', actors=('h1_supervisor_nic', 'h2_supervisor_nic', 'annual_supervisor_nic')),
    _spec('good_conduct_register.csv', 'GOOD_CONDUCT', 'Good conduct', ACTIVITY_HEADERS['good_conduct_register.csv'],
          ('good_conduct_id',), ('SRB',), 'SOURCE_REPRESENTATION', 'RECORD', None, 'event_date',
          actors=('recommending_asp_nic', 'sanctioning_authority_nic')),
    _spec('bad_conduct_register.csv', 'BAD_CONDUCT', 'Disciplinary records', ACTIVITY_HEADERS['bad_conduct_register.csv'],
          ('punishment_id',), ('SRB',), 'SOURCE_REPRESENTATION', 'RECORD', None, 'date_of_punishment'),
    _spec('officer_education.csv', 'EDUCATION', 'Education', REMAINING_HEADERS['officer_education.csv'], (),
          ('POLICE_HR_IS', 'PF_REGISTRY', 'SRB'), 'MULTISOURCE_REPRESENTATION', 'RECORD', None, None),
    _spec('officer_family_details.csv', 'FAMILY', 'Family details', REMAINING_HEADERS['officer_family_details.csv'], (),
          ('POLICE_HR_IS', 'PF_REGISTRY', 'SRB'), 'MULTISOURCE_REPRESENTATION', 'RECORD', None, 'datails_entry_date',
          actors=('recorded_by_officer_nic',)),
    _spec('public_complaints.csv', 'COMPLAINTS', 'Public complaints (allegations)',
          REMAINING_HEADERS['public_complaints.csv'], ('complaint_id',), ('PF_REGISTRY',), 'SOURCE_REPRESENTATION',
          'RECORD', None, 'date_received',
          actors=('officer_nic_as_recorded', 'investigating_officer_nic', 'unit_senior_questioned_nic')),
    _spec('operations.csv', 'OPERATIONS', 'Operations', REMAINING_HEADERS['operations.csv'], ('operation_no',),
          ('PF_REGISTRY',), 'SOURCE_REPRESENTATION', 'RECORD', None, 'operation_date',
          subjects=('commanding_officer_nic_no', 'investigating_officers_nic_numbers'),
          actors=('commanding_officer_nic_no',)),
    _spec('court_details.csv', 'COURT_CASES', 'Court cases', REMAINING_HEADERS['court_details.csv'], ('court_no',),
          ('PF_REGISTRY',), 'SOURCE_REPRESENTATION', 'RECORD', None, 'case_instituted_date',
          subjects=('participate_officers_details',)),
    _spec('_demotions_enacted.csv', 'DEMOTIONS', 'Enacted demotions', REMAINING_HEADERS['_demotions_enacted.csv'],
          ('punishment_id',), ('DERIVED_BAD_CONDUCT_VIEW',), 'DERIVED_NON_INDEPENDENT', 'RANK',
          'punishment_date', 'punishment_date'),
)}
CODES = {d.code: d for d in DATASETS.values()}
assert len(CODES) == len(DATASETS) and all(re.fullmatch('[A-Z_]{1,31}', c) for c in CODES)


def dataset(name):
    """Look up by filename or ledger code; unsupported files are refused."""
    spec = DATASETS.get(name) or CODES.get(name)
    if spec is None:
        raise ValueError('DATASET_UNSUPPORTED')
    return spec


def source_key(spec, row):
    """Stable reported source identity, scoped to the dataset.

    Rows without a source ID are content-addressed so an identical re-upload
    is a duplicate while any changed row is retained as a separate report.
    """
    if spec.key_columns:
        parts = [row[c].strip() for c in spec.key_columns]
        return None if any(not p for p in parts) or any(len(p) > 128 for p in parts) else '\x1f'.join(parts)
    from app.intake.promotion_pipeline.core import digest
    return 'CONTENT:' + row['officer_nic_no'].strip() + ':' + digest([row[c] for c in spec.columns])


def subject_nics(spec, row):
    """Reported subject NICs with their roles; malformed lists refuse to guess."""
    found, issues = [], []
    for column in spec.subject_columns:
        text = row[column]
        if column == 'participate_officers_details':
            parsed = parse_court_participants(text)
            if parsed.state != 'PARSED_SOURCE_CLAIMS':
                issues.append(column + ':' + parsed.state)
                continue
            values = [p['reported_nic'].upper() for p in parsed.participants]
        elif column == 'investigating_officers_nic_numbers':
            values = [v.strip().upper() for v in text.split(';')] if text.strip() else []
        else:
            values = [text.strip().upper()] if text.strip() or column == 'officer_nic_no' else []
        for value in values:
            if not NIC.fullmatch(value):
                issues.append(column + ':NIC_FORMAT_UNSUPPORTED')
            else:
                found.append((value, column))
    if not found and not issues:
        issues.append('SUBJECT_OFFICER_REQUIRED')
    return found, issues


def planner_issues(spec, row, officer, *, stations, actors, references):
    """Run the reviewed per-file planner with explicit lookup candidates.

    Candidate evidence comes from the signed directory (exact NIC), the
    provisioned station snapshot and the reference index. Returned codes are
    review issues only; parsed observations are not acceptance.
    """
    from app.identity.history_plan import plan_history
    from app.identity.srb_plan import plan_srb
    from app.identity.srb_activity_plan import plan_activity
    from app.identity.remaining_plan import plan_remaining
    from app.identity.service_plan import plan_service
    name = spec.filename
    uid = None if officer is None else UUID(officer)
    if name == 'transfer_history.csv':
        plan = plan_history(name, row, officer_uid=uid, station_candidates=stations)
    elif name in ('officer_police_numbers.csv', 'officer_restrictions.csv', 'restriction_overrides.csv'):
        plan = plan_srb(name, row, officer_uid=uid, station_candidates=stations, actor_candidates=actors,
                        reference_candidates=references if name == 'restriction_overrides.csv' else None)
    elif name in ACTIVITY_HEADERS:
        plan = plan_activity(name, row, officer_uid=uid, station_candidates=stations, actor_candidates=actors)
    elif name == 'officer_service_information.csv':
        plan = plan_service(row, officer_uid=uid, station_candidates=stations)
    else:
        plan = plan_remaining(name, row, officer_uid=uid, identity_candidates=actors)
    issues = list(plan.review_issues)
    for field in plan.fields:
        if field.status == 'REVIEW_REQUIRED':
            issues.extend(field.source_column + ':' + v for v in field.issues)
    return issues
