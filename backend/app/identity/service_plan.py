"""Plan all HR service fields in memory; no persistence, classification or access."""
from dataclasses import dataclass, field, replace
from uuid import UUID
from app.identity.service_values import CATEGORY_MAPS, EXPECTED_RANK_CATEGORY, map_service_category, parse_service_date

SERVICE_PLAN_POLICY = 'HR_SERVICE_PLAN_V1'
ROUTES = {'service_id': 'source_record_id', 'officer_nic_no': 'officer_uid', 'date_of_enlistment': 'reported_enlistment_date', 'daily_paid_commencement_date': 'reported_daily_paid_commencement_date', 'pensionable_post_appointment_date': 'reported_pensionable_appointment_date', 'pensionable_post_confirmation_date': 'reported_pensionable_confirmation_date', 'entry_rank': 'reported_entry_rank_code', 'recruitment_batch': 'recruitment_batch_reference', 'entry_police_no': 'entry_police_number_ciphertext', 'current_police_no': 'reported_current_police_number_ciphertext', 'enrollment_type': 'enrollment_type_code', 'first_posted_date': 'reported_first_posting_date', 'first_posted_police_station_name': 'reported_first_station_name', 'first_posted_police_station_code': 'first_station_reference', 'first_posted_Police_Station_division': 'reported_first_station_division', 'first_posted_Police_Station_province': 'reported_first_station_province', 'entry_unit_type': 'reported_entry_unit_type_code', 'entry_unit_name': 'entry_unit_reference', 'current_rank': 'reported_current_rank_code', 'current_rank_category': 'reported_current_rank_category_code', 'current_unit_type': 'reported_current_unit_type_code', 'current_unit_name': 'reported_current_unit_reference', 'current_unit_location': 'reported_current_unit_location', 'current_posted_to_unit_date': 'reported_current_unit_posting_date', 'current_station': 'reported_current_station_name', 'current_station_code': 'reported_current_station_reference', 'current_division': 'reported_current_division', 'current_province': 'reported_current_province', 'retirement_date': 'reported_retirement_date', 'service_years': 'reported_service_years', 'time_left': 'reported_time_left', 'service_status': 'reported_service_status_code'}
DATE_FIELDS = frozenset({'date_of_enlistment','daily_paid_commencement_date',
    'pensionable_post_appointment_date','pensionable_post_confirmation_date',
    'first_posted_date','current_posted_to_unit_date','retirement_date'})
REQUIRED = frozenset({'service_id','officer_nic_no','current_rank','current_unit_type','service_status'})

@dataclass(frozen=True)
class ServiceField:
    source_column: str
    target_field: str
    source_value: str = field(repr=False)
    value: object = field(repr=False)
    status: str
    issues: tuple[str,...] = ()

@dataclass(frozen=True)
class ServicePlan:
    fields: tuple[ServiceField,...] = field(repr=False)
    review_issues: tuple[str,...] = ()
    uncertainties: tuple[str,...] = ('SNAPSHOT_DATE_UNAVAILABLE','RETIREMENT_DATE_MEANING_UNASSESSED',
        'SOURCE_INDEPENDENCE_UNVERIFIED','IDENTIFIER_TEMPORAL_ELIGIBILITY_UNASSESSED')
    policy_version: str = SERVICE_PLAN_POLICY

    @property
    def needs_review(self):
        return bool(self.review_issues) or any(f.status == 'REVIEW_REQUIRED' for f in self.fields)


def plan_service(row, *, officer_uid, station_candidates=None):
    if not isinstance(officer_uid,UUID):
        raise ValueError('An established officer UUID is required.')
    if set(row) != set(ROUTES) or any(not isinstance(value,str) for value in row.values()):
        raise ValueError('Service rows must have the exact text-valued routing fields.')
    fields = []
    for name,target in ROUTES.items():
        original = row[name]
        text = original.strip()
        if not text:
            status = 'REVIEW_REQUIRED' if name in REQUIRED else 'MISSING'
            fields.append(ServiceField(name,target,original,None,status,('REQUIRED_VALUE_MISSING',) if name in REQUIRED else ()))
            continue
        if len(text) > 1000 or any(ord(c) < 32 or ord(c) == 127 for c in text):
            fields.append(ServiceField(name,target,original,None,'REVIEW_REQUIRED',('INVALID_TEXT_VALUE',)))
            continue
        if name in CATEGORY_MAPS:
            result = map_service_category(name,text)
            value,status,issues = result.value,result.status,result.issues
        elif name in DATE_FIELDS:
            result = parse_service_date(text)
            value,status,issues = result.value,result.status,result.issues
        else:
            value,status,issues = text,'PARSED',()
            if name == 'officer_nic_no':
                # Caller verifies exact stored identifier evidence first.
                value = officer_uid
            elif name in {'entry_unit_name','current_unit_name'}:
                value = {'reported_label':text,'resolution':'UNRESOLVED'}
                issues = ('UNIT_REFERENCE_UNRESOLVED',)
            elif name in {'service_years','time_left'}:
                issues = ('DERIVED_VALUE_UNITS_AND_REFERENCE_DATE_UNASSESSED',)
            elif name in {'first_posted_Police_Station_division','first_posted_Police_Station_province','current_division','current_province'}:
                issues = ('HIERARCHY_APPLICABILITY_UNASSESSED',)
        fields.append(ServiceField(name,target,original,value,status,issues))
    by_name = {f.source_column:i for i,f in enumerate(fields)}
    for code_name,label_name in (
        ('first_posted_police_station_code','first_posted_police_station_name'),
        ('current_station_code','current_station'),
    ):
        index = by_name[code_name]
        item,label = fields[index],fields[by_name[label_name]]
        if item.status != 'PARSED':
            if item.status == 'MISSING' and label.status == 'PARSED':
                fields[index] = replace(item,status='REVIEW_REQUIRED',issues=('STATION_CODE_MISSING',))
            continue
        # Exact code/name pair must exist in this supplied source snapshot.
        candidates = None if station_candidates is None else station_candidates.get(label.source_value.strip(),())
        if station_candidates is None:
            fields[index] = replace(item,value=None,status='REVIEW_REQUIRED',issues=('STATION_REFERENCE_UNASSESSED',))
        elif label.status != 'PARSED':
            fields[index] = replace(item,value=None,status='REVIEW_REQUIRED',issues=('STATION_LABEL_MISSING',))
        elif tuple(candidates) != (item.source_value.strip(),):
            fields[index] = replace(item,value=None,status='REVIEW_REQUIRED',issues=('STATION_CODE_NAME_UNRESOLVED_OR_CONFLICTING',))
        else:
            fields[index] = replace(item,issues=('STATION_REFERENCE_SOURCE_SCOPED',))
    values = {f.source_column:f.value for f in fields if f.status == 'PARSED'}
    reviews = []
    rank,category = values.get('current_rank'),values.get('current_rank_category')
    if rank is not None and category is not None and EXPECTED_RANK_CATEGORY.get(rank) != category:
        reviews.append('REPORTED_RANK_CATEGORY_CONFLICT')
    for before,after,issue in (
        ('pensionable_post_appointment_date','pensionable_post_confirmation_date','REPORTED_CONFIRMATION_BEFORE_APPOINTMENT'),
        ('date_of_enlistment','first_posted_date','REPORTED_FIRST_POSTING_BEFORE_ENLISTMENT'),
    ):
        if before in values and after in values and values[after] < values[before]:
            reviews.append(issue)
    return ServicePlan(tuple(fields),tuple(reviews))


def validate_service_routing(contract):
    files = [f for f in contract['files'] if f['filename'] == 'officer_service_information.csv']
    if len(files) != 1:
        raise ValueError('Service routing membership differs.')
    fields = files[0]['fields']
    if len(fields) != len(ROUTES) or {f['source_column']:f['target_field'] for f in fields} != ROUTES or any(f['destination'] != 'mongodb.service_status_events' for f in fields):
        raise ValueError('Service routing contract differs.')
