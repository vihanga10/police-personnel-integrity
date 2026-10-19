"""Versioned exact source vocabularies; no authority or historical-state inference."""
import re
from dataclasses import dataclass, field
from datetime import date
from types import MappingProxyType

SERVICE_VALUE_POLICY = 'HR_SERVICE_VALUES_V1'
RANKS = MappingProxyType({
    'Police Constable':'PC',
    'Police Constable Class 1':'PC_C1', 'Police Constable Class 2':'PC_C2',
    'Police Constable Class 3':'PC_C3', 'Police Constable Class 4':'PC_C4',
    'Police Sergeant Class 1':'PS_C1', 'Police Sergeant Class 2':'PS_C2',
    'Sub Inspector of Police':'SI', 'Inspector of Police':'IP',
    'Chief Inspector of Police':'CIP', 'Assistant Superintendent of Police':'ASP',
    'Superintendent of Police':'SP', 'Senior Superintendent of Police':'SSP',
    'Deputy Inspector General of Police':'DIG', 'Senior Deputy Inspector General of Police':'SDIG',
})
UNITS = MappingProxyType({
    'CID':'CID', 'CCIB':'CCIB', 'Criminal Division':'CRIMINAL_DIVISION',
    'Station Crime Branch':'STATION_CRIME_BRANCH', 'Police Station':'POLICE_STATION',
    'District Command':'DISTRICT_COMMAND', 'Divisional Command':'DIVISIONAL_COMMAND',
    'Provincial Command':'PROVINCIAL_COMMAND', 'Administration Branch':'ADMINISTRATION_BRANCH',
    'Children and Women Bureau':'CHILDREN_AND_WOMEN_BUREAU',
    'Community Policing Branch':'COMMUNITY_POLICING_BRANCH',
    'Complaints and Information Branch':'COMPLAINTS_AND_INFORMATION_BRANCH',
    'Court Duty Branch':'COURT_DUTY_BRANCH', 'Reserve and Patrol Branch':'RESERVE_AND_PATROL_BRANCH',
    'Traffic Branch':'TRAFFIC_BRANCH', 'Vice and Narcotics Branch':'VICE_AND_NARCOTICS_BRANCH',
})
CATEGORY_MAPS = MappingProxyType({
    'entry_rank':RANKS, 'current_rank':RANKS,
    'entry_unit_type':UNITS, 'current_unit_type':UNITS,
    'current_rank_category':MappingProxyType({'Junior Gazetted':'JUNIOR_GAZETTED',
        'Non-Gazetted':'NON_GAZETTED', 'Senior Gazetted':'SENIOR_GAZETTED'}),
    'enrollment_type':MappingProxyType({'normal_service':'NORMAL_SERVICE','sport':'SPORT'}),
    'service_status':MappingProxyType({'Active':'ACTIVE','Interdicted':'INTERDICTED','On Extended Leave':'EXTENDED_LEAVE'}),
})
# Dataset consistency rule, not a legal or authorization definition.
EXPECTED_RANK_CATEGORY = MappingProxyType({code:
    'JUNIOR_GAZETTED' if code in {'ASP','SP'} else
    'SENIOR_GAZETTED' if code in {'SSP','DIG','SDIG'} else 'NON_GAZETTED'
    for code in RANKS.values()})

@dataclass(frozen=True)
class ServiceValue:
    value: object = field(repr=False)
    status: str
    issues: tuple[str,...] = ()
    policy_version: str = SERVICE_VALUE_POLICY


def map_service_category(name,supplied):
    if name not in CATEGORY_MAPS:
        raise ValueError('Unsupported service category.')
    if supplied is None or isinstance(supplied,str) and not supplied.strip():
        return ServiceValue(None,'MISSING')
    if not isinstance(supplied,str):
        return ServiceValue(None,'REVIEW_REQUIRED',('INVALID_TEXT_TYPE',))
    code = CATEGORY_MAPS[name].get(supplied.strip())
    if code is None:
        return ServiceValue(None,'REVIEW_REQUIRED',('UNMAPPED_CATEGORY',))
    return ServiceValue(code,'PARSED')


def parse_service_date(supplied):
    if supplied is None or isinstance(supplied,str) and not supplied.strip():
        return ServiceValue(None,'MISSING')
    if not isinstance(supplied,str):
        return ServiceValue(None,'REVIEW_REQUIRED',('INVALID_TEXT_TYPE',))
    value = supplied.strip()
    if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',value) is None:
        return ServiceValue(None,'REVIEW_REQUIRED',('UNSUPPORTED_DATE_FORMAT',))
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return ServiceValue(None,'REVIEW_REQUIRED',('INVALID_CALENDAR_DATE',))
    return ServiceValue(parsed,'PARSED',('REPORTED_DATE_NOT_STATE_EFFECTIVE_DATE',))
