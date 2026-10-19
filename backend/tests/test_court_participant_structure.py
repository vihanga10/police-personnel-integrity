"""Grammar privacy, quoting and conservative review categories."""
import json
import pytest
from app.identity.court_participant_structure import structure, CourtStructureReport

@pytest.mark.parametrize('text', ['', '  ', '\n'])
def test_missing(text):assert structure(text)['state']=='MISSING'

@pytest.mark.parametrize('text', ['(', ']','([)]','"unfinished','x (y'])
def test_unbalanced(text):assert structure(text)['state']=='UNBALANCED_REVIEW'


def test_no_identifiers_or_names_in_report():
    report=CourtStructureReport()
    report.add('123456789V (PRIVATE_NAME / PRIVATE_RANK); 200012345678 (OTHER_NAME)')
    rendered=json.dumps(report.report())
    assert all(x not in rendered for x in ['123456789V','200012345678','PRIVATE_NAME','PRIVATE_RANK','OTHER_NAME'])
    assert report.report()['observations']['TOP_SEPARATOR:SEMICOLON']==1


def test_internal_separators_not_flat_members():
    result=structure('123456789V (rank, role); 200012345678 (rank)')
    assert result['observations']['SEGMENTS']==2
    assert 'TOP_SEPARATOR:COMMA' not in result['observations']


def test_quotes_hide_separators():
    result=structure('nic: 123456789V name: "Example; Name"')
    assert result['observations']['SEGMENTS']==1


def test_mixed_separators_stay_review():
    assert structure('123456789V;200012345678|987654321X')['state']=='MIXED_TOP_SEPARATORS_REVIEW'


def test_labels_bounded_allowlist():
    result=structure('private_person_name: Example nic: 123456789V')
    assert 'private_person_name' not in json.dumps(result)
    assert any(k.startswith('LABEL:') for k in result['observations'])


def test_embedded_nic_is_not_a_whole_token():
    assert structure('prefix123456789Vtail')['observations']['SEGMENT_NIC_COUNT:0']==1


def test_oversize_and_invalid_types():
    assert structure('x'*1048577)['state']=='OVERSIZED_REVIEW'
    with pytest.raises(ValueError):structure(None)


def test_empty_segment_preserved():
    assert structure('123456789V;;200012345678')['observations']['EMPTY_SEGMENT']==1


def test_aggregate_counts_include_all_rows():
    report=CourtStructureReport();report.add('');report.add('123456789V')
    assert report.report()['rows']==2
    assert sum(report.report()['structure_states'].values())==2
