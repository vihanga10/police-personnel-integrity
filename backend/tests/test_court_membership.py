"""Full-cell grammar handling and candidate membership without invented roles."""
from uuid import uuid4
import pytest
from app.identity.court_membership import parse_court_participants, candidate_membership
from app.identity.evidence_bundle_v2 import BundleInventory

NIC='123456789V'


def test_original_entries_and_descriptor_preserved():
    text='  '+NIC+' (  Private descriptor  );200012345678 (Other) '
    p=parse_court_participants(text)
    assert p.state=='PARSED_SOURCE_CLAIMS' and len(p.participants)==2
    assert p.participants[0]['original_entry']=='  '+NIC+' (  Private descriptor  )'
    assert p.participants[0]['parenthesized_text']=='  Private descriptor  '
    assert [x['position'] for x in p.participants]==[1,2]
    assert 'Private descriptor' not in repr(p)


@pytest.mark.parametrize('text',[
    NIC+' (Text);', 'prefix '+NIC+' (Text)',NIC+' (Text) trailing',
    NIC+' (Text)|200012345678 (Other)',NIC+' ((Text))',NIC+' (  )',
    NIC+' (Text);invalid',NIC+' Text',NIC+' (Text;Other)', '123456789Vtail (Text)',
    'nic: '+NIC+' (Text)',NIC+' (Text),200012345678 (Other)'])
def test_unreviewed_grammar_produces_no_partial_links(text):
    p=parse_court_participants(text)
    assert p.state=='GRAMMAR_REVIEW_REQUIRED' and not p.participants


def test_unresolved_participant_and_repeats_not_lost():
    officer=uuid4()
    def resolve(nic):
        return ('EXACT_EVIDENCE_CANDIDATE',officer) if nic==NIC else ('NO_CANDIDATE_FOUND',None)
    p=candidate_membership(NIC+' (Text);'+NIC+' (Text);200012345678 (Other)',resolve)
    assert len(p.participants)==3
    assert p.participants[2]['officer_uid'] is None
    assert p.participants[2]['candidate_status']=='NO_CANDIDATE_FOUND'
    assert all(not x['linkage_accepted'] and x['authority']=='UNASSESSED' for x in p.participants)


def test_candidate_not_authority_or_rank():
    p=candidate_membership(NIC+' (SP)',lambda _:('EXACT_EVIDENCE_CANDIDATE',uuid4()))
    assert p.participants[0]['parenthesized_text']=='SP'
    assert p.participants[0]['descriptor_semantics']=='UNASSESSED'
    assert 'rank' not in p.participants[0]


@pytest.mark.parametrize('state,officer', [('MULTIPLE_CANDIDATES',uuid4()),('EXACT_EVIDENCE_CANDIDATE','not-a-uuid')])
def test_invalid_resolver_binding_rejected(state,officer):
    with pytest.raises(ValueError):candidate_membership(NIC+' (Text)',lambda _:(state,officer))


def test_ambiguous_candidates_remain_unknown():
    p=candidate_membership(NIC+' (Text)',lambda _:('MULTIPLE_CANDIDATES',None))
    assert p.participants[0]['officer_uid'] is None


def test_missing_oversized_and_limit():
    assert parse_court_participants(' ').state=='MISSING_REVIEW'
    assert parse_court_participants('x'*1048577).state=='OVERSIZED_REVIEW'
    assert parse_court_participants(';'.join([NIC+' (Text)']*1001)).state=='PARTICIPANT_LIMIT_REVIEW'
    with pytest.raises(ValueError):parse_court_participants(None)


def test_malformed_cell_does_not_call_identity_resolver():
    def fail(_):raise AssertionError('Resolver should not be called')
    assert not candidate_membership(NIC+' (Text);invalid',fail).participants


def test_version2_shared_court_links_and_empty_unassigned_counter():
    officers=[str(uuid4()),str(uuid4())];inv=BundleInventory(officers,{'court_details.csv':1})
    inv.add('court_details.csv','a'*64,dict(columns=['participate_officers_details'],values=[NIC+' (Text)']),
        dict(source_row_number=1),[(o,'reported_court_participant') for o in officers])
    inv.bind_receipt('a'*64,dict(complete=True),dict(x=1))
    snap=dict(batch_id='fixture',archive_sha256='b'*64,confirmation_sha256='c'*64,code_revision='d'*40,collection_started_at='fixture')
    result=inv.finish(snap)
    assert all(x['bundle_version']==2 for x in result['bundles'])
    assert len(inv.catalog['court_details.csv'])==1
    assert all(x['evidence'][0]['candidate_roles']==['reported_court_participant'] for x in result['bundles'])


def test_v2_encrypted_participant_recovery_and_v1_context_rejection(tmp_path):
    import base64
    import json
    from app.security.identity_crypto import IdentityCrypto
    from app.identity.evidence_bundle_v2 import seal_artifact, open_artifact
    from app.identity.evidence_bundle import open_artifact as open_v1
    data=dict(active_encryption_key_version='v1',active_lookup_key_version='v1',
        encryption_keys={'v1':base64.b64encode(b'A'*32).decode()},
        lookup_keys={'v1':base64.b64encode(b'B'*32).decode()})
    primary=tmp_path/'primary.json';backup=tmp_path/'backup.json'
    for path in (primary,backup):path.write_text(json.dumps(data))
    crypto,recovery=IdentityCrypto(primary),IdentityCrypto(backup)
    result=candidate_membership(NIC+' (PRIVATE_DESCRIPTION)',lambda _:('NO_CANDIDATE_FOUND',None))
    payload=dict(participants=list(result.participants))
    binding=dict(artifact='fixture-court')
    envelope=seal_artifact(crypto,recovery,payload,binding)
    assert NIC not in json.dumps(envelope) and 'PRIVATE_DESCRIPTION' not in json.dumps(envelope)
    assert open_artifact(recovery,envelope,binding)==payload
    with pytest.raises(ValueError):open_v1(crypto,envelope,binding)


def test_lowercase_old_nic_and_original_descriptor_not_normalized():
    result=parse_court_participants('123456789v (  original TEXT  )')
    assert result.participants[0]['reported_nic']=='123456789v'
    assert result.participants[0]['parenthesized_text']=='  original TEXT  '
