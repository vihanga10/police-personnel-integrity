"""Synthetic gate fixtures and real AEAD; no live research execution."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from uuid import UUID
import base64
import json
import pytest
import app.identity.audit_gate as A
from app.identity.anchor_gate import POLICY as LIVE_POLICY, publication_plan
from app.identity.protected_commitment import digest, merkle_root
from app.identity.destination_binding import row_binding
from app.identity.bitemporal_timestamp_binding import TABLE
from app.identity.evidence_bundle_v2 import open_artifact
from app.security.identity_crypto import IdentityCrypto
from app.identity.protected_recording_review import review_loaded_snapshot, POLICY
OFFICER, ASSERTION, SOURCE, FILE = (UUID(int=i) for i in range(1,5))
START = datetime(2026,10,1,tzinfo=timezone.utc)

def public_fixture():
    rows = [dict(publication_id='%064x' % (i+1), commitment_version=1, commitment='%064x' % (i+10000)) for i in range(6596)]
    payload = dict(policy='OFFICER_PROTECTED_COMMITMENT_V1', commitment_version=1, key_version='commit-v1',
                   batch_publication_id='%064x' % 80000, officers=rows, shared_commitment='%064x' % 80001,
                   coverage_commitment='%064x' % 80002, batch_commitment='%064x' % 80003)
    leaves = [dict(kind='OFFICER', **r) for r in rows] + [dict(kind='BATCH', publication_id=payload['batch_publication_id'], commitment=payload['batch_commitment'])]
    payload['merkle_root'] = merkle_root(leaves)
    return payload

@pytest.fixture
def verified(monkeypatch):
    p=public_fixture(); monkeypatch.setattr(A,'PUBLIC_SHA',digest(p))  # test-only fixture pin
    now=datetime.now(timezone.utc)
    c=dict(code_revision='a'*40,bundle_attempt_id='fixture-bundle',binding_attempt_id='fixture-binding',commitment_attempt_id='fixture-commitment',binding_artifact_sha256='b'*64)
    l=dict(policy=LIVE_POLICY,status='PASSED',public_payload_sha256=A.PUBLIC_SHA,checked_at=(now-timedelta(seconds=30)).isoformat(),completed_at=(now-timedelta(seconds=1)).isoformat(),scope=A.SCOPE,max_age_seconds=600,historical_claims='UNASSESSED',plan=publication_plan(p),code_revision=c['code_revision'],commitment_attempt_id=c['commitment_attempt_id'],binding_artifact_sha256=c['binding_artifact_sha256'])
    n=dict(channel='personnel',chaincode='officer-evidence-v1',genesis_sha256=A.FABRIC_GENESIS,genesis_identity=dict(policy='FABRIC_GENESIS_HEADER_DATA_V1',header_sha256=A.HEADER,data_sha256=A.DATA))
    f=dict(status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],public_payload_sha256=A.PUBLIC_SHA,fabric_result=dict(status='PASSED',mode='RECONCILE',officers=6596,original_valid_transactions=68,two_organization_readback=True,classification='UNASSESSED',public_payload_sha256=A.PUBLIC_SHA,batch_publication_id=p['batch_publication_id'],merkle_root=p['merkle_root'],network=n))
    i=dict(policy='SEPOLIA_PUBLICATION_TRANSACTION_V1',chain_id=11155111,genesis=A.GENESIS,contract=A.CONTRACT,deployment_transaction=A.DEPLOYMENT_TX,writer=A.WRITER,runtime_sha256=A.RUNTIME,config_sha256=A.CONFIG,batch='0x'+p['batch_publication_id'],public_payload_sha256=A.PUBLIC_SHA,merkle_root='0x'+p['merkle_root'])
    r=dict(status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],public_result=dict(policy='SEPOLIA_RESEARCH_PUBLICATION_V1',status='PASSED',mode='RECONCILE',code_revision=c['code_revision'],identity=i,officers=6596,original_valid_transactions=68,two_rpc_readback=True,finalized=True,research_publication_complete=True,submitted_transactions_this_run=0,classification='UNASSESSED',sealed_block='0x123',sealed_block_hash='0x'+'c'*64,transaction_hashes=['0x'+format(j+1,'064x') for j in range(68)]))
    return p,l,f,r,c,now

@pytest.fixture
def source():
    row = dict(source_assertion_id=ASSERTION, officer_uid=OFFICER,
        source_system_id=SOURCE, import_file_id=FILE, raw_record_id='a'*64,
        source_file_name='officer_police_numbers.csv', source_file_sha256='b'*64,
        source_row_number=1, intake_batch_id='FIXTURE', assertion_type='POLICE_NUMBER',
        transaction_start=START, transaction_end=None, assertion_state='ACTIVE',
        asserted_value_ciphertext=b'fixture-ciphertext')
    assertion = {k: str(v) if isinstance(v, UUID) else v for k, v in row.items()
        if k not in {'officer_uid', 'transaction_start', 'transaction_end',
            'assertion_state', 'asserted_value_ciphertext'}}
    catalog = dict(raw_record_id=row['raw_record_id'], assertion=assertion,
        filename=row['source_file_name'], delivery=dict(complete=True, assertion_id=str(ASSERTION)),
        candidate_links=[dict(officer_uid=str(OFFICER), role='officer_nic_no',
            state='CANDIDATE_NOT_ACCEPTED')])
    bindings = {row['raw_record_id']: [row_binding(TABLE, ('source_assertion_id',), row)]}
    return row, catalog, bindings

@pytest.fixture
def keys(tmp_path):
    data = dict(active_encryption_key_version='enc', active_lookup_key_version='lookup',
        encryption_keys={'enc':base64.b64encode(b'E'*32).decode()},
        lookup_keys={'lookup':base64.b64encode(b'L'*32).decode()})
    paths = [tmp_path/'primary.json', tmp_path/'backup.json']
    for path in paths:
        path.write_text(json.dumps(data)); path.chmod(0o600)
    return tuple(IdentityCrypto(path) for path in paths)


@pytest.fixture
def setup_review(verified, source, keys, tmp_path):
    p, live, fabric, public, context, now = verified
    permit = A.verify_inputs(p, live, fabric, public, context, now=now)
    crypto, backup = keys
    row, catalog, bindings = source
    snapshot = dict(crypto=crypto, backup=backup, public=p, context=context,
        envelope=A.seal_permit(crypto, backup, permit),
        catalog={row['raw_record_id']:catalog}, bindings={'raw_bindings':bindings})
    output = tmp_path/'private'; output.mkdir(mode=0o700)
    repo = tmp_path/'repo'; repo.mkdir()
    return snapshot, row, output/'review.json', repo


def run_review(data, rows=None):
    snapshot, row, dest, repo = data
    return review_loaded_snapshot(snapshot, [row] if rows is None else rows,
        [row['raw_record_id']], dest, repo)


def test_complete_private_review_recovers_and_makes_no_history_claim(setup_review):
    snapshot, row, dest, repo = setup_review
    assert run_review(setup_review) == dict(policy=POLICY, selected_rows=1,
        historical_known_as_of_supported=False)
    envelope = json.loads(dest.read_text())
    value = open_artifact(snapshot['crypto'], envelope, envelope['binding'])
    assert value == open_artifact(snapshot['backup'], envelope, envelope['binding'])
    assert value['records'][0]['transaction_start'] == START.isoformat()
    assert not value['visibility_time_established'] and not value['complete_history_established']
    assert not value['historical_known_as_of_supported'] and value['accepted_state'] is None
    assert str(OFFICER) not in dest.read_text()
    assert dest.stat().st_mode & 0o777 == 0o600
    assert list(dest.parent.iterdir()) == [dest]


@pytest.mark.parametrize('kind', ['missing','duplicate','altered','unknown','catalog','binding',
    'context','ciphertext','publication','backup','expired','output_repo','symlink','permissions'])
def test_failure_leaves_no_published_review(setup_review, kind, monkeypatch):
    snapshot, row, dest, repo = setup_review
    rows = [row]
    if kind == 'missing': rows = []
    elif kind == 'duplicate': rows = [row, row]
    elif kind == 'altered': rows = [dict(row, transaction_start=START+timedelta(seconds=1))]
    elif kind == 'unknown': rows = [dict(row, raw_record_id='f'*64)]
    elif kind == 'catalog': snapshot['catalog'][row['raw_record_id']]['delivery']['complete'] = False
    elif kind == 'binding': snapshot['bindings']['raw_bindings'][row['raw_record_id']].clear()
    elif kind == 'context': snapshot['context']['binding_attempt_id'] = 'changed'
    elif kind == 'ciphertext': snapshot['envelope']['ciphertext'] = 'AAAA'
    elif kind == 'publication': snapshot['public']['officers'][0]['commitment'] = 'f'*64
    elif kind == 'backup': snapshot['backup'] = IdentityCrypto.__new__(IdentityCrypto)
    elif kind == 'expired':
        value = open_artifact(snapshot['crypto'], snapshot['envelope'], A.binding(snapshot['context']))
        value['checked_at'] = (datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
        value['issued_at'] = value['checked_at']
        value['expires_at'] = (datetime.fromisoformat(value['checked_at'])+timedelta(seconds=600)).isoformat()
        snapshot['envelope'] = A.seal_permit(snapshot['crypto'], snapshot['backup'], value)
    elif kind == 'output_repo': dest = repo/'review.json'
    elif kind == 'symlink':
        link = dest.parent.parent/'link'; link.symlink_to(dest.parent, target_is_directory=True)
        dest = link/'review.json'
    elif kind == 'permissions': dest.parent.chmod(0o755)
    with pytest.raises(Exception):
        review_loaded_snapshot(snapshot, rows, [row['raw_record_id']], dest, repo)
    assert not dest.exists()


def test_existing_receipt_cannot_be_replaced(setup_review):
    dest = setup_review[2]; dest.write_bytes(b'original')
    with pytest.raises(FileExistsError): run_review(setup_review)
    assert dest.read_bytes() == b'original'
    assert list(dest.parent.iterdir()) == [dest]


def test_evidence_mutation_during_iteration_rejected(setup_review):
    snapshot, row, dest, repo = setup_review
    def rows():
        yield row
        snapshot['catalog'][row['raw_record_id']]['filename'] = 'changed.csv'
    with pytest.raises(ValueError, match='evidence changed'): run_review(setup_review, rows())
    assert not dest.exists()


def test_expiry_at_final_publication_cleans_temporary_file(setup_review, monkeypatch):
    import app.identity.protected_recording_review as R
    original = R.AlgorithmPermit.check
    calls = []
    def check(self, snapshot):
        calls.append(1)
        if len(calls) == 4:
            permit = open_artifact(snapshot['crypto'], snapshot['envelope'], A.binding(snapshot['context']))
            return original(self, snapshot, now=datetime.fromisoformat(permit['expires_at']))
        return original(self, snapshot)
    monkeypatch.setattr(R.AlgorithmPermit, 'check', check)
    with pytest.raises(ValueError, match='expired'): run_review(setup_review)
    assert len(calls) == 4
    assert list(setup_review[2].parent.iterdir()) == []
