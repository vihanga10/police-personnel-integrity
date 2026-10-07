"""Family schema and migration safety checks without database access."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import pytest
from sqlalchemy import CheckConstraint
from app.db.base import Base
from app.models import OfficerFamilyCivilEventVersion, OfficerNextOfKinVersion, SourceAttestation

MODELS=(OfficerFamilyCivilEventVersion,OfficerNextOfKinVersion,SourceAttestation)
REMOVED={
    'officer_family_civil_event_version':{'event_type','event_date','evidence_reference_ciphertext'},
    'officer_next_of_kin_version':{'related_person_name','relationship_type','address_ciphertext'},
    'source_attestation':{'actor_name_ciphertext','actor_identifier_ciphertext','actor_identifier_lookup_hmac',
        'actor_rank_asserted','signature_reference_ciphertext','attested_on','lookup_key_version','actor_identifier_type'},
}


def migration():
    path=Path(__file__).resolve().parents[1]/'migrations/versions/f28b6d40ea73_encrypt_empty_family_destinations.py'
    spec=importlib.util.spec_from_file_location('family_migration_test',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('model',MODELS)
def test_sensitive_family_values_have_only_required_encrypted_payload(model):
    table=model.__table__
    assert REMOVED[model.__tablename__].isdisjoint(table.c.keys())
    assert table.c.profile_payload_ciphertext.nullable is False
    assert table.c.encryption_key_version.nullable is False
    assert table.c.source_assertion_id.nullable is False
    for constraint in table.constraints:
        if isinstance(constraint,CheckConstraint):
            import re
            assert not any(re.search(r'\b'+name+r'\b',str(constraint.sqltext)) for name in REMOVED[model.__tablename__])


@pytest.mark.parametrize('model',MODELS)
def test_versions_keep_traceable_chains_and_restricted_foreign_keys(model):
    table=model.__table__
    assert {'version_number','transaction_start','transaction_end','record_state'}.issubset(table.c.keys())
    assert all(fk.ondelete=='RESTRICT' for fk in table.foreign_keys)
    assert any(index.unique and 'predecessor' in index.name for index in table.indexes)
    assert any(getattr(c,'name','') and 'chain_version' in c.name for c in table.constraints)


def test_next_of_kin_dates_stay_unknown_in_plaintext():
    table=OfficerNextOfKinVersion.__table__
    assert any(str(c.sqltext)=='valid_from IS NULL AND valid_to IS NULL' for c in table.constraints if isinstance(c,CheckConstraint))


class RecordingOps:
    def __init__(self,fail_at=None):self.calls=[];self.guards=0;self.fail_at=fail_at
    def f(self,name):return name
    def execute(self,sql):
        self.calls.append(('execute',str(sql)))
        if 'IF EXISTS (SELECT 1 FROM identity.' in str(sql):
            self.guards+=1
            if self.guards==self.fail_at:raise RuntimeError('simulated populated destination')
    def __getattr__(self,name):
        def action(*args,**kwargs):self.calls.append((name,args,kwargs))
        return action


@pytest.mark.parametrize('position',[1,2,3])
def test_any_populated_destination_stops_before_schema_mutation(position):
    module=migration();ops=RecordingOps(position)
    with patch.object(module,'op',ops),pytest.raises(RuntimeError,match='populated'):
        module.upgrade()
    assert all(call[0]=='execute' for call in ops.calls)
    assert ops.calls[0][1].startswith('LOCK TABLE ')
    assert ops.calls[0][1].count('identity.')==3
    assert not any('CREATE FUNCTION' in call[1] for call in ops.calls)


def test_frozen_migration_matches_encrypted_model_coverage_and_chain():
    module=migration();ops=RecordingOps()
    with patch.object(module,'op',ops):module.upgrade()
    assert module.down_revision=='e17a5c39df62'
    assert module.revision=='f28b6d40ea73'
    assert ops.guards==3
    for table in module.SPEC:
        names={call[1][1].name for call in ops.calls if call[0]=='add_column' and call[1][0]==table}
        assert names=={'profile_payload_ciphertext','encryption_key_version'}
        rules={call[1][0] for call in ops.calls if call[0]=='create_check_constraint' and call[1][1]==table}
        expected={c.name for c in Base.metadata.tables['identity.'+table].constraints if isinstance(c,CheckConstraint) and any(c.name.endswith(suffix) for suffix in ('family_payload_present','family_key_present','family_dates_protected'))}
        assert rules==expected
    sql='\n'.join(call[1] for call in ops.calls if call[0]=='execute')
    assert 'r.officer_uid = NEW.officer_uid' in sql
    assert 'protect_family_delete' in sql and 'protect_family_truncate' in sql
    assert 'GRANT UPDATE' not in sql


def test_no_automatic_downgrade_can_remove_encrypted_evidence():
    with pytest.raises(RuntimeError,match='preserve encrypted evidence'):migration().downgrade()


@pytest.mark.parametrize('table',list(REMOVED))
def test_checker_fixture_recovers_with_backup_and_rejects_wrong_row_context(tmp_path,table):
    import base64,json
    from uuid import uuid4
    from cryptography.exceptions import InvalidTag
    from app.security.identity_crypto import IdentityCrypto
    path=Path(__file__).resolve().parents[1]/'scripts/check_family_storage.py'
    spec=importlib.util.spec_from_file_location('family_checker_fixture_test',path)
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    key=base64.b64encode(b'e'*32).decode();copies=[]
    for name in ('primary.json','backup.json'):
        key_path=tmp_path/name
        key_path.write_text(json.dumps(dict(active_encryption_key_version='TEST',active_lookup_key_version='TEST',
            encryption_keys={'TEST':key},lookup_keys={'TEST':key})))
        key_path.chmod(0o600);copies.append(IdentityCrypto(key_path))
    row,payload=checker.fixture(table,uuid4(),uuid4(),uuid4(),copies[0])
    for copy in copies:
        assert copy.decrypt_assertion(row['profile_payload_ciphertext'],key_version=row['encryption_key_version'],
            context=checker.context(table,row))==payload
    assert b'Synthetic Relative' not in row['profile_payload_ciphertext']
    changed=dict(row);changed[checker.IDS[table][0]]=uuid4()
    with pytest.raises(InvalidTag):
        copies[0].decrypt_assertion(row['profile_payload_ciphertext'],key_version=row['encryption_key_version'],
            context=checker.context(table,changed))
