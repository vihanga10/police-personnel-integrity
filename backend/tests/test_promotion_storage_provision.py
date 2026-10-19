"""Provisioning failure tests use an explicit command simulator, not a live Mongo server."""
from copy import deepcopy
import pytest
from app.intake.promotion_pipeline import provision_storage as P
from app.intake.promotion_pipeline.core import IntakeError

class Collection:
    def list_indexes(self):return [{'name':'_id_','key':{'_id':1}}]
class Database:
    name=P.DATABASE
    def __init__(self):self.collection=None;self.role=None;self.user=None;self.calls=[];self.fail=None;self.after=False
    def list_collections(self,filter):return [] if self.collection is None else [deepcopy(self.collection)]
    def create_collection(self,name,**options):
        self.calls.append('collection')
        if self.fail=='collection' and not self.after:raise ConnectionError()
        self.collection={'name':name,'type':'collection','options':deepcopy(options)}
        if self.fail=='collection':raise ConnectionError()
    def __getitem__(self,name):assert name==P.COLLECTION;return Collection()
    def command(self,command,value,**options):
        if command=='rolesInfo':return {'roles':[] if self.role is None else [deepcopy(self.role)]}
        if command=='usersInfo':return {'users':[] if self.user is None else [deepcopy(self.user)]}
        step='role' if command=='createRole' else 'user';self.calls.append(step)
        if self.fail==step and not self.after:raise ConnectionError()
        if step=='role':self.role={'role':value,'roles':options['roles'],'privileges':deepcopy(options['privileges'])}
        else:self.user={'user':value,'roles':deepcopy(options['roles'])}
        if self.fail==step:raise ConnectionError()
        return {'ok':1}

@pytest.fixture
def env(tmp_path):
    root=tmp_path/'setup';root.mkdir(mode=0o700);return Database(),root

def run(db,root):return P.mongo(db,'a'*48,root,authenticate=lambda password:None)

def test_setup_creates_only_dedicated_destination_and_exact_least_privilege(env):
    db,root=env;assert run(db,root)['status']=='PROMOTION_MONGO_DESTINATION_VERIFIED'
    assert db.calls==['collection','role','user'];assert db.role['privileges']==P.PRIVILEGES
    run(db,root);assert db.calls==['collection','role','user']

@pytest.mark.parametrize('phase',['collection','role','user'])
def test_lost_setup_ack_reconciles_existing_object_without_repeating_command(env,phase):
    db,root=env;db.fail=phase;db.after=True
    with pytest.raises(ConnectionError):run(db,root)
    before=list(db.calls);db.fail=None;run(db,root)
    assert db.calls.count(phase)==1 and db.calls[:len(before)]==before

@pytest.mark.parametrize('phase',['collection','role','user'])
def test_uncertain_absent_object_does_not_automatically_repeat_creation(env,phase):
    db,root=env;db.fail=phase
    with pytest.raises(ConnectionError):run(db,root)
    db.fail=None;before=list(db.calls)
    with pytest.raises(IntakeError,match='MONGO_SETUP_UNCERTAIN_RECONCILE_REQUIRED'):run(db,root)
    assert db.calls==before

def test_preexisting_foreign_destination_is_not_adopted(env):
    db,root=env;db.collection={'name':P.COLLECTION,'type':'collection','options':P.OPTIONS}
    with pytest.raises(IntakeError,match='MONGO_DESTINATION_ALREADY_EXISTS'):run(db,root)
    assert db.calls==[]

def test_changed_destination_validator_or_role_is_not_silently_fixed(env):
    db,root=env;run(db,root);db.role['privileges'][0]['actions'].append('remove')
    with pytest.raises(IntakeError,match='MONGO_WRITER_ROLE_DIFFERS'):run(db,root)
    assert db.calls==['collection','role','user']

def test_matching_user_record_does_not_replace_password_authentication(env):
    db,root=env;run(db,root)
    def denied(password):raise PermissionError()
    with pytest.raises(PermissionError):P.mongo(db,'b'*48,root,authenticate=denied)
    assert db.calls==['collection','role','user']
