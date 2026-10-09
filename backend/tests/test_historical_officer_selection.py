"""Made-up identifiers and fake SQL connections; no real officer or database input."""
from copy import deepcopy
from datetime import date
import warnings
from uuid import uuid4
import pytest
import app.identity.historical_officer_selection as S
from app.identity.reconstruct_history import arguments
from test_protected_commitment import identity_crypto


@pytest.fixture
def selected(tmp_path,monkeypatch):
    # Never use an actual NIC in fixture output or version-controlled test data.
    nic='fixture-nic-only'; officer=str(uuid4()); crypto=identity_crypto(tmp_path)
    manifest=dict(bundles=[dict(officer_uid=officer)])
    raw='a'*64
    catalog={raw:dict(filename='officer_personal_information.csv',raw_record_id=raw,
        original=dict(columns=['officer_nic_no'],values=[nic]),classification='UNASSESSED',
        delivery=dict(complete=True),candidate_links=[dict(officer_uid=officer,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')])}
    calls=[]
    def verified(connection,primary,backup,value,cache):
        calls.append((connection,value))
        return 'EXACT_EVIDENCE_CANDIDATE',officer
    monkeypatch.setattr(S,'inspected_link',verified)
    return nic,officer,crypto,manifest,catalog,calls


def test_exact_candidate_requires_live_verifier_and_anchored_profile(selected):
    nic,officer,crypto,manifest,catalog,calls=selected
    result=S.select_candidate('read-only',crypto,crypto,nic,manifest,catalog)
    assert result.officer_uid==officer and result.profile_raw_ids==('a'*64,)
    assert result.historical_identity=='UNASSESSED' and result.linkage_accepted is False
    assert calls==[('read-only',nic)]
    assert nic not in repr(result) and officer not in repr(result)
    assert nic not in result.__dict__.values()


@pytest.mark.parametrize('state', ['NO_CANDIDATE_FOUND','MULTIPLE_CANDIDATES','NO_USABLE_NIC_EVIDENCE','UNUSABLE_NIC'])
def test_no_ambiguous_or_unusable_live_candidate_can_select(selected,monkeypatch,state):
    nic,officer,crypto,manifest,catalog,_=selected
    monkeypatch.setattr(S,'inspected_link',lambda *args:(state,None))
    with pytest.raises(ValueError):S.select_candidate(None,crypto,crypto,nic,manifest,catalog)


@pytest.mark.parametrize('change',['officer','NIC','missing_profile','duplicate_profile','multiple_links',
    'accepted_link','classification','delivery','raw_id','columns','outside_universe'])
def test_anchored_and_live_selection_must_agree(selected,change):
    nic,officer,crypto,manifest,catalog,_=selected
    manifest,catalog=deepcopy(manifest),deepcopy(catalog)
    row=catalog['a'*64]
    if change=='officer':row['candidate_links'][0]['officer_uid']=str(uuid4())
    elif change=='NIC':row['original']['values'][0]='different-fixture'
    elif change=='missing_profile':row['filename']='operations.csv'
    elif change=='duplicate_profile':
        catalog['b'*64]=deepcopy(row);catalog['b'*64]['raw_record_id']='b'*64
    elif change=='multiple_links':row['candidate_links'].append(deepcopy(row['candidate_links'][0]))
    elif change=='accepted_link':row['candidate_links'][0]['state']='ACCEPTED'
    elif change=='classification':row['classification']='PUBLIC'
    elif change=='delivery':row['delivery']['complete']=False
    elif change=='raw_id':row['raw_record_id']='changed'
    elif change=='columns':row['original']['columns'].append('officer_nic_no');row['original']['values'].append(nic)
    elif change=='outside_universe':manifest['bundles']=[]
    with pytest.raises(ValueError):S.select_candidate(None,crypto,crypto,nic,manifest,catalog)


def test_trim_is_allowed_but_case_and_format_aliases_are_not_guessed(selected):
    nic,officer,crypto,manifest,catalog,_=selected
    assert S.select_candidate(None,crypto,crypto,' '+nic+' ',manifest,catalog).officer_uid==officer
    with pytest.raises(ValueError):S.select_candidate(None,crypto,crypto,nic.upper(),manifest,catalog)


@pytest.mark.parametrize('bad',[None,123,'','a'*65,'x\x00y'])
def test_invalid_nic_is_refused_without_verifier_calls(selected,bad):
    _,_,crypto,manifest,catalog,calls=selected
    with pytest.raises(ValueError):S.select_candidate(None,crypto,crypto,bad,manifest,catalog)
    assert not calls


def test_hidden_prompt_normalizes_without_echo(monkeypatch,capsys):
    prompts=[]
    monkeypatch.setattr(S.getpass,'getpass',lambda prompt:(prompts.append(prompt) or ' fixture-nic-only '))
    assert S.read_private_nic()=='fixture-nic-only'
    assert 'hidden' in prompts[0] and 'fixture-nic-only' not in capsys.readouterr().out


def test_echoing_fallback_is_refused_before_reading(monkeypatch):
    called=[]
    def fallback(prompt):
        warnings.warn('Cannot disable terminal echo',S.getpass.GetPassWarning)
        called.append(True)
        return 'should-not-be-read'
    monkeypatch.setattr(S.getpass,'getpass',fallback)
    with pytest.raises(S.getpass.GetPassWarning):S.read_private_nic()
    assert not called


class Connection:
    def __init__(self,identity=('police_identity_app','police_identity')):
        self.calls=[];self.identity=identity
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def begin(self):return self
    def execute(self,statement):self.calls.append(str(statement));return self
    def one(self):return self.identity


class Engine:
    def __init__(self,connection):self.connection=connection;self.disposed=False
    def connect(self):return self.connection
    def dispose(self):self.disposed=True


def setup_sql(monkeypatch,identity=('police_identity_app','police_identity')):
    from types import SimpleNamespace
    settings=SimpleNamespace(host='127.0.0.1',port=5432,name='police_identity',user='police_identity_app')
    monkeypatch.setattr(S,'Settings',lambda:settings)
    connection=Connection(identity);engine=Engine(connection)
    monkeypatch.setattr(S,'create_identity_engine',lambda config:engine)
    return settings,connection,engine


def test_sql_is_read_only_and_disposed_after_selection(selected,monkeypatch):
    nic,officer,crypto,manifest,catalog,_=selected
    _,connection,engine=setup_sql(monkeypatch)
    result=S.select_from_sql(crypto,crypto,nic,manifest,catalog)
    assert result.officer_uid==officer and engine.disposed
    assert connection.calls==['SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY',
        'SELECT current_user, current_database()']


@pytest.mark.parametrize('identity',[('admin','police_identity'),('police_identity_app','other')])
def test_unexpected_sql_identity_stops_before_candidate_lookup(selected,monkeypatch,identity):
    nic,_,crypto,manifest,catalog,calls=selected
    _,_,engine=setup_sql(monkeypatch,identity)
    with pytest.raises(ValueError):S.select_from_sql(crypto,crypto,nic,manifest,catalog)
    assert engine.disposed and not calls


def test_wrong_target_stops_before_opening_engine(selected,monkeypatch):
    nic,_,crypto,manifest,catalog,_=selected
    settings,connection,engine=setup_sql(monkeypatch);settings.user='admin'
    with pytest.raises(ValueError):S.select_from_sql(crypto,crypto,nic,manifest,catalog)
    assert not connection.calls


def test_verifier_failure_preserves_failure_and_disposes_engine(selected,monkeypatch):
    nic,_,crypto,manifest,catalog,_=selected
    _,_,engine=setup_sql(monkeypatch)
    def fail(*args):raise ValueError('Private evidence failed')
    monkeypatch.setattr(S,'inspected_link',fail)
    with pytest.raises(ValueError):S.select_from_sql(crypto,crypto,nic,manifest,catalog)
    assert engine.disposed


def test_cli_selection_flag_keeps_dates_selectable_and_refuses_nic_argument():
    names=['key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','audit-gate-attempt','output-root']
    paths=[part for name in names for part in ['--'+name,'/private/'+name]]
    for query in ['2024-12-31','2020-01-01']:
        args=arguments(paths+['--select-nic','--on',query])
        assert args.select_nic and args.on==date.fromisoformat(query)
    assert not arguments(paths+['--on','2024-12-31']).select_nic
    with pytest.raises(SystemExit):arguments(paths+['--on','2024-12-31','--nic','never-accept-this'])


@pytest.mark.parametrize('expire_at_prompt',[False,True])
def test_runner_selects_only_one_and_encrypts_selection_details(tmp_path,monkeypatch,capsys,expire_at_prompt):
    """Verify CLI control flow and private output; commitment primitives have separate tests."""
    import hashlib,json
    from types import SimpleNamespace
    import app.identity.reconstruct_history as R
    from app.identity.evidence_bundle_v2 import open_artifact
    crypto=identity_crypto(tmp_path)
    officer=str(uuid4())
    others=[str(uuid4()) for _ in range(6595)]
    manifest=dict(bundles=[dict(officer_uid=o) for o in [officer,*others]],
        snapshot=dict(collection_started_at='2026-10-09T04:00:00+00:00'))
    roots={name:tmp_path/name for name in ['bundle','binding','commitment','gate']}
    for p in roots.values():p.mkdir()
    (roots['binding']/'destination-bindings.encrypted.json').write_text('{}')
    public={'fixture':'not-research'};(roots['commitment']/'public-commitments.json').write_text(json.dumps(public))
    (roots['commitment']/'commitments.encrypted.json').write_text('{"binding":{}}')
    (roots['gate']/'audit-permit.encrypted.json').write_text('{}')
    key=tmp_path/'primary';backup=tmp_path/'backup';key.write_text('fixture');backup.write_text('fixture')
    paths=['--key-file',str(key),'--backup-key-file',str(backup),
        '--commitment-key-file',str(tmp_path/'commitkey'),'--backup-commitment-key-file',str(tmp_path/'commitbackup'),
        '--bundle-attempt',str(roots['bundle']),'--binding-attempt',str(roots['binding']),
        '--commitment-attempt',str(roots['commitment']),'--audit-gate-attempt',str(roots['gate']),
        '--output-root',str(tmp_path/'out'),'--select-nic','--on','2024-12-31']
    # Isolate orchestration from external stores. No fixture pretends to be a chain proof.
    monkeypatch.setattr(R.subprocess,'check_output',lambda cmd,**kw:'' if 'status' in cmd else 'a'*40)
    monkeypatch.setattr(R,'private_path',lambda p,*args:p)
    monkeypatch.setattr(R,'private_key_file',lambda p:crypto)
    monkeypatch.setattr(R,'load_keys',lambda *args:SimpleNamespace(assert_separate=lambda c:None))
    monkeypatch.setattr(R,'PUBLIC_SHA',R.digest(public))
    permit_checks=[];prompt_finished=[]
    def check(*args,**kw):
        permit_checks.append(True)
        if expire_at_prompt and prompt_finished:
            raise ValueError('Expired fixture permit')
    monkeypatch.setattr(R,'require_audit_permit',check)
    monkeypatch.setattr(R,'load_attempt',lambda *args:(manifest,{}))
    sha=hashlib.sha256(b'{}').hexdigest()
    monkeypatch.setattr(R,'load_binding',lambda *args:({'raw_bindings':{}},sha))
    monkeypatch.setattr(R,'open_artifact',lambda *args:dict(context=dict(generator_revision='b'*40)))
    generator_calls=[]
    def generate(*args,**kw):
        generator_calls.append((len(args[0]['bundles']),kw['generator_revision']))
        return public,dict(context=dict(generator_revision='b'*40))
    monkeypatch.setattr(R,'generate',generate)
    verified=[];monkeypatch.setattr(R,'verify_saved',lambda *args:verified.append(True))
    def read_nic():
        prompt_finished.append(True)
        return 'never-print-fixture-nic'
    monkeypatch.setattr(R,'read_private_nic',read_nic)
    selected=[]
    def lookup(*args):
        selected.append(len(args[3]['bundles']))
        return S.Selection(officer,('a'*64,))
    monkeypatch.setattr(R,'select_from_sql',lookup)
    assert R.main(paths)==(1 if expire_at_prompt else 0)
    if expire_at_prompt:
        assert not selected and not (tmp_path/'out').exists()
        assert 'never-print-fixture-nic' not in capsys.readouterr().out
        return
    captured=capsys.readouterr().out
    assert officer not in captured and 'never-print-fixture-nic' not in captured
    assert generator_calls==[(6596,'b'*40)] and verified and selected==[6596]
    outputs=list((tmp_path/'out').iterdir());assert len(outputs)==1
    summary=json.loads((outputs[0]/'PASSED.json').read_text())
    assert summary['officers']==1 and summary['encrypted_artifacts']==1
    assert summary['selection_mode']=='SINGLE_NIC_CANDIDATE'
    assert officer not in json.dumps(summary)
    env=json.loads((outputs[0]/'history-000.encrypted.json').read_text())
    payload=open_artifact(crypto,env,env['binding'])
    assert payload['selection']['officer_uid']==officer
    assert len(payload['results'])==1 and payload['results'][0]['officer_uid']==officer
    assert payload['on']=='2024-12-31'
    assert len(permit_checks)>=7
