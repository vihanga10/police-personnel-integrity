"""Isolated protected capture fixtures; no research execution or deployment."""
from copy import deepcopy
from datetime import date
from uuid import UUID
import pytest
from app.identity import protected_findings_capture as C
from app.identity import observed_recording_journal as J
from test_findings_tip_witness import witnessed_findings,registered,journal,output,witnessed,setup,verified,keys,OP,ID,OFFICER,advance,authorize,inventory


def capture(d,**changes):
    t=d['t']['d']['t'];s=t['s']
    args=dict(officer_uid=OFFICER,effective_on=date(2024,12,31),known_at=s['clock'][0],
        operation_id=OP,finding_id=ID,destination=d['t']['d']['output'].parent/'capture.json')
    args.update(changes)
    return C.capture_loaded(s['snapshot'],s['repo'],t['adapter'],d['adapter'],**args)


def test_capture_is_encrypted_witnessed_and_idempotent(witnessed_findings):
    d=witnessed_findings
    assert capture(d)['status']=='CAPTURED'
    before=inventory(d)
    assert capture(d)['status']=='ALREADY_CAPTURED' and inventory(d)==before
    selected=d['adapter'].select()
    assert selected['registry_tip']['sequence']==1
    assert selected['entries'][0]['entry']['kind']=='FINDING'
    assert OFFICER not in str(capture(d))


@pytest.mark.parametrize('change',[{'officer_uid':str(UUID(int=999))},{'operation_id':'bad'},
    {'finding_id':'bad'},{'effective_on':'2024-12-31'},{'known_at':'2024-12-31'},
    {'reason':'unbound'},{'supersedes':'bad','reason':'correction'}])
def test_invalid_request_publishes_no_finding(witnessed_findings,change):
    d=witnessed_findings;before=inventory(d)
    with pytest.raises(Exception):capture(d,**change)
    assert inventory(d)==before


@pytest.mark.parametrize('field',['finding_id','effective_on','known_at','operation_id'])
def test_changed_retry_cannot_adopt_existing_receipt(witnessed_findings,field):
    d=witnessed_findings;capture(d);before=inventory(d)
    values=dict(finding_id=str(UUID(int=800)),effective_on=date(2024,12,30),
        known_at=d['t']['d']['t']['s']['clock'][0].replace(year=2023),operation_id=str(UUID(int=801)))
    with pytest.raises(Exception):capture(d,**{field:values[field]})
    assert inventory(d)==before


def test_preexisting_receipt_without_intent_refused(witnessed_findings):
    d=witnessed_findings
    with pytest.raises(Exception):capture(d,destination=d['t']['d']['output'])
    assert d['adapter'].select()['entries']==[]


def test_producer_interruption_can_retry_signed_intent(witnessed_findings,monkeypatch):
    d=witnessed_findings;original=C.P.run_loaded_comparison
    def fail(*a,**k):raise RuntimeError('fixture interrupted producer')
    monkeypatch.setattr(C.P,'run_loaded_comparison',fail)
    with pytest.raises(RuntimeError):capture(d)
    assert d['adapter'].select()['entries']==[]
    monkeypatch.setattr(C.P,'run_loaded_comparison',original)
    assert capture(d)['status']=='CAPTURED'


def test_changed_findings_predecessor_blocks_pending_intent(witnessed_findings,monkeypatch):
    d=witnessed_findings;original=C.P.run_loaded_comparison
    monkeypatch.setattr(C.P,'run_loaded_comparison',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('stop')))
    with pytest.raises(RuntimeError):capture(d)
    monkeypatch.setattr(C.P,'run_loaded_comparison',original)
    d['adapter'].append_receipt(operation_id=str(UUID(int=700)),finding_id=str(UUID(int=701)),receipt_path=d['t']['d']['output'])
    before=inventory(d)
    with pytest.raises(Exception):capture(d)
    assert inventory(d)==before


@pytest.mark.parametrize('kind',['source','permit','receipt','witness'])
def test_last_publication_guard_blocks_changed_state(witnessed_findings,monkeypatch,kind):
    d=witnessed_findings;s=d['t']['d']['t']['s'];original=J._publish
    def intercepted(path,*a,**k):
        if path.parent==d['t']['d']['ledger'].root:
            if kind=='source':s['snapshot']['catalog']['fixture-new']={}
            elif kind=='permit':monkeypatch.setattr(C.AlgorithmPermit,'check',lambda *a,**k:(_ for _ in ()).throw(ValueError('expired')))
            elif kind=='receipt':(d['t']['d']['output'].parent/'capture.json').write_text('{}')
            else:d['client'].exchange=lambda *a,**k:(_ for _ in ()).throw(ConnectionError('outage'))
        return original(path,*a,**k)
    monkeypatch.setattr(J,'_publish',intercepted)
    with pytest.raises(Exception):capture(d)
    assert not list(d['t']['d']['ledger'].root.glob('entry-*.encrypted.json'))


def test_public_entry_refuses_fixture_transport(witnessed_findings):
    d=witnessed_findings;t=d['t']['d']['t'];s=t['s']
    with pytest.raises(Exception):C.capture_contradictions(None,s['repo'],'fixture',t['adapter'],d['adapter'])
    assert d['adapter'].select()['entries']==[]


def test_correction_preserves_original_and_exact_lineage(witnessed_findings):
    d=witnessed_findings;known=d['t']['d']['t']['s']['clock'][0];capture(d);first=d['adapter'].select();advance(d['t']['d'])
    args=dict(known_at=known,operation_id=str(UUID(int=600)),supersedes=first['journal_tip']['entry_sha256'],
        reason='fixture corrected interpretation',destination=d['t']['d']['output'].parent/'correction.json')
    assert capture(d,**args)['status']=='CAPTURED'
    entries=d['adapter'].select()['entries']
    assert len(entries)==2 and entries[0]==first['entries'][0]
    assert entries[1]['entry']['supersedes']==first['journal_tip']['entry_sha256']
    assert entries[1]['entry']['kind']=='CORRECTION'


@pytest.mark.parametrize('lost_after_commit',[True,False])
def test_witness_interruption_requires_authenticated_resolution(witnessed_findings,lost_after_commit):
    from hashlib import sha256
    d=witnessed_findings;original=d['client'].exchange
    def fail(receipt):
        if receipt['payload']['operation']=='CAS':
            if lost_after_commit:original(receipt)
            raise OSError('fixture acknowledgement interrupted')
        return original(receipt)
    d['client'].exchange=fail
    with pytest.raises(OSError):capture(d)
    d['client'].exchange=original
    if not lost_after_commit:
        with pytest.raises(ValueError):capture(d)
        r=d['t']['r'];j=d['t']['d']['ledger']
        rt=r._tip(1,sha256((r.root/'entry-00000001.encrypted.json').read_bytes()).hexdigest())
        jt=j._tip(1,sha256((j.root/'entry-00000001.encrypted.json').read_bytes()).hexdigest())
        d['adapter'].recover(authorize(d,jt,pending_registry_tip=rt))
    before=inventory(d)
    assert capture(d)['status']=='ALREADY_CAPTURED' and inventory(d)==before


def test_intent_tampering_refused(witnessed_findings,monkeypatch):
    d=witnessed_findings;original=C.P.run_loaded_comparison
    monkeypatch.setattr(C.P,'run_loaded_comparison',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('stop')))
    with pytest.raises(RuntimeError):capture(d)
    path=d['t']['d']['output'].parent/'capture.json.capture-intent.encrypted.json'
    path.write_bytes(path.read_bytes()[:-10]+b'XXXXXXXXXX')
    monkeypatch.setattr(C.P,'run_loaded_comparison',original)
    with pytest.raises(Exception):capture(d)
    assert d['adapter'].select()['entries']==[]


from test_witness_secure_transport import secured,wire_client,certs,listener

def test_public_full_loader_and_both_actual_mutual_tls_witnesses(witnessed_findings,secured,tmp_path,monkeypatch):
    import socket
    from app.identity import findings_tip_witness as A,recording_tip_witness as W,witness_secure_transport as T
    from app.identity import algorithm_snapshot
    d=witnessed_findings;r=d['t']['r'];t=d['t']['d']['t'];s=t['s']
    assert secured['t'] is t
    pki=certs(tmp_path/'capture-pki',J._now());control=tmp_path/'capture-control';control.mkdir(mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    profile=control/'profile.json'
    pin=T.provision(d['server'],profile_path=profile,endpoint=f'https://127.0.0.1:{port}'+T.PATH,
        ca_certificate=pki['ca'],server_certificate=pki['server'],server_key=pki['server_key'],
        client_certificates={r.key_id:pki['client']})
    server_args=dict(profile_path=profile,expected_profile_sha256=pin,ca_certificate=pki['ca'],
        server_certificate=pki['server'],server_key=pki['server_key'])
    transport_args=dict(profile_path=profile,expected_profile_sha256=pin,witness_keys=d['args']['witness_keys'],
        repo=s['repo'],ca_certificate=pki['ca'],client_certificate=pki['client'],client_key=pki['client_key'])
    calls=[]
    def loader(*args):calls.append(args);return s['snapshot']
    monkeypatch.setattr(algorithm_snapshot,'load_verified_snapshot',loader)
    with listener(secured),listener(dict(port=port,t={'server':d['server']},server_args=server_args)):
        recording=W.WitnessedCheckpointRegistry(t['adapter'].registry,wire_client(secured))
        findings=A.WitnessedFindingsRegistry(r,W.WitnessClient(**d['client_args'],exchange=T.HTTPSWitnessTransport(**transport_args)))
        result=C.capture_contradictions('fixture-args',s['repo'],'fixture-revision',recording,findings,
            officer_uid=OFFICER,effective_on=date(2024,12,31),known_at=s['clock'][0],
            operation_id=OP,finding_id=ID,destination=d['t']['d']['output'].parent/'public.json')
        assert result['status']=='CAPTURED' and len(calls)==1
        assert findings.select()['registry_tip']['sequence']==1


def test_new_recording_prefix_preserves_earlier_knowledge_capture(witnessed_findings,monkeypatch):
    from test_protected_contradiction_runner import next_checkpoint
    d=witnessed_findings;t=d['t']['d']['t'];known=t['s']['clock'][0]
    original=C.P.run_loaded_comparison
    def interrupted(*a,**k):original(*a,**k);raise RuntimeError('receipt complete; capture interrupted')
    monkeypatch.setattr(C.P,'run_loaded_comparison',interrupted)
    with pytest.raises(RuntimeError):capture(d,known_at=known)
    monkeypatch.setattr(C.P,'run_loaded_comparison',original)
    pin=next_checkpoint(t);t['adapter'].register(checkpoint_file=pin['checkpoint_file'],checkpoint_sha256=pin['checkpoint_sha256'])
    assert capture(d,known_at=known)['status']=='CAPTURED'


def test_stale_correction_head_never_branches(witnessed_findings):
    d=witnessed_findings;known=d['t']['d']['t']['s']['clock'][0];capture(d)
    old=d['adapter'].select()['journal_tip']['entry_sha256'];advance(d['t']['d'])
    capture(d,known_at=known,operation_id=str(UUID(int=610)),destination=d['t']['d']['output'].parent/'first-correction.json',
        supersedes=old,reason='first correction')
    advance(d['t']['d'])
    with pytest.raises(ValueError):capture(d,known_at=known,operation_id=str(UUID(int=611)),
        destination=d['t']['d']['output'].parent/'stale-correction.json',supersedes=old,reason='stale correction')
    assert len(d['adapter'].select()['entries'])==2
