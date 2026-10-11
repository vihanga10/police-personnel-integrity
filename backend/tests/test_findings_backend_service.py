"""Real child-pipe protocol tests; worker doubles never submit chain transactions."""
import json
from pathlib import Path
import sys
import base64
from datetime import datetime,timezone,timedelta

import pytest
from app.identity.findings_backend_service import _exchange,_json
from app.identity import findings_backend_service as S
from app.identity import findings_backend_gate as G
from app.identity.protected_commitment import encoded
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from test_findings_backend_gate import gate_fixture,build,prepared,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys


def child(tmp_path,body):
    p=tmp_path/'worker.py'
    p.write_text('import sys,json,time\njob=json.loads(sys.stdin.readline())["job"]\n'+body)
    return [sys.executable,str(p)]


def frame(id=1):
    return dict(kind='guard',id=id,action='ENTRY',selection={'fixture':True},mode='RECONCILE')


def test_real_pipe_guard_then_result(tmp_path):
    command=child(tmp_path,
        'print(json.dumps('+repr(frame())+'),flush=True)\n'
        'reply=json.loads(sys.stdin.readline())\n'
        'assert reply["kind"]=="approved" and reply["id"]==1\n'
        'print(json.dumps({"kind":"result","result":{"fixture":True}}),flush=True)\n')
    calls=[]
    def guard(action,selection,mode):calls.append((action,mode));return selection
    assert _exchange(command,{},guard,timeout=2)=={'fixture':True}
    assert calls==[('ENTRY','RECONCILE')]


@pytest.mark.parametrize('message',[
    {'kind':'result','result':{}},frame(2),dict(frame(),extra=True),
    {'kind':'error'}, {'kind':'guard','id':True,'action':'ENTRY','selection':{},'mode':'RECONCILE'}])
def test_invalid_or_out_of_order_child_message_stops(tmp_path,message):
    command=child(tmp_path,'print(json.dumps('+repr(message)+'),flush=True)\n')
    with pytest.raises(ValueError):_exchange(command,{},lambda *a:{},timeout=2)


def test_failed_replay_never_sends_approval(tmp_path):
    marker=tmp_path/'approved'
    command=child(tmp_path,'print(json.dumps('+repr(frame())+'),flush=True)\n'
        'reply=sys.stdin.readline()\n'+f'open({str(marker)!r},"w").write(reply)\n')
    def deny(*args):raise ValueError('Permit expired')
    with pytest.raises(ValueError,match='Permit expired'):_exchange(command,{},deny,timeout=2)
    assert not marker.exists()


def test_stalled_child_has_bounded_deadline(tmp_path):
    command=child(tmp_path,'time.sleep(20)\n')
    with pytest.raises(ValueError,match='timed out'):_exchange(command,{},lambda *a:{},timeout=1)


def test_worker_crash_is_not_retried(tmp_path):
    count=tmp_path/'runs'
    command=child(tmp_path,f'open({str(count)!r},"a").write("1")\nsys.exit(4)\n')
    with pytest.raises(ValueError):_exchange(command,{},lambda *a:{},timeout=2)
    assert count.read_text()=='1'


def test_duplicate_or_nonfinite_pipe_json_rejected():
    for text in ('{"kind":"result","kind":"guard"}','{"value":NaN}'):
        with pytest.raises(ValueError):_json(text)


def test_oversized_child_output_is_rejected(tmp_path):
    command=child(tmp_path,'print("x"*1048577,flush=True)\n')
    with pytest.raises(ValueError,match='too large'):_exchange(command,{},lambda *a:{},timeout=2)


def test_trailing_child_data_is_rejected(tmp_path):
    command=child(tmp_path,'print(json.dumps('+repr(frame())+'),flush=True)\n'
        'sys.stdin.readline()\nprint(json.dumps({"kind":"result","result":{}}),flush=True)\nprint("extra",flush=True)\n')
    with pytest.raises(ValueError):_exchange(command,{},lambda *a:{},timeout=2)


@pytest.fixture
def service_fixture(gate_fixture,tmp_path):
    gate=build(gate_fixture);key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
    fmt=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z')
    body=dict(policy=G.POLICY,key_id='backend',mode='EXECUTE',issued_at=fmt(now-timedelta(seconds=1)),
        expires_at=fmt(now+timedelta(seconds=120)),selection=gate.selection)
    grant=dict(body=body,signature=base64.b64encode(key.sign(encoded(body))).decode())
    worker=gate.repo/'blockchain/fabric/client/findings-backend-worker.js';worker.parent.mkdir(parents=True);worker.write_text('// fixture worker double')
    root=tmp_path/'service-retention';root.mkdir(mode=0o700)
    secret=tmp_path/'service-retention.key';secret.write_bytes(b'R'*32);secret.chmod(0o600)
    kwargs=dict(approval=grant,trusted_keys={'backend':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)},
        node_binary=sys.executable,gateway_config_file='/fixture-gateway',witness_config_file='/fixture-witness',
        witness_config_sha256='f'*64,recovery_directory=root,recovery_key_file=secret)
    s=gate.selection
    result=dict(status='FABRIC_COMMIT_VERIFIED',mode='EXECUTE',operation=S.digest_operation(s),
        recovery_witness_transport='MTLS',recovery_witness_fixture=False,both_chains_anchored=False,
        independent_witness_deployment_verified=False,receipt=dict(status='FINAL',payload=s['payload'],destination=s['destination'],
            transaction_id='a'*64,verification=dict(validation_code='VALID',organizations=['Org1MSP','Org2MSP'],block_sha256='b'*64)))
    return gate,kwargs,result,gate_fixture


def test_service_builds_fixed_job_and_rechecks_source_before_return(service_fixture,monkeypatch):
    gate,kwargs,result,fixture=service_fixture;initial=len(fixture['calls'])
    def double(command,job,guard,timeout):
        assert command[1]==str(gate.repo/'blockchain/fabric/client/findings-backend-worker.js')
        assert job['selection']==gate.selection and job['recoveryKeyFile']==str(kwargs['recovery_key_file'])
        assert 'R'*32 not in str(job)
        guard('BEFORE_SUBMIT',job['selection'],job['mode']);return result
    monkeypatch.setattr(S,'_exchange',double)
    value=S.run_fabric(gate,**kwargs)
    assert value['backend_gate']=='FULL_REPLAY_AND_WITNESSED_FINDINGS'
    assert value['public_transport_enabled'] is value['live_research_ready'] is False
    assert len(fixture['calls'])==initial+3


@pytest.mark.parametrize('fault',['fixture','public-claim','payload','validation','mode'])
def test_service_rejects_misbound_worker_result(service_fixture,monkeypatch,fault):
    gate,kwargs,result,_=service_fixture
    if fault=='fixture':result['recovery_witness_fixture']=True
    elif fault=='public-claim':result['both_chains_anchored']=True
    elif fault=='payload':result['receipt']['payload']={}
    elif fault=='validation':result['receipt']['verification']['validation_code']='INVALID'
    else:result['mode']='RECONCILE'
    monkeypatch.setattr(S,'_exchange',lambda *args,**kw:result)
    with pytest.raises(ValueError):S.run_fabric(gate,**kwargs)


def test_recovery_key_change_during_worker_blocks_guard(service_fixture,monkeypatch):
    gate,kwargs,result,_=service_fixture
    def double(command,job,guard,timeout):
        kwargs['recovery_key_file'].write_bytes(b'S'*32)
        guard('BEFORE_SUBMIT',job['selection'],job['mode']);return result
    monkeypatch.setattr(S,'_exchange',double)
    with pytest.raises(ValueError,match='recovery key changed'):S.run_fabric(gate,**kwargs)
