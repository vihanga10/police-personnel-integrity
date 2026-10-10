"""Simulated ledger tests: no Fabric network, RPC, wallet or blockchain writes."""
from copy import deepcopy
from datetime import timedelta
import base64
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.identity import controlled_findings_anchoring as A
from app.identity import findings_commitments as C
from app.identity.protected_commitment import digest,encoded
from test_findings_commitments import prepared,prepare,recovered,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys,OP,ID,OFFICER,advance,inventory


class Ledger:
    fixture_transport=True
    def __init__(self,name,destination):
        self.name=name;self.destination=deepcopy(destination);self.plans=[];self.calls=[];self.records={}
        self.fail_after_submit=False;self.pending=False;self.prepare_hook=lambda:None
        self.observe_hook=lambda value:value
    def inspect(self,destination):return deepcopy(self.destination)
    def prepare(self,operation,payload,destination):
        self.prepare_hook()
        plan=dict(operation=operation,payload_sha256=digest(payload),destination=deepcopy(destination),
            transaction_id=digest([self.name,operation,payload]),transaction=json.dumps([self.name,operation,payload]))
        self.plans.append(deepcopy(plan));return plan
    def submit(self,plan,payload,destination):
        assert plan in self.plans and plan['payload_sha256']==digest(payload)
        self.calls.append(deepcopy(plan))
        verification=(dict(validation_code='VALID',organizations=['Org1MSP','Org2MSP'],block_sha256='b'*64)
            if self.name=='fabric' else dict(execution_status=1,finalized=True,independent_readback=True,block_sha256='c'*64))
        self.records[plan['transaction_id']]=dict(status='FINAL',destination=deepcopy(destination),payload=deepcopy(payload),
            transaction_id=plan['transaction_id'],verification=verification)
        if self.fail_after_submit:raise RuntimeError('Simulated acknowledgement loss')
    def observe(self,plan,payload,destination):
        if self.pending:return {'status':'PENDING'}
        return self.observe_hook(deepcopy(self.records.get(plan['transaction_id'],{'status':'ABSENT'})))


@pytest.fixture
def pipeline(prepared,tmp_path):
    t=prepared;r=prepare(t);t['pin']=r['private_artifact_sha256'];t['public_pin']=r['public_sha256']
    root=tmp_path/'anchor-recovery';root.mkdir(mode=0o700);t['anchor_root']=root
    dest=dict(fabric=dict(genesis_sha256='a'*64,channel='personnel',chaincode='findings-test-v1',namespace=A.NAMESPACE,
        organizations=['Org1MSP','Org2MSP']),public=dict(chain_id=11155111,contract='0x'+'1'*40,runtime_sha256='2'*64,
        writer='0x'+'3'*40,namespace=A.NAMESPACE,finality='FINALIZED'))
    t['selection']=dict(private_sha256=t['pin'],public_sha256=t['public_pin'],history_sha256=digest(recovered(t)['history']),
        code_revision=t['s']['snapshot']['context']['code_revision'],destinations=dest)
    t['signer']=Ed25519PrivateKey.generate();t['trust']={'approver':t['signer'].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)}
    t['fabric']=Ledger('fabric',dest['fabric']);t['public']=Ledger('public',dest['public'])
    t['approval']=approve(t);return t


def approve(t,mode='EXECUTE',**updates):
    now=t['s']['clock'][0]
    body=dict(policy=A.POLICY,key_id='approver',mode=mode,issued_at=now.isoformat(),
        expires_at=(now+timedelta(seconds=120)).isoformat(),selection=deepcopy(t['selection']))
    body.update(updates)
    return dict(body=body,signature=base64.b64encode(t['signer'].sign(encoded(body))).decode())


def run(t,**updates):
    args=dict(commitment_directory=t['root'],expected_private_sha256=t['pin'],expected_public_sha256=t['public_pin'],
        approval=t['approval'],trusted_keys=t['trust'],fabric=t['fabric'],public=t['public'],directory=t['anchor_root'])
    args.update(updates)
    return A.run_isolated(t['s']['snapshot'],t['s']['repo'],t['d']['adapter'],t['keys'],t['backup'],**args)


def files(t):return {p.name:p.read_bytes() for p in t['anchor_root'].iterdir()}


def test_complete_private_first_and_exact_public_link(pipeline):
    t=pipeline;before=inventory(t['d']);result=run(t)
    assert result['status']=='ISOLATED_BOTH_VERIFIED' and not result['findings_anchored'] and not result['live_chain_verification']
    assert result['accepted_state'] is None and inventory(t['d'])==before
    assert len(t['fabric'].calls)==len(t['public'].calls)==1
    receipt=next(iter(t['fabric'].records.values()));payload=next(iter(t['public'].records.values()))['payload']
    assert payload['fabric_transaction_id']==receipt['transaction_id'] and payload['fabric_receipt_sha256']==digest(receipt)
    assert payload['merkle_root']==recovered(t)['public']['merkle_root']
    assert len(files(t))==5 and all(p.stat().st_mode&0o777==0o600 for p in t['anchor_root'].iterdir())
    for adapter in (t['fabric'],t['public']):
        text=json.dumps(adapter.records)
        for secret in (OFFICER,ID,OP,'recorded_at','NEEDS_MORE_EVIDENCE'):assert secret not in text


def test_exact_retry_and_read_only_reconciliation(pipeline):
    t=pipeline;run(t);before=files(t);assert run(t)['status']=='ISOLATED_BOTH_VERIFIED'
    result=run(t,mode='RECONCILE',approval=approve(t,'RECONCILE'))
    assert not result['latest_history_checked'] and files(t)==before
    assert len(t['fabric'].calls)==len(t['public'].calls)==1


@pytest.mark.parametrize('name',['fabric','public'])
def test_acknowledgement_loss_reconciles_original_transaction(pipeline,name):
    t=pipeline;adapter=t[name];adapter.fail_after_submit=True
    with pytest.raises(RuntimeError):run(t)
    assert len(adapter.plans)==len(adapter.calls)==1
    before=files(t);adapter.fail_after_submit=False;run(t)
    assert len(adapter.plans)==len(adapter.calls)==1
    assert all(files(t)[k]==v for k,v in before.items())


def test_pending_stops_without_public_submission_or_new_identity(pipeline):
    t=pipeline;t['fabric'].pending=True
    with pytest.raises(ValueError):run(t)
    with pytest.raises(ValueError):run(t)
    assert len(t['fabric'].plans)==1 and not t['fabric'].calls and not t['public'].plans
    t['fabric'].pending=False;run(t);assert len(t['fabric'].plans)==1


@pytest.mark.parametrize('field',['private_sha256','public_sha256','history_sha256','code_revision'])
def test_wrong_signed_selection_blocks_before_plan(pipeline,field):
    t=pipeline;selection=deepcopy(t['selection']);selection[field]='f'*len(selection[field])
    with pytest.raises(ValueError):run(t,approval=approve(t,selection=selection))
    assert not files(t) and not t['fabric'].plans


@pytest.mark.parametrize('mutation',['signature','trust','expired','future','long','mode'])
def test_approval_authentication_and_time(pipeline,mutation):
    t=pipeline;a=deepcopy(t['approval']);trust=t['trust']
    now=t['s']['clock'][0]
    if mutation=='signature':a['signature']=base64.b64encode(b'x'*64).decode()
    elif mutation=='trust':trust={}
    elif mutation=='expired':a=approve(t,issued_at=(now-timedelta(seconds=60)).isoformat(),expires_at=now.isoformat())
    elif mutation=='future':a=approve(t,issued_at=(now+timedelta(seconds=1)).isoformat())
    elif mutation=='long':a=approve(t,expires_at=(now+timedelta(seconds=601)).isoformat())
    elif mutation=='mode':a=approve(t,'RECONCILE')
    with pytest.raises(Exception):run(t,approval=a,trusted_keys=trust)
    assert not files(t) and not t['fabric'].plans


@pytest.mark.parametrize('kind',['fabric-namespace','public-namespace','original-chaincode','chain-id','finality','organizations','zero-contract'])
def test_dedicated_destination_policy(pipeline,kind):
    t=pipeline;d=deepcopy(t['selection']['destinations'])
    if kind=='fabric-namespace':d['fabric']['namespace']='evidence-v1'
    elif kind=='public-namespace':d['public']['namespace']='evidence-v1'
    elif kind=='original-chaincode':d['fabric']['chaincode']='officer-evidence-v1'
    elif kind=='chain-id':d['public']['chain_id']=1
    elif kind=='finality':d['public']['finality']='LATEST'
    elif kind=='organizations':d['fabric']['organizations']=['Org1MSP']
    else:d['public']['contract']='0x'+'0'*40
    selection=deepcopy(t['selection']);selection['destinations']=d
    with pytest.raises(ValueError):run(t,approval=approve(t,selection=selection))
    assert not files(t)


@pytest.mark.parametrize('name',['fabric','public'])
def test_live_transport_rejected_and_destination_drift(pipeline,name):
    t=pipeline;t[name].fixture_transport=False
    with pytest.raises(ValueError):run(t)
    t[name].fixture_transport=True;t[name].destination['namespace']='other'
    with pytest.raises(ValueError):run(t)
    assert not files(t)


@pytest.mark.parametrize('mutation',['payload','destination','transaction','fabric-invalid','fabric-single-peer','public-reverted','public-unfinalized','public-single-read'])
def test_receipt_verification_blocks_false_success(pipeline,mutation):
    t=pipeline;name='public' if mutation.startswith('public') else 'fabric'
    def mutate(r):
        if r.get('status')!='FINAL':return r
        if mutation=='payload':r['payload']['merkle_root']='f'*64
        elif mutation=='destination':r['destination']['namespace']='other'
        elif mutation=='transaction':r['transaction_id']='f'*64
        elif mutation=='fabric-invalid':r['verification']['validation_code']='MVCC_READ_CONFLICT'
        elif mutation=='fabric-single-peer':r['verification']['organizations']=['Org1MSP']
        elif mutation=='public-reverted':r['verification']['execution_status']=0
        elif mutation=='public-unfinalized':r['verification']['finalized']=False
        else:r['verification']['independent_readback']=False
        return r
    t[name].observe_hook=mutate
    with pytest.raises(ValueError):run(t)
    if name=='fabric':assert not t['public'].plans
    assert name+'-final.encrypted.json' not in files(t)


def test_source_changes_during_prepare_block_broadcast(pipeline):
    t=pipeline;t['fabric'].prepare_hook=lambda:t['s']['snapshot']['catalog'].update(changed={})
    with pytest.raises(ValueError):run(t)
    assert not t['fabric'].calls and 'fabric-plan.encrypted.json' not in files(t)


def test_history_advances_blocks_execution_but_allows_existing_read_only_audit(pipeline):
    t=pipeline;run(t)
    old=t['d']['adapter'].select
    t['d']['adapter'].select=lambda:dict(old(),newer=True)
    with pytest.raises(ValueError):run(t)
    assert run(t,mode='RECONCILE',approval=approve(t,'RECONCILE'))['latest_history_checked'] is False


def test_reconciliation_cannot_create_or_submit(pipeline):
    t=pipeline
    with pytest.raises(ValueError):run(t,mode='RECONCILE',approval=approve(t,'RECONCILE'))
    assert not files(t) and not t['fabric'].plans and not t['public'].calls


def test_final_transaction_disappears_no_rebroadcast(pipeline):
    t=pipeline;run(t);t['fabric'].records.clear()
    with pytest.raises(ValueError):run(t)
    assert len(t['fabric'].calls)==1


@pytest.mark.parametrize('kind',['overlap','unknown','symlink','corruption'])
def test_output_and_recovery_protection(pipeline,tmp_path,kind):
    t=pipeline
    if kind=='overlap':
        with pytest.raises(ValueError):run(t,directory=t['root'])
    elif kind=='unknown':
        (t['anchor_root']/'unknown').write_text('inspect me')
        with pytest.raises(ValueError):run(t)
    elif kind=='symlink':
        (t['anchor_root']/'intent.encrypted.json').symlink_to(t['root']/C.PRIVATE_NAME)
        with pytest.raises(ValueError):run(t)
    else:
        run(t);path=t['anchor_root']/'fabric-plan.encrypted.json';path.write_text('{}')
        with pytest.raises(Exception):run(t)
        assert len(t['fabric'].calls)==1


def test_private_ledger_rechecked_after_public_finality(pipeline):
    t=pipeline
    original=t['public'].submit
    def submit(*args):
        original(*args);t['fabric'].records.clear()
    t['public'].submit=submit
    with pytest.raises(ValueError):run(t)
    assert len(t['public'].calls)==1


@pytest.mark.parametrize('stage',['fabric-plan','fabric-final','public-plan','public-final'])
def test_storage_interruption_preserves_original_transaction_recovery(pipeline,monkeypatch,stage):
    t=pipeline;publish=A.J._publish
    def interrupted(path,*args):
        if path.name==stage+'.encrypted.json':raise OSError('Simulated storage interruption')
        return publish(path,*args)
    monkeypatch.setattr(A.J,'_publish',interrupted)
    with pytest.raises(OSError):run(t)
    before=files(t)
    if stage.endswith('-plan'):assert not t[stage.split('-')[0]].calls
    monkeypatch.setattr(A.J,'_publish',publish);run(t)
    assert len(t['fabric'].calls)==len(t['public'].calls)==1
    assert all(files(t)[k]==v for k,v in before.items())


def test_approval_expires_after_preparation_before_broadcast(pipeline):
    t=pipeline
    def expire():t['s']['clock'][0]+=timedelta(seconds=121)
    t['fabric'].prepare_hook=expire
    with pytest.raises(ValueError):run(t)
    assert not t['fabric'].calls and 'fabric-plan.encrypted.json' not in files(t)


def test_public_preparation_rechecks_private_destination(pipeline):
    t=pipeline;t['public'].prepare_hook=lambda:t['fabric'].destination.update(channel='changed')
    with pytest.raises(ValueError):run(t)
    assert len(t['fabric'].calls)==1 and not t['public'].calls
    assert 'fabric-final.encrypted.json' in files(t) and 'public-plan.encrypted.json' not in files(t)


def test_commitment_changes_during_preparation_block_submission(pipeline):
    t=pipeline
    def change():
        path=t['root']/C.PUBLIC_NAME;value=json.loads(path.read_text());value['merkle_root']='f'*64
        path.write_text(json.dumps(value))
    t['fabric'].prepare_hook=change
    with pytest.raises(ValueError):run(t)
    assert not t['fabric'].calls
