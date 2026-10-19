"""Isolated keyed commitments and proofs; no production keys or chain execution."""
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from uuid import UUID
import base64
import json
import pytest
from app.identity import findings_commitments as M
from app.identity import observed_recording_journal as J
from app.identity.protected_commitment import CommitmentKeys,KEY_POLICY,digest
from test_findings_tip_witness import witnessed_findings,registered,journal,output,witnessed,setup,verified,keys,OP,ID,OFFICER,advance,inventory


def key_data(content=b'K'*32,publication=b'Z'*32):
    return dict(policy=M.KEY_POLICY,version=M.KEY_VERSION,content_key=base64.b64encode(content).decode(),
        publication_key=base64.b64encode(publication).decode())


@pytest.fixture
def prepared(witnessed_findings,tmp_path):
    d=witnessed_findings;s=d['t']['d']['t']['s'];s['snapshot']['manifest']={'bundles':[{'officer_uid':OFFICER}]}
    d['adapter'].append_receipt(operation_id=OP,finding_id=ID,receipt_path=d['t']['d']['output'])
    original=CommitmentKeys(dict(policy=KEY_POLICY,version='commit-v1',content_key=base64.b64encode(b'C'*32).decode(),
        publication_key=base64.b64encode(b'P'*32).decode()))
    root=tmp_path/'commit-output';root.mkdir(mode=0o700)
    return dict(d=d,s=s,keys=M.FindingsCommitmentKeys(key_data()),backup=M.FindingsCommitmentKeys(key_data()),
        original=original,root=root)


def prepare(t,**changes):
    args=dict(directory=t['root']);args.update(changes)
    return M.prepare_loaded(t['s']['snapshot'],t['s']['repo'],t['d']['adapter'],t['keys'],t['backup'],t['original'],**args)


def recovered(t):
    return M._read(t['root'],t['s']['repo'],t['s']['crypto'],t['s']['backup'])[1]


def verify(t,pin):
    return M.verify_prepared(t['root'],t['s']['repo'],t['keys'],t['backup'],t['s']['crypto'],t['s']['backup'],
        expected_private_sha256=pin)


def test_preparation_is_private_complete_verifiable_and_idempotent(prepared):
    t=prepared;history=t['d']['adapter'].select();before=inventory(t['d']);r=prepare(t)
    p=recovered(t);public=json.loads((t['root']/M.PUBLIC_NAME).read_text())
    assert p['history']==history and p['public']==public and inventory(t['d'])==before
    assert r['status']=='PREPARED' and r['latest_history_checked'] and not r['findings_anchored']
    assert verify(t,r['private_artifact_sha256'])['latest_history_checked'] is False
    files={p.name:p.read_bytes() for p in t['root'].iterdir()}
    t['s']['clock'][0]+=timedelta(seconds=1)
    assert prepare(t)==r and files=={p.name:p.read_bytes() for p in t['root'].iterdir()}
    assert all(p.stat().st_mode&0o777==0o600 for p in t['root'].iterdir())
    text=json.dumps(public)
    for secret in (OFFICER,ID,OP,t['d']['t']['d']['ledger'].ledger_id,'fixture-100','NEEDS_MORE_EVIDENCE','recorded_at','source_context'):
        assert secret not in text
    assert OFFICER not in str(r)
    for handle in [e['publication_id'] for e in public['entries']]+[public['publication_id']]:
        assert M.verify_inclusion(public,M.inclusion_proof(public,handle))


def test_new_preparation_salt_prevents_stable_public_linkage(prepared,tmp_path):
    t=prepared;prepare(t);first=recovered(t);other=tmp_path/'other';other.mkdir(mode=0o700)
    prepare(t,directory=other);second=M._read(other,t['s']['repo'],t['s']['crypto'],t['s']['backup'])[1]
    assert first['history']==second['history'] and first['salt']!=second['salt']
    assert first['public']['publication_id']!=second['public']['publication_id']
    assert set(e['publication_id'] for e in first['public']['entries']).isdisjoint(e['publication_id'] for e in second['public']['entries'])


@pytest.mark.parametrize('field',['kind','receipt','reason','recorded_at','review'])
def test_all_entry_content_is_committed(prepared,field):
    t=prepared;prepare(t);p=recovered(t);h=deepcopy(p['history']);entry=h['entries'][0]['entry']
    if field=='kind':entry['kind']='CORRECTION'
    elif field=='receipt':entry['receipt_sha256']='f'*64
    elif field=='reason':entry['reason']='changed exact explanation'
    elif field=='recorded_at':entry['recorded_at']=t['s']['clock'][0].isoformat()
    else:entry['review']={'changed':'review payload'}
    if field=='recorded_at':entry['recorded_at']=(t['s']['clock'][0]-timedelta(seconds=1)).isoformat()
    public,_=M.generate(h,t['keys'],salt=bytes.fromhex(p['salt']),context=p['context'])
    assert public['merkle_root']!=p['public']['merkle_root'] and public['entries'][0]['commitment']!=p['public']['entries'][0]['commitment']


def test_corrections_and_legacy_reviews_are_preserved_without_acceptance(prepared):
    from test_encrypted_findings_journal import review
    t=prepared;d=t['d'];first=d['adapter'].select();advance(d['t']['d'])
    second=d['adapter'].append_receipt(operation_id=str(UUID(int=950)),finding_id=ID,receipt_path=d['t']['d']['output'],
        supersedes=first['journal_tip']['entry_sha256'],reason='fixture correction')
    advance(d['t']['d']);d['adapter'].append_review(intent=review(d['t']['d'],second['journal_tip']))
    prepare(t);p=recovered(t)
    assert [e['entry']['kind'] for e in p['history']['entries']]==['FINDING','CORRECTION','REVIEW']
    assert len(p['public']['entries'])==3 and p['history']['accepted_state'] is None
    for handle in [e['publication_id'] for e in p['public']['entries']]+[p['public']['publication_id']]:
        assert M.verify_inclusion(p['public'],M.inclusion_proof(p['public'],handle))


@pytest.mark.parametrize('kind',['root','history','entry','extra-field','reordered','duplicate'])
def test_public_payload_mutation_refused(prepared,kind):
    t=prepared;prepare(t);p=deepcopy(recovered(t)['public'])
    if kind=='root':p['merkle_root']='f'*64
    elif kind=='history':p['history_commitment']='f'*64
    elif kind=='entry':p['entries'][0]['commitment']='f'*64
    elif kind=='extra-field':p['officer_uid']=OFFICER
    elif kind=='duplicate':p['entries'].append(deepcopy(p['entries'][0]))
    else:p['entries'][0]['publication_id']=p['publication_id']
    with pytest.raises(ValueError):M.validate_public(p)


@pytest.mark.parametrize('kind',['direction','sibling','index','count','leaf','truncated','extended'])
def test_inclusion_proof_mutation_refused(prepared,kind):
    t=prepared;prepare(t);public=recovered(t)['public'];proof=M.inclusion_proof(public,public['entries'][0]['publication_id'])
    if kind=='direction':proof['siblings'][0]['side']='LEFT'
    if kind=='sibling':proof['siblings'][0]['sha256']='f'*64
    if kind=='index':proof['index']=True
    if kind=='count':proof['leaf_count']+=1
    if kind=='leaf':proof['leaf']['commitment']='f'*64
    if kind=='truncated':proof['siblings']=[]
    if kind=='extended':proof['siblings'].append(deepcopy(proof['siblings'][0]))
    with pytest.raises(ValueError):M.verify_inclusion(public,proof)


@pytest.mark.parametrize('value',[b'C'*32,b'P'*32,b'E'*32,b'L'*32,b'T'*32,b'U'*32])
def test_keys_cannot_reuse_original_or_store_secrets(prepared,value):
    t=prepared;t['keys']=M.FindingsCommitmentKeys(key_data(content=value));t['backup']=M.FindingsCommitmentKeys(key_data(content=value))
    with pytest.raises(ValueError):prepare(t)
    assert not list(t['root'].iterdir())


@pytest.mark.parametrize('kind',['wrong-backup','same-domain','version','short'])
def test_key_config_rejected(prepared,kind):
    t=prepared;data=key_data()
    if kind=='wrong-backup':t['backup']=M.FindingsCommitmentKeys(key_data(content=b'X'*32))
    elif kind=='same-domain':data['publication_key']=data['content_key']
    elif kind=='version':data['version']='unexpected-version'
    else:data['content_key']=base64.b64encode(b'X').decode()
    with pytest.raises(ValueError):
        if kind=='wrong-backup':prepare(t)
        else:M.FindingsCommitmentKeys(data)


@pytest.mark.parametrize('kind',['public','private','approved-pin','wrong-key'])
def test_saved_verifier_requires_exact_artifacts_keys_and_external_pin(prepared,kind):
    t=prepared;r=prepare(t);pin=r['private_artifact_sha256']
    if kind=='public':(t['root']/M.PUBLIC_NAME).write_text('{}')
    elif kind=='private':(t['root']/M.PRIVATE_NAME).write_text('{}')
    elif kind=='approved-pin':pin='f'*64
    else:t['keys']=M.FindingsCommitmentKeys(key_data(content=b'X'*32));t['backup']=M.FindingsCommitmentKeys(key_data(content=b'X'*32))
    with pytest.raises(Exception):verify(t,pin)


def test_interruption_preserves_private_intent_and_resumes_exact_publication(prepared,monkeypatch):
    t=prepared;original=M._publish_public
    monkeypatch.setattr(M,'_publish_public',lambda *a,**k:(_ for _ in ()).throw(OSError('fixture interrupted')))
    with pytest.raises(OSError):prepare(t)
    assert (t['root']/M.PRIVATE_NAME).exists() and not (t['root']/M.PUBLIC_NAME).exists()
    before=(t['root']/M.PRIVATE_NAME).read_bytes();monkeypatch.setattr(M,'_publish_public',original)
    r=prepare(t);assert before==(t['root']/M.PRIVATE_NAME).read_bytes()
    assert verify(t,r['private_artifact_sha256'])['status']=='VERIFIED_SAVED'


def test_latest_tip_advance_blocks_repreparation_of_old_attempt(prepared):
    t=prepared;r=prepare(t);before={p.name:p.read_bytes() for p in t['root'].iterdir()};d=t['d'];advance(d['t']['d'])
    d['adapter'].append_receipt(operation_id=str(UUID(int=960)),finding_id=str(UUID(int=961)),receipt_path=d['t']['d']['output'])
    with pytest.raises(ValueError):prepare(t)
    assert before=={p.name:p.read_bytes() for p in t['root'].iterdir()}
    assert verify(t,r['private_artifact_sha256'])['latest_history_checked'] is False


@pytest.mark.parametrize('kind',['source','permit','witness','key'])
def test_final_publication_guard_refuses_midflight_change(prepared,monkeypatch,kind):
    t=prepared;original=J._publish
    def intercept(path,*args,**kwargs):
        if path.name==M.PRIVATE_NAME:
            if kind=='source':t['s']['snapshot']['catalog']['changed']={}
            elif kind=='permit':t['s']['snapshot']['envelope']['binding']['changed']=True
            elif kind=='key':t['keys'].content=b'X'*32
            else:t['d']['client'].exchange=lambda *a,**k:(_ for _ in ()).throw(OSError('offline'))
        return original(path,*args,**kwargs)
    monkeypatch.setattr(J,'_publish',intercept)
    with pytest.raises(Exception):prepare(t)
    assert not list(t['root'].iterdir())


def test_empty_history_and_outside_subject_refused(witnessed_findings,tmp_path):
    d=witnessed_findings;s=d['t']['d']['t']['s'];s['snapshot']['manifest']={'bundles':[{'officer_uid':OFFICER}]}
    root=tmp_path/'empty-output';root.mkdir(mode=0o700)
    original=CommitmentKeys(dict(policy=KEY_POLICY,version='commit-v1',content_key=base64.b64encode(b'C'*32).decode(),publication_key=base64.b64encode(b'P'*32).decode()))
    with pytest.raises(ValueError):M.prepare_loaded(s['snapshot'],s['repo'],d['adapter'],M.FindingsCommitmentKeys(key_data()),M.FindingsCommitmentKeys(key_data()),original,directory=root)
    assert not list(root.iterdir())


def test_odd_node_duplication_and_manifest_metadata_are_bound(prepared):
    t=prepared;d=t['d'];advance(d['t']['d'])
    d['adapter'].append_receipt(operation_id=str(UUID(int=970)),finding_id=str(UUID(int=971)),receipt_path=d['t']['d']['output'])
    prepare(t);public=recovered(t)['public'];proof=M.inclusion_proof(public,public['publication_id'])
    assert proof['leaf_count']==3 and M.verify_inclusion(public,proof)
    proof['siblings'][0]['sha256']='f'*64
    with pytest.raises(ValueError):M.verify_inclusion(public,proof)


def test_public_after_private_guard_preserves_pending_artifact_on_witness_failure(prepared,monkeypatch):
    t=prepared;original=M._publish_public
    def fail(*args,**kwargs):
        t['d']['client'].exchange=lambda *a,**k:(_ for _ in ()).throw(OSError('fixture witness lost'))
        return original(*args,**kwargs)
    monkeypatch.setattr(M,'_publish_public',fail)
    with pytest.raises(OSError):prepare(t)
    assert {p.name for p in t['root'].iterdir()}=={M.PRIVATE_NAME}


@pytest.mark.parametrize('kind',['public-only','unexpected','symlink','repo','stores','traversal'])
def test_output_boundaries_refused(prepared,kind):
    t=prepared;args={}
    if kind=='public-only':(t['root']/M.PUBLIC_NAME).write_text('{}')
    if kind=='unexpected':(t['root']/'unapproved-staging').write_text('fixture')
    if kind=='symlink':(t['root']/M.PRIVATE_NAME).symlink_to(t['d']['t']['d']['output'])
    if kind=='repo':args['directory']=t['s']['repo']
    if kind=='stores':args['directory']=t['d']['t']['r'].root
    if kind=='traversal':args['directory']=t['root'].parent/'..'/t['root'].parent.name/t['root'].name
    before=inventory(t['d'])
    with pytest.raises(ValueError):prepare(t,**args)
    assert inventory(t['d'])==before


def test_key_loader_checks_both_private_copies(prepared,tmp_path):
    t=prepared;root=tmp_path/'key-copies';root.mkdir(mode=0o700);paths=[]
    for name in ('primary.json','backup.json'):
        p=root/name;p.write_text(json.dumps(key_data()));p.chmod(0o600);paths.append(p)
    assert M._key_pin(M.load_keys(*paths,t['s']['repo'])[0])==M._key_pin(t['keys'])
    with pytest.raises(ValueError):M.load_keys(paths[0],paths[0],t['s']['repo'])
    paths[1].write_text(json.dumps(key_data(content=b'X'*32)))
    with pytest.raises(ValueError):M.load_keys(*paths,t['s']['repo'])
    paths[1].write_text(json.dumps(key_data()));paths[1].chmod(0o644)
    with pytest.raises(ValueError):M.load_keys(*paths,t['s']['repo'])


from test_temporal_findings_review import authorized,intent as authorized_intent,record as authorized_record

def test_authorized_review_proof_and_explanation_are_fully_preserved(authorized,tmp_path):
    a=authorized;i=authorized_intent(a);authorized_record(a,i);root=tmp_path/'authorized-commit';root.mkdir(mode=0o700)
    original=CommitmentKeys(dict(policy=KEY_POLICY,version='commit-v1',content_key=base64.b64encode(b'C'*32).decode(),publication_key=base64.b64encode(b'P'*32).decode()))
    t=dict(d=a['d'],s=a['s'],keys=M.FindingsCommitmentKeys(key_data()),backup=M.FindingsCommitmentKeys(key_data()),original=original,root=root)
    prepare(t);p=recovered(t)
    assert p['history']['entries'][-1]['entry']['review']==i
    assert i['payload']['authority_decision']['status']=='VALID'
    assert 'authority_decision' not in json.dumps(p['public'])


def test_public_entry_refuses_fixture_transport(prepared):
    t=prepared
    with pytest.raises(ValueError):M.prepare(None,t['s']['repo'],'a'*40,t['d']['adapter'],key_file='unused',backup_key_file='unused',directory=t['root'])
    assert not list(t['root'].iterdir())


from test_witness_secure_transport import certs,listener

def test_public_entry_uses_full_loader_original_keys_and_real_mutual_tls(prepared,tmp_path,monkeypatch):
    import socket
    from types import SimpleNamespace
    from app.identity import findings_tip_witness as A,recording_tip_witness as W,witness_secure_transport as T
    from app.identity import algorithm_snapshot,generate_protected_commitments as G
    t=prepared;d=t['d'];r=d['t']['r'];pki=certs(tmp_path/'commit-pki',J._now())
    control=tmp_path/'commit-control';control.mkdir(mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    profile=control/'profile.json'
    pin=T.provision(d['server'],profile_path=profile,endpoint=f'https://127.0.0.1:{port}'+T.PATH,
        ca_certificate=pki['ca'],server_certificate=pki['server'],server_key=pki['server_key'],client_certificates={r.key_id:pki['client']})
    server_args=dict(profile_path=profile,expected_profile_sha256=pin,ca_certificate=pki['ca'],server_certificate=pki['server'],server_key=pki['server_key'])
    transport_args=dict(profile_path=profile,expected_profile_sha256=pin,witness_keys=d['args']['witness_keys'],repo=t['s']['repo'],
        ca_certificate=pki['ca'],client_certificate=pki['client'],client_key=pki['client_key'])
    calls=[];original_calls=[]
    def loader(*args):calls.append(args);return t['s']['snapshot']
    def original(*args):original_calls.append(args);return t['original']
    monkeypatch.setattr(algorithm_snapshot,'load_verified_snapshot',loader);monkeypatch.setattr(G,'load_keys',original)
    paths=[]
    for name in ('commit-key.json','commit-key-backup.json'):
        p=control/name;p.write_text(json.dumps(key_data()));p.chmod(0o600);paths.append(p)
    with listener(dict(port=port,t={'server':d['server']},server_args=server_args)):
        adapter=A.WitnessedFindingsRegistry(r,W.WitnessClient(**d['client_args'],exchange=T.HTTPSWitnessTransport(**transport_args)))
        result=M.prepare(SimpleNamespace(commitment_key_file='original',backup_commitment_key_file='original-backup'),
            t['s']['repo'],'a'*40,adapter,key_file=paths[0],backup_key_file=paths[1],directory=t['root'])
        assert result['status']=='PREPARED' and len(calls)==1 and len(original_calls)==2
        assert verify(t,result['private_artifact_sha256'])['status']=='VERIFIED_SAVED'
