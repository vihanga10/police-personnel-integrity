"""Explicit operator setup and recording of documented generated research assessments.

No dataset rewrite, historical backdating, web approval, RPC call or chain submit.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime,timezone
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.access import generated_connection as G,research_connection as C,research_connection_runtime as R
from app.access import operational_authority as A,authority_case_store as S,research_policy as P
from app.access.policy import require
from app.identity.run_research_algorithms import json_value
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_ID='generated-research-workflow-assessor'

def prepare(repo,app):
    C.revision(repo);from_stopped(repo,app)
    manifest=R.read_json(app/'accounts.json',repo)
    require(manifest['record_origin']=='GENERATED_RESEARCH_RECORDS','Generated research configuration required')
    config=R.read_json(app/'workspace-config.json',repo)
    require('accountability_config' in config,'Protected accountability must be configured before trust setup')
    first=app/'keys/research-workflow-assessor.key';second=app/'key-backup/research-workflow-assessor.key'
    if first.exists() or second.exists():
        require(R.private(first,repo=repo).read_bytes()==R.private(second,repo=repo).read_bytes(),'Preserve partial assessor key state')
    else:
        key=Ed25519PrivateKey.generate();seed=key.private_bytes_raw();G.write(first,seed);G.write(second,seed)
    key=R.signer(first,repo);keys=G.pins({KEY_ID:G.public(key)})
    access=R.read_json(config['access_config'],repo);logs=R.read_json(config['accountability_config'],repo)
    seed=first.read_bytes()
    require(all(seed!=R.private(path,repo=repo).read_bytes() for path in
        (access['key_file'],config['key_file'],logs['key_file'],app/'keys/research-access-signer.key',app/'keys/research-presentation-signer.key')),
        'Research assessor signing seed must be separate')
    file=app/'workspace-config.json'
    if 'workflow_assessment_keys' in config:require(config['workflow_assessment_keys']==keys,'Existing assessment trust differs')
    else:G.write(file,{**config,'workflow_assessment_keys':keys},replace=True)
    directory=app/'priority2'
    if not directory.exists():directory.mkdir(mode=0o700);G.write(directory/'operator.lock',b'')
    R.private(directory,directory=True,repo=repo);R.private(directory/'operator.lock',repo=repo)
    from app.access.research_app import configured
    store,_=configured(file);require(store.workflow_keys[KEY_ID]==G.public(key))
    require(store.accountability is not None,'Protected accountability must be configured')
    administrative_log(store,'AUTHORITY_TRUST_SETUP','ALLOWED','SEPARATE_GENERATED_RESEARCH_ASSESSOR_PINNED')
    return dict(status='PRIORITY2_PRIVATE_TRUST_PREPARED',existing_datasets_or_histories_changed=False,
        police_authority_issued=False,new_assessments_created=False,chain_submitted=False)

def from_stopped(repo,app):
    from provision_generated_connection import stopped_app
    stopped_app(repo,app)

def administrative_log(store,action,outcome,reason,officer=None,operation=None):
    require(store.accountability is not None)
    store.accountability.append(dict(request_id=str(uuid4()),action=action,phase='ADMINISTRATION',method='OPERATOR',
        actor=dict(principal_kind='SIGNING_KEY',key_id=KEY_ID),requested_officer_uid=officer,finding_id=None,
        operation_id=operation,subject_user_id=None,peer_reference=None,status=None,outcome=outcome,reason=reason))

def source(repo,app,officer,extra_actors=()):
    C.revision(repo);from_stopped(repo,app)
    from app.access.research_app import configured
    store,_=configured(app/'workspace-config.json')
    require(store.workflow_keys,'Prepare separate research assessor trust first')
    packet=store.get_packet(officer)
    require(packet['policy']==P.RETAINED_POLICY and packet['record_origin']=='GENERATED_RESEARCH_RECORDS')
    with store.access.transaction() as database:directory=store.access._directory(database)
    require(any(o['officer_uid']==officer for o in directory['officers']))
    actions=A.inventory(packet,directory);known=datetime.fromtimestamp(store.clock(),timezone.utc)
    history,pins,missing=A.actor_history(store,packet,directory,actions.values(),known,extra_actors)
    return store,packet,directory,actions,known,history,pins,missing

def template(repo,app,officer,output,action_ref=None,actor_dates=()):
    requested=[(value.split('@')[0],A.date.fromisoformat(value.split('@')[1])) for value in actor_dates]
    store,packet,directory,actions,known,history,pins,missing=source(repo,app,officer,[u for u,_ in requested])
    candidates={}
    for reference,action in actions.items():
        candidates[reference]=dict(action_type=action.action_kind,action_on=action.reported_date,
            actors=list(action.actor_candidates),raw_record_reference=action.raw_record_id)
    value=dict(record_origin='GENERATED_RESEARCH_RECORDS',officer_uid=officer,workspace_sha256=P.fingerprint(packet),
        source_public_sha256=packet['source_public_sha256'],actions=candidates,missing_actor_workspaces=missing,
        instruction='Choose one action. Supply independently reviewed facts, instruments and evidence files; no current rank becomes authority.')
    if action_ref is not None:
        require(action_ref in actions);action=actions[action_ref]
        require(action.reported_date is not None and len(action.actor_candidates)==1 and not missing,'A dated resolved candidate and recorded actor copy are required')
        actor=action.actor_candidates[0];on=A.date.fromisoformat(action.reported_date);state_id,state=history.project(actor,on)
        unresolved=dict(value=None,assessment='UNASSESSED',evidence=[])
        typed=dict(public_payload_sha256=packet['source_public_sha256'],original_action_digest=A.digest(json_value(asdict(action))),
            destination_digest=action.destination_digest,actor_uid=actor,target_scope='REPLACE_WITH_ASSESSED_TARGET_SCOPE',
            identity=unresolved,date_semantics=unresolved,coverage=unresolved,
            states=[dict(state_id=state_id,state=json_value(asdict(state)))],rules=[],delegations=[],evidence_digests=[])
        for uid,on in requested:
            identifier,state=history.project(uid,on)
            if not any(s['state']['actor_uid']==uid and s['state']['on']==on.isoformat() for s in typed['states']):
                typed['states'].append(dict(state_id=identifier,state=json_value(asdict(state))))
        value=dict(officer_uid=officer,action_reference=action_ref,workspace_sha256=P.fingerprint(packet),
            actor_packets=pins,assessment=typed,evidence_files={},review_reference='REPLACE_WITH_DOCUMENTED_RESEARCH_REVIEW',
            supersedes=None)
    G.write(output,value)
    return dict(status='PRIVATE_ASSESSMENT_TEMPLATE_CREATED',actions=len(actions),output=str(output),police_authority_issued=False)

def record(repo,app,draft_file):
    draft=R.read_json(draft_file,repo)
    require(set(draft)=={'officer_uid','action_reference','workspace_sha256','actor_packets','assessment','evidence_files','review_reference','supersedes'})
    typed=A.assessment(draft['assessment'])
    store,packet,directory,actions,known,history,pins,missing=source(repo,app,draft['officer_uid'],A.assessment_actors(typed))
    require(not missing and draft['workspace_sha256']==P.fingerprint(packet) and draft['actor_packets']==pins)
    ref=draft['action_reference'];require(ref in actions);typed=A.assessment(draft['assessment']);A.evidence_references(typed)
    require(actions[ref].reported_date is not None and A.date.fromisoformat(actions[ref].reported_date)<=known.date(),
        'No historical decision for a future reported action')
    result=A.ActionAuthority(history).review(actions[ref],typed)
    require(type(draft['evidence_files']) is dict and 0<len(draft['evidence_files'])<=128)
    evidence={};file_pins={}
    for name,path in draft['evidence_files'].items():
        file=R.private(path,repo=repo);pin=C.file_digest(file,repo,8*1024*1024)
        data=file.read_bytes();require(data and hashlib.sha256(data).hexdigest()==pin)
        evidence[name]=data;file_pins[file]=pin
    require(sum(map(len,evidence.values()))<=8*1024*1024 and
        {n:hashlib.sha256(d).hexdigest() for n,d in evidence.items()}==dict(typed.evidence_digests))
    prior=S.rows(store,draft['officer_uid']);head=next((e for e in reversed(prior) if e['payload']['action_reference']==ref),None)
    require(draft['supersedes']==(P.fingerprint(head) if head else None),'Explicit exact correction target required')
    p=dict(policy=S.POLICY,kind='AUTHORITY_ASSESSMENT',record_origin='GENERATED_RESEARCH_RECORDS',officer_uid=draft['officer_uid'],
        action_reference=ref,workspace_sha256=P.fingerprint(packet),source_public_sha256=packet['source_public_sha256'],
        assessment=json_value(asdict(typed)),actor_packets=pins,recorded_at=datetime.now(timezone.utc).isoformat(),
        version=head['payload']['version']+1 if head else 1,supersedes=draft['supersedes'],operation_id=str(uuid4()),review_reference=draft['review_reference'])
    key=R.signer(app/'keys/research-workflow-assessor.key',repo);require(G.public(key)==store.workflow_keys[KEY_ID])
    envelope=G.signed(key,KEY_ID,p)
    def check(database=None):
        def current(officer):
            if database is None:return store.get_packet(officer)
            ident=store.index('OFFICER',officer);row=database.execute('SELECT value FROM presentations WHERE id=?',(ident,)).fetchone()
            require(row is not None);return P.packet(store.open('PACKET',ident,row[0]),store.keys,store.clock())
        require(P.fingerprint(current(p['officer_uid']))==p['workspace_sha256'])
        for officer,pin in pins.items():require(P.fingerprint(current(officer))==pin)
        for file,pin in file_pins.items():require(C.file_digest(file,repo,8*1024*1024)==pin,'Assessment evidence changed')
        with store.access.transaction() as db:require(store.access._directory(db)==directory)
    with R.private(app/'priority2/operator.lock',repo=repo).open('rb') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        administrative_log(store,'AUTHORITY_ASSESSMENT_RECORD','ATTEMPT','DOCUMENTED_GENERATED_RESEARCH_ASSESSMENT',p['officer_uid'],p['operation_id'])
        try:receipt=S.append(store,envelope,check,evidence=evidence)
        except BaseException:
            administrative_log(store,'AUTHORITY_ASSESSMENT_RECORD','FAILED','RECORDING_STOPPED_PRESERVE_INPUTS',p['officer_uid'],p['operation_id']);raise
        administrative_log(store,'AUTHORITY_ASSESSMENT_RECORD','ALLOWED','RESEARCH_EVALUATION_'+result['status'],p['officer_uid'],p['operation_id'])
    return dict(status='GENERATED_RESEARCH_ASSESSMENT_RECORDED',result=result['status'],assessment_reference=receipt,
        recorded_at=p['recorded_at'],version=p['version'],police_action_authorized=False,source_or_chain_modified=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','template','record'))
    parser.add_argument('--repository',type=Path,required=True);parser.add_argument('--app-root',type=Path,required=True)
    parser.add_argument('--officer');parser.add_argument('--action-reference');parser.add_argument('--output',type=Path);parser.add_argument('--draft',type=Path)
    parser.add_argument('--actor-at',action='append',default=[])
    args=parser.parse_args();os.umask(0o077)
    try:
        repo=args.repository.expanduser().resolve();app=args.app_root.expanduser().absolute()
        if args.action=='prepare':require(args.officer is None and args.action_reference is None and args.output is None and args.draft is None and not args.actor_at);result=prepare(repo,app)
        elif args.action=='template':require(args.officer is not None and args.output is not None and args.draft is None);result=template(repo,app,args.officer,args.output.expanduser().absolute(),args.action_reference,args.actor_at)
        else:require(args.draft is not None and args.officer is None and args.action_reference is None and args.output is None and not args.actor_at);result=record(repo,app,args.draft.expanduser().absolute())
        print(json.dumps(result,indent=2));return 0
    except Exception as error:print(json.dumps(dict(status='STOPPED',error_type=type(error).__name__,source_or_chain_modified=False)));return 2
if __name__=='__main__':raise SystemExit(main())
