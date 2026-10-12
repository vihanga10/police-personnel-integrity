"""Operator-only Stage 4 requests, observed corrections and anchoring preparation.

A web request never grants action-date authority. The installed Stage 3 actor
identities are application identities; pending requests do not establish police
reviewer identities. Approval imports must pass the existing protected authority
runner and trust pins. No fixture receipt is promoted to live chain verification.
"""
from contextlib import ExitStack
from copy import deepcopy
from datetime import date, datetime, timezone
import base64
import fcntl
from functools import wraps
import os
from pathlib import Path
import time
from uuid import uuid4
from app.access import generated_connection as G, research_connection as C
from app.access import research_connection_runtime as R, research_bridge as B
from app.access.policy import account, encoded, require, uid
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest

POLICY='GENERATED_STAGE4_WORKFLOW_V1'
REQUEST_POLICY='GENERATED_STAGE4_REQUEST_POLICY_V1'
REQUEST_ROLES=('IGP','HQ_ADMIN','SDIG','DIG','SSP','SP')
KEY_ID='stage4-request-policy'


def prepare(repo, root, app_root, connection_root):
    repo=Path(repo).resolve();root=Path(root).absolute();app_root=Path(app_root).absolute();connection_root=Path(connection_root).absolute()
    revision=C.revision(repo)
    R.private(root.parent,directory=True,repo=repo)
    require(not root.exists() and not root.is_symlink(),'New Stage 4 root required; preserve prior state')
    for other in (app_root,connection_root):
        R.private(other,directory=True,repo=repo)
        require(not root.is_relative_to(other) and not other.is_relative_to(root),'Separate Stage 4 controls required')
    plan=G.validate_plan(repo,connection_root,app_root)
    accounts=R.read_json(app_root/'accounts.json',repo)
    require(accounts['record_origin']=='GENERATED_RESEARCH_RECORDS' and len(accounts['accounts'])==10)
    require((connection_root/'connection-config.json').is_file(),'Successful Stage 3 connection required first')
    root.mkdir(mode=0o700)
    for name in ('keys','key-backup','operations','commitments'):(root/name).mkdir(mode=0o700)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
    key=Ed25519PrivateKey.generate();seed=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    G.write(root/'keys/request-policy.key',seed);G.write(root/'key-backup/request-policy.key',seed)
    from app.identity.findings_commitments import KEY_POLICY,KEY_VERSION
    keys=dict(policy=KEY_POLICY,version=KEY_VERSION,content_key=base64.b64encode(os.urandom(32)).decode(),publication_key=base64.b64encode(os.urandom(32)).decode())
    G.write(root/'keys/findings-commitment.json',keys);G.write(root/'key-backup/findings-commitment.json',keys)
    settings=dict(policy=POLICY,repository=str(repo),app_root=str(app_root),connection_root=str(connection_root),
        record_origin='GENERATED_RESEARCH_RECORDS',request_authority_keys=G.pins({KEY_ID:G.public(key)}),
        key_file=str(root/'keys/findings-commitment.json'),backup_key_file=str(root/'key-backup/findings-commitment.json'))
    G.write(root/'settings.json',settings)
    G.write(root/'operator.lock',b'')
    renew_request_policy(repo,root)
    return dict(status='STAGE4_PRIVATE_CONTROLS_PREPARED',request_roles=list(REQUEST_ROLES),
        police_reviewer_identity_established=False,review_authority_issued=False,chain_submitted=False)


def settings(root,repo):
    root=R.private(root,directory=True,repo=repo)
    s=R.fields(R.read_json(root/'settings.json',repo),('policy','repository','app_root','connection_root','record_origin',
        'request_authority_keys','key_file','backup_key_file'))
    require(s['policy']==POLICY and Path(s['repository']).resolve()==Path(repo).resolve() and
        s['record_origin']=='GENERATED_RESEARCH_RECORDS','Stage 4 binding differs')
    R.public_keys(s['request_authority_keys'])
    return s


def request_policy(path,repo,app_root,revision,accounts):
    envelope=R.read_json(path,repo);p=R.fields(envelope['payload'],('policy','kind','repository','app_root','code_revision',
        'issued_at','expires_at','record_origin','requester_identity_basis','request_roles','accounts','settings_file'))
    s=settings(Path(p['settings_file']).parent,repo)
    require(Path(p['settings_file']).absolute()==Path(p['settings_file']).parent.absolute()/'settings.json')
    require(p['policy']==REQUEST_POLICY and p['kind']=='REVIEW_REQUEST_PERMISSION' and p['code_revision']==revision and
        Path(p['repository']).resolve()==Path(repo).resolve() and Path(p['app_root']).resolve()==Path(app_root).resolve() and
        s['policy']==POLICY and s['repository']==p['repository'] and s['app_root']==p['app_root'] and
        s['record_origin']==p['record_origin']=='GENERATED_RESEARCH_RECORDS' and
        p['requester_identity_basis']=='APPLICATION_ACCOUNT_NOT_POLICE_IDENTITY' and p['request_roles']==list(REQUEST_ROLES))
    R.fields(envelope,('key_id','payload','signature'));require(envelope['key_id']==KEY_ID)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(R.public_keys(s['request_authority_keys'])[KEY_ID]).verify(
        base64.b64decode(envelope['signature'],validate=True),encoded(p))
    now=time.time();require(type(p['issued_at']) is int and type(p['expires_at']) is int and
        p['issued_at']<=now<p['expires_at']<=p['issued_at']+86400,'Current request policy required')
    expected={a['user_id']:a for a in accounts if a['active'] and a['role'] in REQUEST_ROLES}
    require(type(p['accounts']) is list and len(p['accounts'])==len(expected),'Request account inventory differs')
    seen=set()
    for value in p['accounts']:
        R.fields(value,('user_id','account_version','role'));uid(value['user_id'])
        require(value['user_id'] not in seen and value['user_id'] in expected,'Request account differs');seen.add(value['user_id'])
        current=expected[value['user_id']]
        require(value['account_version']==current['version'] and value['role']==current['role'],'Request account version or role differs')
    return seen


def operator_action(function):
    """Serialize with connection imports and log before/after protected mutations.

    The operator is the local OS user, separately labelled from the requester.
    A failed completion log leaves the operation uncertain; never invent success.
    """
    @wraps(function)
    def run(repo,root,*args,**kwargs):
        s=settings(root,repo)
        from app.access.research_app import configured
        store,_=configured(Path(s['app_root'])/'workspace-config.json')
        require(store.accountability is not None,'Accountability required for Stage 4')
        with ExitStack() as stack:
            for file in (Path(root)/'operator.lock',Path(s['connection_root'])/'operator.lock'):
                lock=stack.enter_context(R.private(file,repo=repo).open('rb'))
                fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            event=dict(action='OTHER_REQUEST',phase='ADMINISTRATION',method='OPERATOR',
                request_id=str(uuid4()),stage4_action=function.__name__,
                actor={'identity_basis':'LOCAL_OS_OPERATOR','uid':os.getuid()},
                operation_id=args[1] if function.__name__ in ('correction','review') and len(args)>1 else None,
                outcome='ATTEMPT',reason=None)
            store.accountability.append(event)
            try:
                value=function(repo,root,*args,**kwargs)
            except Exception:
                store.accountability.append({**event,'outcome':'FAILED','reason':'OPERATION_OUTCOME_UNCERTAIN'})
                raise
            store.accountability.append({**event,'outcome':'ALLOWED'})
            return value
    return run


@operator_action
def renew_request_policy(repo,root):
    s=settings(root,repo);rev=C.revision(repo);app=Path(s['app_root'])
    signer=R.signer(app/'keys/research-access-signer.key',repo)
    accounts=G.current_accounts(app,repo,signer)
    now=int(time.time());policy=dict(policy=REQUEST_POLICY,kind='REVIEW_REQUEST_PERMISSION',repository=str(Path(repo).resolve()),
        app_root=str(app),code_revision=rev,issued_at=now-1,expires_at=now+86398,
        record_origin='GENERATED_RESEARCH_RECORDS',requester_identity_basis='APPLICATION_ACCOUNT_NOT_POLICE_IDENTITY',
        request_roles=list(REQUEST_ROLES),accounts=[dict(user_id=a['user_id'],account_version=a['version'],
            role=a['role']) for a in accounts if a['active'] and a['role'] in REQUEST_ROLES],
        settings_file=str(Path(root)/'settings.json'))
    key=R.signer(Path(root)/'keys/request-policy.key',repo)
    require(G.public(key)==R.public_keys(s['request_authority_keys'])[KEY_ID])
    destination=Path(root)/'request-policy.json'
    G.write(destination,G.signed(key,KEY_ID,policy),replace=destination.exists())
    return dict(status='STAGE4_REQUEST_POLICY_SIGNED',policy_file=str(destination),
        review_decision_authorized=False,police_reviewer_identity_established=False)


def open_context(stack,repo,root,audit_attempt,officer,*,progress=lambda _:None):
    """One full original replay, existing durable journals and real mTLS only."""
    s=settings(root,repo);app=Path(s['app_root']);connection_root=Path(s['connection_root'])
    plan=G.validate_plan(repo,connection_root,app)
    original=R.read_json(connection_root/'connection-config.json',repo)
    require(officer in original['officers'],'Officer was not connected in Stage 3')
    # The earlier source-bound authorization must remain valid at this revision.
    # The Stage 4 audit/connect command creates a current one before operations.
    require(original['source']['audit_gate_attempt']==str(Path(audit_attempt).absolute()),'Use current connected audit attempt')
    connection=C.Connection(connection_root/'connection-config.json')
    snapshot=connection._snapshot([officer]);AlgorithmPermit(snapshot).check(snapshot)
    require((connection_root/'officers'/officer/'runtime.json').is_file(),'Existing complete Stage 3 runtime required')
    runtime=G.open_officer(stack,connection_root,repo,plan,snapshot,officer)
    recording=R.recording(runtime['recording_config'],repo);findings=R.findings(runtime['findings_config'],repo,officer)
    from app.identity.protected_findings_capture import _recording_transport
    _recording_transport(recording,repo);findings._config()
    from app.access.research_app import configured
    store,_=configured(app/'workspace-config.json')
    return s,connection,snapshot,recording,findings,store,runtime


@operator_action
def correction(repo,root,audit_attempt,operation,*,effective_on,known_at):
    """Correct a reported finding by changed query/evidence; never edit personnel rows."""
    from app.access.research_app import configured
    s=settings(root,repo);store,_=configured(Path(s['app_root'])/'workspace-config.json')
    request=B._current_request(store,operation)['request'];require(request['kind']=='CORRECTION','Correction request required')
    require(type(effective_on) is date,'Effective date required')
    known_at=datetime.fromisoformat(known_at);require(known_at.tzinfo is not None,'Aware knowledge timestamp required')
    with ExitStack() as stack:
        s,connection,snapshot,recording,findings,store,runtime=open_context(stack,repo,root,audit_attempt,request['officer_uid'])
        record=B._current_request(store,operation);request=record['request']
        selected=findings.select();existing=[e for e in selected['entries'] if e['entry']['operation_id']==operation]
        if existing:
            require(len(existing)==1 and existing[0]['entry']['kind']=='CORRECTION' and
                existing[0]['entry']['finding_id']==request['finding_id'] and existing[0]['entry']['supersedes']==request['target_head_sha256'] and
                existing[0]['entry']['reason']==request['reason'],'Retained correction differs')
        else:
            heads=[e for e in selected['entries'] if e['entry']['finding_id']==request['finding_id'] and e['entry']['kind']!='REVIEW']
            require(heads and heads[-1]['entry_sha256']==request['target_head_sha256'],'Correction target changed')
            from app.identity.protected_findings_capture import _verified_source
            _,query,comparison=_verified_source(snapshot,recording,request['officer_uid'],effective_on,known_at)
            require(comparison['comparison_digest']!=heads[-1]['entry']['finding']['comparison']['comparison_digest'],
                'Correction requires a changed query or recorded evidence; duplicate re-evaluation refused')
        output=Path(root)/'operations'/operation
        if not output.exists():output.mkdir(mode=0o700)
        R.private(output,directory=True,repo=repo)
        from app.identity.protected_findings_capture import capture_loaded
        result=capture_loaded(snapshot,repo,recording,findings,officer_uid=request['officer_uid'],effective_on=effective_on,
            known_at=known_at,operation_id=operation,finding_id=request['finding_id'],destination=output/'correction.encrypted.json',
            supersedes=request['target_head_sha256'],reason=request['reason'])
        connection.unchanged([request['officer_uid']]);AlgorithmPermit(snapshot).check(snapshot)
        entries=findings.select()['entries'];entry=next(e for e in entries if e['entry']['operation_id']==operation)
        B._current_request(store,operation)
        store.protected_result(operation,record['request_sha256'],'CORRECTION_RECORDED',entry['entry_sha256'])
        return dict(status='CORRECTION_RECORDED',operation_id=operation,source_records_changed=False,
            earlier_finding_preserved=True,accepted_state=None,chain_submitted=False,presentation_refresh_required=True)


@operator_action
def review(repo,root,audit_attempt,operation,*,intent_file,authority_sha256,receipt_file):
    """A real protected decision requires independently configured temporal authority."""
    from app.access.research_app import configured
    s=settings(root,repo);store,_=configured(Path(s['app_root'])/'workspace-config.json')
    request=B._current_request(store,operation)['request'];require(request['kind']=='REVIEW')
    with ExitStack() as stack:
        s,connection,snapshot,recording,findings,store,runtime=open_context(stack,repo,root,audit_attempt,request['officer_uid'])
        journal=findings.registry.journal
        require(journal.authority_keys and journal.reviewer_identities,'Review authority trust and police reviewer identity are not configured')
        connection._watch(intent_file);connection._watch(receipt_file)
        intent=R.read_json(intent_file,repo);record=B._current_request(store,operation);r=record['request'];value=journal._review(intent)
        require(r['kind']=='REVIEW' and all(value[k]==r[source] for k,source in (
            ('officer_uid','officer_uid'),('operation_id','operation_id'),('finding_id','finding_id'),
            ('target_entry_sha256','target_head_sha256'),('reviewer_uid','reviewer_uid'),('decision','decision'),
            ('reason','reason'),('evidence_references','evidence_references'))),'Review intent differs from retained request')
        require(value['authority']['payload']['request']['public_payload_sha256']==r['source_public_sha256'],'Review source differs')
        from app.identity.temporal_findings_review import record_loaded_review
        result=record_loaded_review(snapshot,repo,findings,intent=intent,expected_authority_sha256=authority_sha256,finding_receipt_path=receipt_file)
        connection.unchanged([r['officer_uid']]);AlgorithmPermit(snapshot).check(snapshot);B._current_request(store,operation)
        store.protected_result(operation,record['request_sha256'],'REVIEW_RECORDED',digest(intent))
        return dict(status='REVIEW_RECORDED',operation_id=operation,accepted_state=None,chain_submitted=False,presentation_refresh_required=True)


@operator_action
def prepare_anchor(repo,root,audit_attempt,officer):
    """Opaque complete witnessed-prefix commitments, not a submitted chain receipt."""
    with ExitStack() as stack:
        s,connection,snapshot,recording,findings,store,runtime=open_context(stack,repo,root,audit_attempt,officer)
        from app.identity import findings_commitments as F
        from app.identity.generate_protected_commitments import load_keys
        keys,backup=F.load_keys(s['key_file'],s['backup_key_file'],repo)
        original=load_keys(connection.args.commitment_key_file,connection.args.backup_commitment_key_file,repo)
        history=findings.select();require(history['entries'],'Nonempty witnessed findings history required')
        directory=Path(root)/'commitments'/str(uuid4());directory.mkdir(mode=0o700)
        result=F.prepare_loaded(snapshot,repo,findings,keys,backup,original,directory=directory)
        connection.unchanged([officer]);AlgorithmPermit(snapshot).check(snapshot)
        G.write(directory/'STAGE4_PREPARATION.json',dict(policy=POLICY,officer_uid=officer,code_revision=C.revision(repo),
            source_public_sha256=digest(snapshot['public']),history_sha256=digest(history),summary=result,
            stage='COMMITMENTS_PREPARED_NOT_SUBMITTED',both_chains_anchored=False))
        return dict(status='COMMITMENTS_PREPARED',officer_uid=officer,directory=str(directory),
            public_payload_has_personnel=False,chain_submitted=False,both_chains_anchored=False,summary=result)


def readiness(repo,root):
    """Configuration inventory only; never a live authority or finality assertion."""
    s=settings(root,repo);connection_root=Path(s['connection_root'])
    cfg=R.read_json(connection_root/'connection-config.json',repo);items=[]
    for officer in sorted(cfg['officers']):
        runtime=R.read_json(connection_root/'officers'/officer/'runtime.json',repo)
        journal=R.read_json(runtime['findings_config'],repo)['journal']
        items.append(dict(officer_uid=officer,review_trust_configured=bool(journal['authority_keys'] and journal['reviewer_identities'] and journal['authority_scopes'])))
    return dict(status='STAGE4_CONFIGURATION_INVENTORY',officers=items,
        review_trust_checked_live=False,live_findings_public_adapter='NOT_IMPLEMENTED',
        dedicated_findings_fabric_destination='NOT_PROVISIONED_BY_THIS_STEP',
        chain_submitted=False,both_chains_anchored=False,
        next_review_requirement='EXPLICIT_REVIEWER_IDENTITY_AND_ASSESSED_ACTION_DATE_AUTHORITY_WITH_REVIEWED_TRUST_MIGRATION',
        next_anchor_requirement='DEDICATED_FABRIC_AND_SEPOLIA_FINDINGS_DESTINATIONS_AND_LIVE_RECONCILIATION')
