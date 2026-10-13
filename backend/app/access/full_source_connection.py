"""Operator-only full generated subject-profile import after fresh exact readiness."""
import fcntl
from pathlib import Path
import time
from uuid import uuid4
from app.access import generated_connection as G, research_connection as C, research_policy as P
from app.access import full_source_profiles as F
from app.access import research_connection_runtime as R
from app.access.policy import permitted, require
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest


def connect_all(repo,root,app_root,audit_attempt,*,progress=lambda _:None):
    repo=Path(repo).resolve();root=Path(root).absolute();app_root=Path(app_root).absolute()
    plan=G.validate_plan(repo,root,app_root)
    with G.private(root/'operator.lock',repo=repo).open('rb') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        revision=C.revision(repo)
        access_signer=R.signer(app_root/'keys/research-access-signer.key',repo)
        signer=R.signer(app_root/'keys/research-presentation-signer.key',repo)
        accounts=G.current_accounts(app_root,repo,access_signer)
        workspace=R.read_json(app_root/'workspace-config.json',repo)
        require(G.public(signer)==R.public_keys(workspace['presentation_keys'])[G.PRESENTATION_ID])
        attempt=root/'imports'/str(uuid4());attempt.mkdir(mode=0o700)
        owner,owner_keys=G.signing(root,repo,G.OWNER_ID);now=int(time.time())
        approval=dict(policy=C.AUTH_POLICY,kind='DATA_USE',issued_at=now-1,expires_at=now+86398,
            source_public_sha256=C.PUBLIC_SHA,code_revision=revision,purpose='SCOPED_RESEARCH_UI',
            directory_all_officers=True,detail_officer_uids='ALL',review_reference=G.REVIEW,
            custodian_reference='GENERATED_RECORD_OWNER_NOT_POLICE_CUSTODIAN')
        auth=attempt/'generated-owner-authorization.json';G.write(auth,G.signed(owner,G.OWNER_ID,approval))
        config=dict(policy=C.POLICY,repository=str(repo),source={**plan['source'],'audit_gate_attempt':str(Path(audit_attempt).absolute())},
            access_config=str(app_root/'access-config.json'),workspace_config=str(app_root/'workspace-config.json'),
            data_authorization=str(auth),authorization_keys=G.pins(owner_keys),officers={})
        bootstrap=attempt/'source-profile-config.json';G.write(bootstrap,config)
        connection=C.Connection(bootstrap)
        progress('FULL_ORIGINAL_BATCH_REPLAY')
        snapshot=connection._snapshot([]);permit=AlgorithmPermit(snapshot);permit.check(snapshot)
        from app.access.research_app import configured
        store,_=configured(app_root/'workspace-config.json');require(store.accountability is not None)
        with store.access.transaction() as c:directory=store.access._directory(c)
        require(directory['source_public_sha256']==C.PUBLIC_SHA and
                directory['review_reference']==G.REVIEW,'Existing generated directory must match')
        identities=C.Connection._identities(snapshot)
        members={o['officer_uid']:o for o in directory['officers']}
        require(set(members)==set(identities),'All anchored identities must be in the existing directory')
        for officer,identity in identities.items():
            require(all(members[officer][k]==identity[k] for k in ('nic','names','source_raw_id')),
                    'Directory identity differs from exact source replay')
        request_id=str(uuid4())
        def event(outcome,reason):
            store.accountability.append(dict(request_id=request_id,action='DATASET_CONNECTION',phase='ADMINISTRATION',method='OPERATOR',
                actor=dict(principal_kind='SIGNING_KEY',key_id=G.OWNER_ID),requested_officer_uid=None,finding_id=None,
                operation_id=None,subject_user_id=None,peer_reference=None,status=None,outcome=outcome,reason=reason))
        event('ATTEMPT','FULL_GENERATED_SOURCE_PROFILE_IMPORT')
        progress('INDEXING_ALL_ORIGINAL_SUBJECT_ROWS')
        groups=F.group_records(snapshot,identities)
        source_pin=digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings']))
        previous=F.active_set(store);generation=previous['generation']+1 if previous else 1
        now=int(time.time());context_sha=digest(snapshot['context']);profiles=[];grants=[]
        for index,officer in enumerate(sorted(identities),1):
            if index==1 or index%500==0:
                progress('SIGNING_FULL_SOURCE_PROFILES_'+str(index)+'_OF_'+str(len(identities)));permit.check(snapshot)
            records=groups[officer]
            payload=dict(policy=F.POLICY,kind='SOURCE_PROFILE',record_origin='GENERATED_RESEARCH_RECORDS',issued_at=now,
                generation=generation,source_public_sha256=C.PUBLIC_SHA,source_context_sha256=context_sha,
                officer_uid=officer,full_records=records,reported_posting=F.posting(records))
            profiles.append(G.signed(signer,G.PRESENTATION_ID,payload))
            for user in accounts:
                if user['active'] and permitted(user,members[officer]):
                    grant=dict(policy=P.RETAINED_POLICY,kind='DISCLOSURE',issued_at=now,
                        expires_at=min(now+86398,user['expires_at'],approval['expires_at']),
                        user_id=user['user_id'],account_version=user['version'],officer_uid=officer,
                        source_public_sha256=C.PUBLIC_SHA,assignment='ORDINARY',classification='ORDINARY',
                        restricted_clearance=False,request_reviews=False,reviewer_uid=None)
                    grants.append(G.signed(signer,G.PRESENTATION_ID,grant))
        metadata=G.signed(signer,G.PRESENTATION_ID,dict(policy=F.POLICY,kind='SOURCE_SET',record_origin='GENERATED_RESEARCH_RECORDS',
            issued_at=now,generation=generation,source_public_sha256=C.PUBLIC_SHA,source_context_sha256=context_sha,
            profiles={store.index('SOURCE_PROFILE',e['payload']['officer_uid']):P.fingerprint(e) for e in profiles}))
        def unchanged():
            permit.check(snapshot);connection.unchanged([])
            require(digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings']))==source_pin,
                    'Original source snapshot changed')
            current=G.current_accounts(app_root,repo,access_signer)
            require(current==accounts,'Accounts changed during full-profile import')
            with store.access.transaction() as c:require(store.access._directory(c)==directory,'Directory changed during full-profile import')
        progress('ATOMIC_ENCRYPTED_FULL_PROFILE_IMPORT')
        try:F.publish(store,profiles,metadata,grants,check=unchanged)
        except BaseException:event('FAILED','FULL_SOURCE_IMPORT_ROLLED_BACK');raise
        event('ALLOWED','ALL_GENERATED_SOURCE_PROFILES_CONNECTED')
        with store.transaction() as c:recorded=c.execute('SELECT COUNT(*) FROM presentations').fetchone()[0]
        result=dict(status='ALL_FULL_SOURCE_PROFILES_IMPORTED',directory_officers=len(identities),
            full_source_profiles_connected=len(profiles),all_officer_source_details_connected=True,
            recorded_history_workspaces_connected=recorded,all_recorded_history_workspaces_connected=recorded==len(identities),
            source_record_rows=sum(map(len,groups.values())),source_profile_generation=generation,
            detail_copy_expires_at=None,reported_posting_source='officer_service_information.csv',
            scope_basis='EXPLICIT_SIMULATION',record_origin='GENERATED_RESEARCH_RECORDS',
            code_revision=revision,source_or_chain_modified=False,findings_chain_anchored=False,
            new_recording_journals_created=False,new_findings_created=False,sign_in_again=True)
        G.write(attempt/'source-set.json',metadata);G.write(attempt/'RESULT.json',result)
        return result
