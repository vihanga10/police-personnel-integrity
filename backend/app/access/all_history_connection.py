"""All-officer observed history enrollment, operator only.

Existing witnessed packets are replayed and preserved. New officers use the
original encrypted observation/checkpoint format and one independently keyed
mTLS checkpoint-set witness. This is an observed generated baseline, not a
reconstruction of undocumented past knowledge or continuous source monitoring.
"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
from pathlib import Path
import time
from uuid import uuid4
import json
from app.access import generated_connection as G, research_connection as C
from app.access import research_connection_runtime as R, research_policy as P
from app.access import full_source_profiles as F, research_bridge as B
from app.access.policy import encoded, permitted, require
from app.identity import observed_recording_journal as J
from app.identity.bulk_history_journal import VerifiedBaselineBatch, publish_control
from app.identity.protected_commitment import digest

POLICY='GENERATED_ALL_OFFICER_HISTORY_V1'
JOB_FIELDS={'policy','kind','code_revision','source_sha256','source_context_sha256',
    'source_public_sha256','source_set_sha256','officers','preserved_packets','registry_id','journal_anchor'}
SET_FIELDS={'policy','kind','code_revision','source_sha256','source_context_sha256',
    'source_public_sha256','source_set_sha256','issued_at','registry_id','journal_anchor','officers'}
SCHEMA='''CREATE TABLE IF NOT EXISTS recorded_history_sets
(id TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS recorded_history_packets
(set_id TEXT NOT NULL,id TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(set_id,id));'''

def wire(history):
    value=json.loads(json.dumps(asdict(history),default=lambda v:v.isoformat(),allow_nan=False))
    value.pop('officer_uid');return value

def packets(store):
    with store.transaction() as database:rows=database.execute('SELECT id,value FROM presentations').fetchall()
    result={}
    for ident,blob in rows:
        envelope=store.open('PACKET',ident,blob);p=P.packet(envelope,store.keys,store.clock())
        require(p['policy']==P.RETAINED_POLICY and ident==store.index('OFFICER',p['officer_uid']))
        require(p['officer_uid'] not in result)
        result[p['officer_uid']]=envelope
    return result

def publish(store,manifest,set_sha,envelopes,grants,*,check):
    """Complete-set atomic import with immutable encrypted recovery copies."""
    P.sha(set_sha);members=manifest['officers'];validated={}
    require(0<len(members)<=10000)
    for envelope in envelopes:
        p=P.packet(envelope,store.keys,store.clock());officer=p['officer_uid']
        require(officer in members and officer not in validated and p['source_public_sha256']==manifest['source_public_sha256'])
        selected=members[officer]
        require(digest(p['history'])==selected['history_sha256'] and
            digest(p['full_records'])==selected['source_records_sha256'] and
            p['generation']==selected['generation'],'History packet differs from witnessed set')
        if selected['kind']=='PRESERVED':require(P.fingerprint(envelope)==selected['packet_sha256'])
        else:require(selected['kind']=='BASELINE' and p['recording_tip_sha256']==set_sha and
            p['issued_at']==manifest['issued_at'] and p['findings']==[],'New baseline cannot fabricate a stored finding')
        validated[officer]=envelope
    require(set(validated)==set(members),'Complete historical officer set required')
    checked_grants=[(e,P.grant(e,store.keys,store.clock())) for e in grants]
    check()
    with store.transaction() as database:
        for statement in SCHEMA.split(';'):
            if statement.strip():database.execute(statement)
        for table,name in (('recorded_history_sets','history_set'),('recorded_history_packets','history_packet')):
            for operation in ('UPDATE','DELETE'):
                database.execute(f"CREATE TRIGGER IF NOT EXISTS no_{name}_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable history evidence'); END")
        old=database.execute('SELECT value FROM recorded_history_sets WHERE id=?',(set_sha,)).fetchone()
        if old:require(store.open('HISTORY_SET',set_sha,old[0])==manifest,'Recorded set identity differs')
        else:database.execute('INSERT INTO recorded_history_sets VALUES(?,?)',(set_sha,store.seal('HISTORY_SET',set_sha,manifest)))
        for officer,envelope in validated.items():
            p=envelope['payload'];ident=store.index('OFFICER',officer)
            row=database.execute('SELECT version,value FROM presentations WHERE id=?',(ident,)).fetchone()
            if row:require(row[0]==p['generation'] and store.open('PACKET',ident,row[1])==envelope,
                           'A current history/correction cannot be overwritten by a bulk baseline')
            else:database.execute('INSERT INTO presentations VALUES(?,?,?)',(ident,p['generation'],store.seal('PACKET',ident,envelope)))
            saved=database.execute('SELECT value FROM recorded_history_packets WHERE set_id=? AND id=?',(set_sha,ident)).fetchone()
            if saved:require(store.open('HISTORY_PACKET',[set_sha,ident],saved[0])==envelope)
            else:database.execute('INSERT INTO recorded_history_packets VALUES(?,?,?)',(set_sha,ident,store.seal('HISTORY_PACKET',[set_sha,ident],envelope)))
        for envelope,p in checked_grants:
            require(p['officer_uid'] in members and p['source_public_sha256']==manifest['source_public_sha256'])
            ident=store.index('GRANT',p['user_id'],p['officer_uid'])
            old=database.execute('SELECT issued,value FROM disclosures WHERE id=?',(ident,)).fetchone()
            if old:
                try:current=P.grant(store.open('GRANT',ident,old[1]),store.keys,store.clock())
                except Exception:current=None
                # Current disclosure and review restrictions are preserved exactly.
                if current and current['account_version']==p['account_version'] and current['source_public_sha256']==p['source_public_sha256']:continue
                require(p['issued_at']>old[0],'Disclosure must advance')
            database.execute('INSERT OR REPLACE INTO disclosures VALUES(?,?,?)',(ident,p['issued_at'],store.seal('GRANT',ident,envelope)))
        if not database.execute("SELECT 1 FROM recorded_history_packets WHERE set_id=?",(set_sha,)).fetchone():raise ValueError('Empty history set')
        if not any(e.get('kind')=='ALL_OFFICER_HISTORIES_IMPORTED' and e.get('set_sha256')==set_sha for e in store._events(database)):
            store.event(database,dict(kind='ALL_OFFICER_HISTORIES_IMPORTED',set_sha256=set_sha,officers=len(validated)))
        check(database)

def check_source_profiles(store,metadata,groups):
    """Read the signed source-set metadata once, not once per officer."""
    pending={store.index('SOURCE_PROFILE',o):o for o in groups}
    require(set(pending)==set(metadata['profiles']))
    with store.transaction() as database:
        for ident,blob in database.execute('SELECT id,value FROM source_profiles WHERE generation=?',(metadata['generation'],)):
            require(ident in pending,'Duplicate/unexpected source profile')
            envelope=store.open('SOURCE_PROFILE',[metadata['generation'],ident],blob)
            require(P.fingerprint(envelope)==metadata['profiles'][ident],'Source profile fingerprint differs')
            p=F.validate_profile(envelope,store.keys,store.clock());officer=pending.pop(ident)
            require(p['officer_uid']==officer and all(p[k]==metadata[k] for k in
                ('generation','source_public_sha256','source_context_sha256')) and
                digest(p['full_records'])==digest(groups[officer]),'Source profile differs from exact original replay')
    require(not pending,'Missing full source profiles')

def authority_index(snapshot,officers,*,check=lambda:None,progress=lambda _:None):
    """Use the existing authority algorithm, with one shared actor history."""
    from app.identity.reported_authority_actions import ROUTES,review_actions
    from app.identity.temporal_findings_review import _history
    from app.identity.action_authority_integration import ActionAuthority
    groups={officer:{} for officer in officers}
    for raw,item in snapshot['catalog'].items():
        if item['filename'] not in ROUTES:continue
        for link in item['candidate_links']:
            if link['role']=='officer_nic_no':
                require(link['officer_uid'] in groups);groups[link['officer_uid']][raw]=item
    result={officer:[] for officer in officers}
    if not any(groups.values()):return result
    history=ActionAuthority(_history(snapshot))
    for index,(officer,group) in enumerate(groups.items(),1):
        if index==1 or index%100==0:
            check();progress('REPORTED_AUTHORITY_SUMMARIES_'+str(index)+'_OF_'+str(len(groups)))
        for action in review_actions(group,snapshot['bindings']['raw_bindings']):
            assessment=history.review(action)
            result[officer].append(dict(action_id=digest({'raw_record_id':action.raw_record_id,'action_kind':action.action_kind}),
                action_type=action.action_kind,action_on=action.reported_date,status='CANNOT_VERIFY',
                reasons=list(assessment['reasons']),assessment_receipt_sha256=None))
        # UI authority summaries retain reasons only; full source rows remain
        # available separately. Do not accumulate unused actor telemetry.
        history.history.drain()
        if len(history.history.states)>4096:history.history.states.clear()
    return result

def connect_all(repo,root,app_root,audit_attempt,*,progress=lambda _:None):
    repo=Path(repo).resolve();root=Path(root).absolute();app_root=Path(app_root).absolute()
    plan=G.validate_plan(repo,root,app_root)
    with G.private(root/'operator.lock',repo=repo).open('rb') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        revision=C.revision(repo);access_signer=R.signer(app_root/'keys/research-access-signer.key',repo)
        signer=R.signer(app_root/'keys/research-presentation-signer.key',repo)
        accounts=G.current_accounts(app_root,repo,access_signer)
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
        bootstrap=attempt/'history-config.json';G.write(bootstrap,config);connection=C.Connection(bootstrap)
        progress('FULL_ORIGINAL_BATCH_REPLAY');snapshot=connection._snapshot([])
        from app.access.research_app import configured
        store,_=configured(app_root/'workspace-config.json');require(store.accountability is not None)
        require(G.public(signer)==store.keys[G.PRESENTATION_ID])
        with store.access.transaction() as database:directory=store.access._directory(database)
        identities=C.Connection._identities(snapshot);members={o['officer_uid']:o for o in directory['officers']}
        require(directory['source_public_sha256']==C.PUBLIC_SHA and directory['review_reference']==G.REVIEW and set(members)==set(identities))
        for officer,identity in identities.items():
            require(all(members[officer][k]==identity[k] for k in ('nic','names','source_raw_id')),'Directory identity differs')
        source_set=F.active_set(store);require(source_set is not None and source_set['source_public_sha256']==C.PUBLIC_SHA)
        require(set(source_set['profiles'])=={store.index('SOURCE_PROFILE',o) for o in identities},'All full source profiles must already be connected')
        progress('COMPILING_ALL_HISTORICAL_SUBJECT_CLAIMS')
        recorder,recorder_keys=G.signing(root,repo,'recorder')
        batch=VerifiedBaselineBatch(snapshot,identities,recorder,'recorder',recorder_keys)
        groups=F.group_records(snapshot,identities);check_source_profiles(store,source_set,groups);existing=packets(store)
        bank=root/'all-history-v1'
        if not bank.exists():
            bank.mkdir(mode=0o700);(bank/'journals').mkdir(mode=0o700);(bank/'control').mkdir(mode=0o700)
            require(set(existing)<=set(identities))
            old={o:P.fingerprint(e) for o,e in existing.items()}
            stable=dict(code_revision=revision,source_sha256=batch.source_sha,source_context_sha256=digest(snapshot['context']),
                source_public_sha256=C.PUBLIC_SHA,source_set_sha256=digest(source_set),officers=sorted(identities),preserved_packets=old)
            job=dict(policy=POLICY,kind='JOB',**stable,registry_id=str(uuid4()),journal_anchor=digest(stable))
            publish_control(bank/'job.json',J._sign(job,recorder,'recorder',POLICY),batch.deadline)
        else:
            G.private(bank,directory=True,repo=repo)
            job=J._verify(R.read_json(bank/'job.json',repo),recorder_keys,JOB_FIELDS,'JOB',POLICY)
            require(job['code_revision']==revision and job['source_sha256']==batch.source_sha and
                job['source_context_sha256']==digest(snapshot['context']) and job['source_public_sha256']==C.PUBLIC_SHA and
                job['source_set_sha256']==digest(source_set) and job['officers']==sorted(identities),'Pending history enrollment inputs differ')
            require(set(existing)<=set(identities))
            for officer,pin in job['preserved_packets'].items():require(officer in existing and P.fingerprint(existing[officer])==pin,'Preserved history changed')
        request_id=str(uuid4())
        def event(outcome,reason):
            store.accountability.append(dict(request_id=request_id,action='DATASET_CONNECTION',phase='ADMINISTRATION',method='OPERATOR',
                actor=dict(principal_kind='SIGNING_KEY',key_id=G.OWNER_ID),requested_officer_uid=None,finding_id=None,
                operation_id=None,subject_user_id=None,peer_reference=None,status=None,outcome=outcome,reason=reason))
        event('ATTEMPT','ALL_OFFICER_HISTORY_ENROLLMENT')
        selected={};histories={}
        try:
            with ExitStack() as stack:
                for officer in sorted(job['preserved_packets']):
                    progress('VERIFYING_PRESERVED_WITNESSED_HISTORY')
                    # Existing per-officer witnesses/findings are replayed. No baseline,
                    # correction, stored finding or old observation time is replaced.
                    runtime=G.open_officer(stack,root,repo,plan,snapshot,officer)
                    recording=R.recording(runtime['recording_config'],repo)
                    findings=R.findings(runtime['findings_config'],repo,officer)
                    current=B._export_loaded(snapshot,repo,recording,officer_uid=officer,
                        generation=existing[officer]['payload']['generation'],findings=findings)
                    old=existing[officer]['payload']
                    require(all(current[k]==old[k] for k in ('history','findings','recording_tip_sha256')),'Existing history has advanced; preserve it and refresh explicitly')
                    require(digest(old['full_records'])==digest(groups[officer]),'Existing profile rows differ')
                    selected[officer]=dict(kind='PRESERVED',packet_sha256=P.fingerprint(existing[officer]),
                        history_sha256=digest(old['history']),source_records_sha256=digest(groups[officer]),generation=old['generation'])
                for index,officer in enumerate(sorted(identities),1):
                    if index==1 or index%100==0:
                        progress('RECORDING_HISTORIES_'+str(index)+'_OF_'+str(len(identities)));batch.check()
                    if officer in selected:continue
                    journal=bank/'journals'/officer
                    if not journal.exists():journal.mkdir(mode=0o700)
                    pin,state=batch.record(journal,repo,officer);h=wire(state['history']);histories[officer]=h
                    selected[officer]=dict(kind='BASELINE',recording=pin,history_sha256=digest(h),
                        source_records_sha256=digest(groups[officer]),generation=1)
                batch.check(full=True)
                file=bank/'checkpoint-set.encrypted.json'
                writer,writer_keys=G.signing(root,repo,'recording-registry')
                registry_crypto,registry_backup=R.crypto_pair(plan['crypto']['recording-registry'],repo)
                binding=dict(artifact='ALL_OFFICER_RECORDED_CHECKPOINT_SET',policy=POLICY,journal_anchor=job['journal_anchor'])
                if file.exists():
                    set_sha,receipt=J._read(G.private(file,repo=repo),registry_crypto,registry_backup,binding)
                    manifest=J._verify(receipt,writer_keys,SET_FIELDS,'CHECKPOINT_SET',POLICY)
                    require(manifest['officers']==selected and all(manifest[k]==job[k] for k in
                        ('code_revision','source_sha256','source_context_sha256','source_public_sha256','source_set_sha256','registry_id','journal_anchor')),'Recorded checkpoint set differs')
                else:
                    max_end=max(P.instant(h['coverage_end']) for h in histories.values()) if histories else datetime.now(timezone.utc)
                    issued=B._export_second(max_end)
                    manifest=dict(policy=POLICY,kind='CHECKPOINT_SET',issued_at=issued,officers=selected,
                        **{k:job[k] for k in ('code_revision','source_sha256','source_context_sha256','source_public_sha256','source_set_sha256','registry_id','journal_anchor')})
                    set_sha=J._publish(file,J._sign(manifest,writer,'recording-registry',POLICY),registry_crypto,registry_backup,binding,batch.deadline)
                progress('PINNED_MTLS_CHECKPOINT_SET_WITNESS')
                witness_file=bank/'witness.json'
                if witness_file.exists():
                    control=R.read_json(witness_file,repo)
                    service=G.witness_service(R.read_json(bank/'recording-witness-service.json',repo),repo)
                else:
                    # Partial witness provisioning is not silently reset/re-enrolled.
                    require(not (bank/'recording-witness-store').exists(),'Partial witness enrollment; preserve private state')
                    service,control=G.create_witness(root,bank,repo,plan,domain='recording-witness',
                        registry_id=job['registry_id'],anchor=job['journal_anchor'],writer_keys=writer_keys)
                    publish_control(witness_file,control,batch.deadline)
                _,witness_keys=G.signing(root,repo,'recording-witness')
                require(control['witness_keys']==G.pins(witness_keys) and service.witness_keys==witness_keys and
                    service.scope['registry_id']==job['registry_id'] and service.scope['journal_anchor']==job['journal_anchor'] and
                    service.scope['witness_id']==control['witness_id'],'Witness key/scope differs from private role pins')
                stack.enter_context(G.listener(service,control,root,repo))
                client=R.witness(control,repo,signing_key=writer,key_id='recording-registry',writer_keys=writer_keys,
                    anchor=job['journal_anchor'],registry_id=job['registry_id'])
                proposed=dict(sequence=1,sha256=set_sha)
                head=client.head()
                if head is None:client.advance(None,proposed)
                else:require(head==proposed,'Witness checkpoint set conflicts; no fallback')
                require(client.head()==proposed,'Fresh checkpoint-set acknowledgment required')
                batch.check(full=True);authority=authority_index(snapshot,identities,check=batch.deadline,progress=progress);envelopes=[]
                for officer in sorted(identities):
                    if officer in job['preserved_packets']:envelopes.append(existing[officer]);continue
                    payload=dict(policy=P.RETAINED_POLICY,kind='PRESENTATION',issued_at=manifest['issued_at'],expires_at=None,
                        officer_uid=officer,generation=1,source_public_sha256=C.PUBLIC_SHA,
                        observed_at=datetime.fromtimestamp(manifest['issued_at'],timezone.utc).isoformat(),recording_tip_sha256=set_sha,
                        history=histories[officer],findings=[],authority=authority[officer],
                        anchoring={k:dict(status='NOT_CONFIGURED',receipt_sha256=None) for k in ('fabric','public','recovery')},
                        record_origin='GENERATED_RESEARCH_RECORDS',full_records=groups[officer])
                    envelopes.append(G.signed(signer,G.PRESENTATION_ID,payload))
                now=int(time.time());grants=[]
                # Previously signed protection settings remain authoritative, including
                # expired/withheld records. Never turn one into ordinary disclosure.
                with store.transaction() as database:old_grants=dict(database.execute('SELECT id,value FROM disclosures'))
                for officer in sorted(identities):
                    for user in accounts:
                        if not user['active'] or not permitted(user,members[officer]):continue
                        ident=store.index('GRANT',user['user_id'],officer);blob=old_grants.get(ident)
                        require(blob is not None,'Existing source disclosure required for history enrollment')
                        old_envelope=store.open('GRANT',ident,blob);old=P.grant(old_envelope,store.keys,old_envelope['payload']['issued_at'])
                        require(old['user_id']==user['user_id'] and old['officer_uid']==officer and old['source_public_sha256']==C.PUBLIC_SHA and
                            old['account_version']<=user['version'] and old['issued_at']<=now)
                        grant={**old,**P.disclosure_lifetime(user,now,approval['expires_at']),'issued_at':now,
                            'account_version':user['version']}
                        # New histories have no stored finding or authenticated reviewer.
                        # Expired review-request policy is never automatically extended.
                        if officer not in job['preserved_packets'] or (old['expires_at'] is not None and now>=old['expires_at']) or old['account_version']!=user['version']:
                            grant.update(request_reviews=False,reviewer_uid=None)
                        elif old['request_reviews'] and old['expires_at'] is not None:
                            grant['expires_at']=min(grant['expires_at'],old['expires_at']) if grant['expires_at'] is not None else old['expires_at']
                            grant['policy']=old['policy']
                        grants.append(G.signed(signer,G.PRESENTATION_ID,grant))
                def unchanged(database=None):
                    batch.check(full=True);connection.unchanged([])
                    require(client.head()==proposed,'Witness changed before publication')
                    if database is None:require(F.active_set(store)==source_set,'Full profile set changed')
                    else:
                        row=database.execute('SELECT generation,value FROM source_profile_sets ORDER BY generation DESC LIMIT 1').fetchone()
                        require(row and F.signed(store.open('SOURCE_SET',row[0],row[1]),store.keys,'SOURCE_SET',store.clock())==source_set,'Full profile set changed')
                    require(G.current_accounts(app_root,repo,access_signer)==accounts,'Accounts changed during history import')
                    with store.access.transaction() as database:require(store.access._directory(database)==directory,'Directory changed')
                progress('ATOMIC_ENCRYPTED_ALL_OFFICER_HISTORY_IMPORT')
                publish(store,manifest,set_sha,envelopes,grants,check=unchanged)
        except BaseException:event('FAILED','HISTORY_ENROLLMENT_INCOMPLETE_PRESERVE_AND_RESUME');raise
        event('ALLOWED','ALL_OFFICER_OBSERVED_HISTORIES_CONNECTED')
        result=dict(status='ALL_OFFICER_HISTORIES_IMPORTED',directory_officers=len(identities),
            recorded_history_workspaces_connected=len(envelopes),all_recorded_history_workspaces_connected=True,
            preserved_existing_histories=len(job['preserved_packets']),new_recorded_baselines=len(histories),
            checkpoint_set_sha256=set_sha,retained_details_expire_at=None,scope_basis='EXPLICIT_SIMULATION',
            record_origin='GENERATED_RESEARCH_RECORDS',code_revision=revision,source_or_chain_modified=False,
            findings_chain_anchored=False,new_findings_created=False,independently_administered_witnesses=False,
            knowledge_semantics='ACTUAL_RECORDED_BASELINE_NOT_PAST_CSV_DATES',sign_in_again=True)
        G.write(attempt/'RESULT.json',result)
        return result
