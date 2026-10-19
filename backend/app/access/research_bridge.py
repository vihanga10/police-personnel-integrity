"""Trusted operator integration with existing protected loaders/runners.

No HTTP path calls these functions. Signing drafts are private and must be
reviewed and signed by a configured presentation authority before import.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import date, datetime, timezone
import json
import math
import time
from app.access.policy import account, permitted, require
from app.access import research_policy as P
from app.identity import recording_tip_witness as W
from app.identity.witness_secure_transport import HTTPSWitnessTransport
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.protected_commitment import digest
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity import observed_recording_journal as J

def export_observed_presentation(args, repo, revision, recording, *, officer_uid, generation, findings=None,
                                pipeline=None, fabric_read_approval=None, public_read_approval=None):
    from app.identity.protected_findings_capture import _recording_transport
    _recording_transport(recording, snapshot_repo(repo))
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot = load_verified_snapshot(args, repo, revision)
    if pipeline is None:
        require(fabric_read_approval is None and public_read_approval is None, 'Anchoring approvals need a configured read-only pipeline')
    else:
        from app.identity.findings_backend_pipeline import FindingsBackendPipeline
        require(type(pipeline) is FindingsBackendPipeline and pipeline.mode=='RECONCILE' and
            findings is not None and pipeline.source.findings is findings and
            pipeline.source.repo==snapshot_repo(repo) and pipeline.source.revision==revision,
            'Presentation and anchoring pipeline differ')
    selected = findings.select() if findings is not None else None
    draft = _export_loaded(snapshot, repo, recording, officer_uid=officer_uid, generation=generation, findings=findings)
    if pipeline is not None:
        require(findings.select()==selected, 'Findings advanced during presentation export')
        draft['anchoring']=observe_anchoring(pipeline,officer_uid=officer_uid,
            fabric_read_approval=fabric_read_approval,public_read_approval=public_read_approval)
        permit=AlgorithmPermit(snapshot);permit.check(snapshot)
        require(findings.select()==selected and recording.client.head()['sha256']==draft['recording_tip_sha256'],
            'Presentation inputs advanced during receipt observation')
    return draft

def _export_second(coverage_end):
    """Wait for the next real whole second when coverage includes microseconds.

    Never round recording history backwards or issue a future-dated grant.
    Genuine future coverage/clock rollback stays a hard failure.
    """
    coverage = coverage_end.timestamp()
    current = time.time()
    require(coverage <= current, 'Export clock/coverage differs')
    boundary = math.ceil(coverage)
    if current < boundary:
        time.sleep(boundary - current)
    observed = int(time.time())
    require(coverage <= observed, 'Export clock/coverage differs')
    return observed

def _export_loaded(snapshot, repo, recording, *, officer_uid, generation, findings=None):
    """Internal only: snapshot must originate from the full original replay loader."""
    permit = AlgorithmPermit(snapshot); permit.check(snapshot)
    registry = recording.registry
    require(registry.repo == snapshot_repo(repo), 'Export repository differs')
    W.WitnessedCheckpointRegistry(registry, recording.client)
    tip = recording.client.head(); original = digest(dict(catalog=snapshot['catalog'], bindings=snapshot['bindings']['raw_bindings']))
    selected_findings=None; findings_tip=None
    if findings is not None:
        from app.identity.findings_tip_witness import WitnessedFindingsRegistry
        require(type(findings) is WitnessedFindingsRegistry and findings.fixture_transport is False and
                findings.registry.journal.officer_uid==officer_uid, 'Operational findings scope required')
        findings._config(); selected_findings=findings.select(); findings_tip=selected_findings['registry_tip']
    with registry._locked():
        recording_entries=registry._entries(tip); selected = registry._selection(recording_entries, tip); state = selected['state']; baseline = state['baseline']
        require(baseline['scope']['officer_uid'] == officer_uid, 'Export officer differs')
        old, current = deepcopy(baseline['source_context']), deepcopy(snapshot['context'])
        old.pop('code_revision', None); current.pop('code_revision', None)
        require(old == current and baseline['original_publication_sha256'] == digest(snapshot['public']) and
                baseline['source_registry_sha256'] == digest({k: sorted(v) for k,v in HEADERS.items()}), 'Original source binding differs')
        expected = [dict(claim=J._wire(c), source_key=json.loads(c.source_reference)['filename'])
                    for c in source_claims(officer_uid, snapshot['catalog'], snapshot['bindings']['raw_bindings'])]
        require(sorted(map(J.canonical, expected)) == sorted(map(J.canonical, baseline['claims'])), 'Original baseline claims differ')
        h = state['history']
        wire = json.loads(json.dumps(asdict(h), default=lambda x:x.isoformat(), allow_nan=False)); wire.pop('officer_uid')
        now = _export_second(h.coverage_end); summaries = []; authority = _reported_authority(snapshot,officer_uid)
        if findings is not None:
            for wrapped in selected_findings['entries']:
                if wrapped['entry']['kind']!='REVIEW':
                    observed=wrapped['entry']['finding']
                    require(observed['witness_scope']==recording.client.scope and
                        recording_entries[-1]['preserved_checkpoints'].get(observed['checkpoint_file'])==observed['checkpoint_sha256'],
                        'Findings recording history differs from the exported journal')
            summaries, review_authority = _findings(snapshot, selected_findings['entries'], findings.registry.journal)
            authority.extend(review_authority)
        draft = dict(policy=P.POLICY, kind='PRESENTATION', issued_at=now, expires_at=now+300,
            officer_uid=officer_uid, generation=generation, source_public_sha256=digest(snapshot['public']),
            observed_at=datetime.fromtimestamp(now, timezone.utc).isoformat(), recording_tip_sha256=tip['sha256'],
            history=wire, findings=summaries, authority=authority,
            anchoring={k:dict(status='NOT_CONFIGURED', receipt_sha256=None) for k in ('fabric','public','recovery')})
        require(h.coverage_end.timestamp() <= now, 'Export clock/coverage differs')
        permit.check(snapshot)
        require(recording.client.head() == tip and registry._selection(registry._entries(tip),tip) == selected and
                digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings'])) == original, 'Export inputs changed')
        if findings is not None: require(findings._head() == findings_tip, 'Findings advanced during export')
        return draft

def snapshot_repo(repo):
    from pathlib import Path
    return Path(repo).expanduser().resolve()

def _reported_authority(snapshot,officer):
    from app.identity.reported_authority_actions import review_actions,ROUTES
    from app.identity.temporal_findings_review import _history
    from app.identity.action_authority_integration import ActionAuthority
    catalog={raw:item for raw,item in snapshot['catalog'].items() if item['filename'] in ROUTES and
        any(l['role']=='officer_nic_no' and l['officer_uid']==officer for l in item['candidate_links'])}
    if not catalog:return []
    history=ActionAuthority(_history(snapshot));result=[]
    for action in review_actions(catalog,snapshot['bindings']['raw_bindings']):
        review=history.review(action)
        result.append(dict(action_id=digest({'raw_record_id':action.raw_record_id,'action_kind':action.action_kind}),
            action_type=action.action_kind,action_on=action.reported_date,status='CANNOT_VERIFY',
            reasons=list(review['reasons']),assessment_receipt_sha256=None))
    return result

def observe_anchoring(pipeline,*,officer_uid,fabric_read_approval,public_read_approval=None):
    """Operator-only fresh RECONCILE composition. Never broadcasts or repairs."""
    from app.identity.findings_backend_pipeline import FindingsBackendPipeline
    require(type(pipeline) is FindingsBackendPipeline and pipeline.mode=='RECONCILE','Exact read-only backend pipeline required')
    selection=pipeline.fabric_selection()
    require(pipeline.source.findings.registry.journal.officer_uid==officer_uid,'Anchoring officer differs')
    history=pipeline.source.findings.select()
    require(selection['history_sha256']==digest(history), 'Anchoring covers an earlier findings prefix; current workspace observation withheld')
    fabric=pipeline.run_fabric(fabric_read_approval)
    statuses=dict(fabric=dict(status='OBSERVED_VALID',receipt_sha256=digest(fabric['receipt'])),
        public=dict(status='NOT_CONFIGURED',receipt_sha256=None),recovery=dict(status='OBSERVED_VALID',receipt_sha256=digest(fabric)))
    if public_read_approval is not None:
        public_selection=pipeline.public_selection(fabric_read_approval)
        result=pipeline.run_public(fabric_read_approval=fabric_read_approval,public_approval=public_read_approval,expected_selection=public_selection)
        statuses['public']=dict(status='PENDING' if result['status']=='PENDING' else 'ISOLATED_ONLY',receipt_sha256=digest(result))
    require(pipeline.source.findings.select()==history, 'Findings advanced during anchoring observation')
    return statuses  # Does not establish independent witness deployment.

def _findings(snapshot, entries, journal):
    from app.identity import temporal_findings_review as M
    summaries = {}; authority = []; authority_history=None
    for wrapped in entries:
        e = wrapped['entry']; head = wrapped['entry_sha256']; key = e['finding_id']
        if e['kind'] != 'REVIEW':
            result = e['finding']; comparison = result['comparison']; pairs = comparison['comparisons']
            # A stored finding can include several dimensions. It remains one
            # stored finding; never fabricate an independent finding per pair.
            dimension = pairs[0]['dimension'] if len({p['dimension'] for p in pairs}) == 1 else 'combined'
            statuses = [p['status'] for p in pairs]
            status = next((s for s in ('REPORTED_CONTRADICTION_CANDIDATE','UNRESOLVED_COMPARISON','REPORTED_AGREEMENT','NO_REPORTED_CONFLICT_AT_POINT') if s in statuses), 'UNRESOLVED_COMPARISON')
            prior = summaries.get(key, {}).get('versions', [])
            summaries[key] = dict(finding_id=key, head_sha256=head, status=status, dimension=dimension,
                effective_on=comparison['effective_on'], known_at=comparison['known_at'], versions=prior)
            decision = None; reason = e['reason'] or 'Reported comparison captured; no accepted contradiction established.'
        else:
            review = e['review']; value = review['payload']
            proof, assessment, decision_result = M.validate_stored_authority(value,review['key_id'],journal)
            if authority_history is None: authority_history=M.ActionAuthority(M._history(snapshot))
            check = authority_history.review(M._action(proof['request']),assessment)
            require(check['status'] == 'VALID' and check['actor_state_links'] == proof['actor_state_links'] and
                tuple(check['successful_paths'])==decision_result.successful_paths, 'Review authority replay differs')
            authority.append(dict(action_id=digest({'operation_id':e['operation_id']}), action_type='FINDING_REVIEW',
                action_on=M._review_day(M.F._time(value['reviewed_at'])).isoformat(), status='VALID',
                reasons=list(check['reasons']) or ['AUTHENTICATED_TEMPORAL_REVIEW_ASSESSMENT'], assessment_receipt_sha256=digest(value['authority'])))
            require(key in summaries, 'Review finding absent'); decision = value['decision']; reason = value['reason']
        summary = summaries[key]
        summary['versions'].append(dict(kind=e['kind'],entry_sha256=head,supersedes=e['supersedes'],recorded_at=e['recorded_at'],decision=decision,reason=reason))
        if e['kind']!='REVIEW': summary['head_sha256'] = head
    return list(summaries.values()), authority

def _current_request(store, operation):
    record = store.get_request(operation); r = record['request']; access = store.access
    with access.transaction() as c:
        row = c.execute('SELECT id,version,value FROM users WHERE owner=?', (access.index('OWNER',r['user_id']),)).fetchone()
        require(row and row[1] == r['account_version'], 'Requester account changed')
        user = account(access.open('USER',row[0],row[1],row[2])['grant'],access.keys,now=access.clock())
        require(user['active'], 'Requester revoked')
        directory = access._directory(c)
        officer = next((o for o in directory['officers'] if o['officer_uid']==r['officer_uid'] and permitted(user,o)),None)
        require(officer is not None, 'Requester officer scope changed')
        require(r['source_public_sha256']==directory['source_public_sha256'],'Requester source batch changed')
        grant = store.get_grant(r['user_id'],r['officer_uid'])
        require(grant['request_reviews'] and grant['reviewer_uid']==r['reviewer_uid'] and
            grant['account_version']==r['account_version'] and grant['source_public_sha256']==directory['source_public_sha256'], 'Requester reviewer link changed')
        from app.security.record_protection import required_protection,AssignmentProtection,RecordClassification,DisclosureCategory,ProtectionLevel
        decision = required_protection(assignment=AssignmentProtection(grant['assignment']),record_classification=RecordClassification(grant['classification']),category=DisclosureCategory.PERSONNEL_DETAILS)
        require(decision.level is ProtectionLevel.NORMAL or (decision.level is ProtectionLevel.RESTRICTED and grant['restricted_clearance']), 'Requester disclosure withheld')
    return record

def record_requested_review(store, operation, args, repo, revision, findings, *, intent, expected_authority_sha256, finding_receipt_path):
    """Explicit operator invocation; signed authority is never generated by the UI."""
    from app.identity.temporal_findings_review import record_review
    record = _current_request(store,operation); r = record['request']; value = findings.registry.journal._review(intent)
    require(value['authority']['payload']['request']['public_payload_sha256']==r['source_public_sha256'],'Review authority source differs from web request')
    require(r['kind']=='REVIEW' and all(value[k] == r[source] for k,source in (
        ('officer_uid','officer_uid'),('operation_id','operation_id'),('finding_id','finding_id'),
        ('target_entry_sha256','target_head_sha256'),('reviewer_uid','reviewer_uid'),('decision','decision'),
        ('reason','reason'),('evidence_references','evidence_references'))), 'Protected intent differs from web request')
    # The existing runner independently verifies authority, exact target head,
    # source replay, review date, receipt and witness, including exact retries.
    result = record_review(args,repo,revision,findings,intent=intent,
        expected_authority_sha256=expected_authority_sha256,finding_receipt_path=finding_receipt_path)
    require(result['status'] in ('REVIEWED','ALREADY_REVIEWED'), 'Protected review did not record')
    _current_request(store,operation)
    store.protected_result(operation,record['request_sha256'],'REVIEW_RECORDED',digest(intent))
    return store.get_request(operation)

def capture_requested_correction(store, operation, args, repo, revision, recording, findings, *, effective_on, known_at, destination):
    """Explicit operator invocation; new evidence must already be in the journal."""
    from app.identity.protected_findings_capture import capture_contradictions
    record = _current_request(store,operation); r = record['request']; require(r['kind']=='CORRECTION','Correction request required')
    from app.identity.algorithm_snapshot import load_verified_snapshot
    require(digest(load_verified_snapshot(args,repo,revision)['public'])==r['source_public_sha256'],'Correction source differs from web request')
    result = capture_contradictions(args,repo,revision,recording,findings,officer_uid=r['officer_uid'],
        effective_on=effective_on,known_at=known_at,operation_id=operation,finding_id=r['finding_id'],
        destination=destination,supersedes=r['target_head_sha256'],reason=r['reason'])
    # Fresh witness selection supplies the appended entry, including recovery
    # after a lost acknowledgement. No receipt from the browser is trusted.
    selected = findings.select(); matches = [e for e in selected['entries'] if e['entry']['operation_id']==operation]
    require(len(matches)==1 and matches[0]['entry']['kind']=='CORRECTION','Protected correction entry required')
    _current_request(store,operation)
    store.protected_result(operation,record['request_sha256'],'CORRECTION_RECORDED',matches[0]['entry_sha256'])
    return store.get_request(operation)
