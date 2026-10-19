"""Scoped operational inspection; no web-issued assessments or action approvals."""
from datetime import date,datetime,timezone
from copy import deepcopy
from app.access.policy import AccessError,require,permitted,projection
from app.access import research_policy as P,operational_authority as A,authority_case_store as S

class WorkflowService:
    def __init__(self,service):self.service=service;self.store=service.store

    def authority(self,token,csrf,body):
        try:
            require(set(body)=={'officer_uid','known_at','action_on','status','limit','offset'})
            require(body['status'] in ('ALL','VALID','INVALID','CANNOT_VERIFY'))
            require(body['action_on'] is None or date.fromisoformat(body['action_on']).isoformat()==body['action_on'])
            require(type(body['limit']) is int and 1<=body['limit']<=50 and type(body['offset']) is int and 0<=body['offset']<=1500)
            known=P.instant(body['known_at']) if body['known_at'] is not None else datetime.fromtimestamp(self.store.clock(),timezone.utc)
            require(known<=datetime.fromtimestamp(self.store.clock(),timezone.utc))
        except Exception:raise AccessError(400,'INVALID_AUTHORITY_QUERY') from None
        user,_,packet,_=self.service.authorized(token,body['officer_uid'],csrf=csrf)
        if packet.get('kind')!='PRESENTATION':raise AccessError(503,'HISTORICAL_WORKSPACE_NOT_CONNECTED')
        if known<P.instant(packet['observed_at']):raise AccessError(422,'AUTHORITY_COPY_NOT_YET_RECORDED')
        with self.store.access.transaction() as database:directory=self.store.access._directory(database)
        actions=A.inventory(packet,directory)
        promotion_reports=self.service.promotion_reports(body['officer_uid'],known)
        if self.service.promotion_analysis is not None:
            actions.update(self.service.promotion_analysis.actions(packet,directory,promotion_reports))
            if len(actions)>1500:raise AccessError(422,'AUTHORITY_ACTION_LIMIT_EXCEEDED')
        # Verified uploads of other datasets become assessable actions at their activation time.
        dataset_reports=[r for r in self.service.dataset_reports(body['officer_uid'],known) if r['subject_officer_uid']==body['officer_uid']]
        if self.service.dataset_analysis is not None and dataset_reports:
            actions.update(self.service.dataset_analysis.actions(packet,directory,dataset_reports))
            if len(actions)>1500:raise AccessError(422,'AUTHORITY_ACTION_LIMIT_EXCEEDED')
        try:records=S.rows(self.store,body['officer_uid'])
        except Exception:raise AccessError(503,'AUTHORITY_ASSESSMENT_INVALID') from None
        selected={};versions={};early_assessments=set()
        upload_times={r['raw_record_id']:P.instant(r['analysis_recorded_at']) for r in promotion_reports+dataset_reports}
        uploaded_files={r['raw_record_id']:r['filename'] for r in dataset_reports}
        for envelope in records:
            p=envelope['payload'];ref=p['action_reference']
            if P.instant(p['recorded_at'])>known:continue
            versions.setdefault(ref,[]).append(dict(reference=P.fingerprint(envelope),recorded_at=p['recorded_at'],
                version=p['version'],supersedes=p['supersedes'],source_matches_current_copy=p['workspace_sha256']==P.fingerprint(packet)))
            if ref in actions and p['workspace_sha256']==P.fingerprint(packet) and p['source_public_sha256']==packet['source_public_sha256']:
                if actions[ref].raw_record_id in upload_times and P.instant(p['recorded_at'])<upload_times[actions[ref].raw_record_id]:
                    early_assessments.add(ref)
                else:selected[ref]=p
        extra=set().union(*(A.assessment_actors(A.assessment(p['assessment'])) for p in selected.values()))
        history,pins,missing=A.actor_history(self.store,packet,directory,actions.values(),known,extra)
        results=[]
        members={o['officer_uid']:o for o in directory['officers']};permitted_actors={}
        for officer in pins:
            try:
                self.service.authorized(token,officer,charge=False)
                permitted_actors[officer]=projection(members[officer])
            except AccessError:continue
        for ref,action in actions.items():
            assessment=selected.get(ref);typed=None if assessment is None else A.assessment(assessment['assessment'])
            needed=set(action.actor_candidates)|(A.assessment_actors(typed) if typed else set())
            stale=assessment is not None and (needed.intersection(missing) or
                {u:assessment['actor_packets'].get(u) for u in needed}!={u:pins[u] for u in needed if u in pins})
            if typed and any(s.state.actor_uid not in history.buckets or history.project(s.state.actor_uid,s.state.on)[0]!=s.state_id for s in typed.states):stale=True
            future=action.reported_date is not None and date.fromisoformat(action.reported_date)>known.date()
            if future:typed=None
            if stale:typed=None
            result=A.ActionAuthority(history).review(action,typed)
            if stale:result['reasons']=sorted(set(result['reasons'])|{'ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE'})
            if future:result['reasons']=sorted(set(result['reasons'])|{'FUTURE_ACTION_AUTHORITY_UNESTABLISHED_AT_KNOWLEDGE_TIME'})
            if ref in versions and assessment is None:result['reasons']=sorted(set(result['reasons'])|{
                'ASSESSMENT_PRECEDES_UPLOADED_EVIDENCE' if ref in early_assessments else 'ASSESSMENT_SOURCE_WORKSPACE_CHANGED'})
            links=[]
            for link in result['actor_state_links']:
                officer=link['officer_uid'];identity=permitted_actors.get(officer)
                links.append(dict(actor_reference=self.store.index('AUTHORITY_ACTOR',officer),identity=identity,
                    disclosure='PERMITTED_ACTOR' if identity else 'ACTOR_DETAILS_WITHHELD',
                    on=link.get('on',action.reported_date),state_reference=link['state_id'],
                    assessment_supplied=bool(link.get('assessment_supplied',False))))
            rules=[];delegations=[]
            if typed:
                for r in typed.rules:rules.append(dict(reference=r.rule_id,powers=list(r.powers),ranks=list(r.ranks),roles=list(r.roles),
                    actor_scopes=list(r.actor_scopes),target_scopes=list(r.target_scopes),start=r.start.isoformat(),
                    end=r.end.isoformat() if r.end else None,may_delegate=r.may_delegate,assessment=r.assessment))
                for d in typed.delegations:delegations.append(dict(reference=d.delegation_id,parent_reference=d.parent_id,
                    issuer=permitted_actors.get(d.issuer_uid),recipient=permitted_actors.get(d.recipient_uid),
                    powers=list(d.powers),target_scopes=list(d.target_scopes),issued_on=d.issued_on.isoformat(),start=d.start.isoformat(),
                    end=d.end.isoformat() if d.end else None,revoked_from=d.revoked_from.isoformat() if d.revoked_from else None,
                    may_delegate=d.may_delegate,assessment=d.assessment))
            results.append(dict(action_reference=ref,action_type=action.action_kind,action_on=action.reported_date,
                status=result['status'],reasons=list(result['reasons']),mode=result['mode'],actors=links,
                rules=rules,delegations=delegations,successful_paths=list(result['successful_paths']),
                assessment_versions=versions.get(ref,[]),assessment_reference=P.fingerprint(next(e for e in records if e['payload']==assessment)) if typed else None,
                source_reference=P.fingerprint({'source':action.source_reference}),destination_reference=action.destination_digest,
                dataset=uploaded_files.get(action.raw_record_id) or next((r['dataset'] for r in packet['full_records'] if r['raw_record_id']==action.raw_record_id),'promotion_history.csv'),
                uploaded_promotion=any(r['raw_record_id']==action.raw_record_id for r in promotion_reports),
                uploaded_dataset_row=action.raw_record_id in uploaded_files,
                police_action_authorized=False,accepted_authority_claim=False))
        filtered=[r for r in results if (body['status']=='ALL' or r['status']==body['status']) and
            (body['action_on'] is None or r['action_on']==body['action_on'])]
        current,_,latest,_=self.service.authorized(token,body['officer_uid'],csrf=csrf,charge=False)
        with self.store.access.transaction() as database:now_directory=self.store.access._directory(database)
        if current!=user or P.fingerprint(latest)!=P.fingerprint(packet) or directory!=now_directory:
            raise AccessError(409,'PRESENTATION_CHANGED')
        for officer,pin in pins.items():
            if P.fingerprint(self.store.get_packet(officer))!=pin:raise AccessError(409,'PRESENTATION_CHANGED')
        if S.rows(self.store,body['officer_uid'])!=records:raise AccessError(409,'ASSESSMENT_CHANGED')
        if self.service.promotion_reports(body['officer_uid'],known)!=promotion_reports:
            raise AccessError(409,'PROMOTION_ANALYSIS_CHANGED')
        if [r for r in self.service.dataset_reports(body['officer_uid'],known) if r['subject_officer_uid']==body['officer_uid']]!=dataset_reports:
            raise AccessError(409,'DATASET_ANALYSIS_CHANGED')
        return dict(items=filtered[body['offset']:body['offset']+body['limit']],total=len(filtered),offset=body['offset'],limit=body['limit'],
            known_at=known.isoformat(),generation=packet['generation'],source_workspace_sha256=P.fingerprint(packet),
            query_digest=P.fingerprint({'policy':A.POLICY,'known':known.isoformat(),'items':results,'source':P.fingerprint(packet),
                **({'promotion_evidence':P.fingerprint(promotion_reports)} if self.service.promotion_analysis is not None else {}),
                **({'dataset_evidence':P.fingerprint(dataset_reports)} if dataset_reports else {})}),
            **({'promotion_analysis':self.service.promotion_analysis.summary(promotion_reports)} if self.service.promotion_analysis is not None else {}),
            assessment_semantics='EXPLICIT_RESEARCH_ASSESSMENT_NOT_POLICE_AUTHORIZATION',
            source_change_completeness_established=False,fresh_live_verification=False,chain_submitted=False)

    def contradictions(self,token,csrf,body):
        try:
            require(set(body)=={'officer_uid','effective_on','known_at','dimension','status','relationship','limit','offset'})
            require(body['dimension'] in ('ALL',*P.FIELDS) and body['status'] in ('ALL','REPORTED_CONTRADICTION_CANDIDATE',
                'UNRESOLVED_COMPARISON','REPORTED_AGREEMENT','NO_REPORTED_CONFLICT_AT_POINT'))
            require(body['relationship'] in ('ALL','CROSS_REPORTED','SAME_REPORTED','UNASSESSED'))
            require(type(body['limit']) is int and 1<=body['limit']<=50 and type(body['offset']) is int and 0<=body['offset']<=20000)
        except Exception:raise AccessError(400,'INVALID_CONTRADICTION_QUERY') from None
        answer=self.service.history(token,csrf,body['officer_uid'],body['effective_on'],body['known_at'])
        pairs=[p for p in answer['comparisons'] if (body['dimension']=='ALL' or p['dimension']==body['dimension']) and
            (body['status']=='ALL' or p['status']==body['status']) and (body['relationship']=='ALL' or
                (body['relationship']=='CROSS_REPORTED' and p['cross_reported_source'] is True) or
                (body['relationship']=='SAME_REPORTED' and p['cross_reported_source'] is False) or
                (body['relationship']=='UNASSESSED' and p['cross_reported_source'] is None))]
        return dict(**{k:answer[k] for k in ('effective_on','known_at','generation','query_digest','comparison_digest','excluded_versions')},
            **{k:answer[k] for k in ('promotion_analysis','promotion_evidence') if k in answer},
            items=pairs[body['offset']:body['offset']+body['limit']],total=len(pairs),unfiltered_total=len(answer['comparisons']),
            offset=body['offset'],limit=body['limit'],accepted_contradiction=False,source_independence_verified=False,chain_submitted=False)
