"""Scope first, disclosure second, then bounded read-only analysis of an observed copy."""
from copy import deepcopy
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo
from app.access.policy import AccessError, permitted, projection, require, uid
from app.access import research_policy as P
from app.identity.bitemporal_reconstruction import query
from app.identity.bitemporal_contradictions import compare_history
from app.security.record_protection import (
    AssignmentProtection, RecordClassification, DisclosureCategory, ProtectionLevel, required_protection)

class ResearchService:
    def __init__(self, store):
        self.store = store; self.access = store.access
        from app.intake.promotion_pipeline.analysis import configured_analysis
        self.promotion_analysis=configured_analysis(store)
        store.promotion_analysis=self.promotion_analysis
        from app.intake.promotion_pipeline.approvals import configured_approvals
        self.promotion_acceptance=configured_approvals(store,self.promotion_analysis)
        store.promotion_acceptance=self.promotion_acceptance
        from app.intake.dataset_pipeline.analysis import configured_analysis as dataset_analysis
        from app.intake.dataset_pipeline.acceptance import configured_approvals as dataset_approvals
        self.dataset_analysis=dataset_analysis(store);store.dataset_analysis=self.dataset_analysis
        self.dataset_acceptance=dataset_approvals(store,self.dataset_analysis);store.dataset_acceptance=self.dataset_acceptance

    def dataset_reports(self,officer,known=None):
        if self.dataset_analysis is None:return []
        try:return self.dataset_analysis.reports(officer,known)
        except Exception:raise AccessError(503,'DATASET_ANALYSIS_UNAVAILABLE') from None

    def recording(self,packet,officer,known=None):
        """Original journal plus verified promotion and dataset uploads at their activation times."""
        h=P.history(packet['history'],officer)
        if self.promotion_analysis is not None:h=self.promotion_analysis.recording(packet,officer,self.promotion_reports(officer,known))
        if self.dataset_analysis is not None:h=self.dataset_analysis.extend_history(h,officer,self.dataset_reports(officer,known))
        return h

    def displayed_state(self,officer,full_records):
        """Source service record plus accepted, currently effective uploaded changes."""
        from app.access.current_state import current_state
        from app.access.full_source_profiles import profile
        with self.access.transaction() as c:directory=self.access._directory(c)
        try:full_records=profile(self.store,officer,directory['source_public_sha256'])['full_records']
        except AccessError:pass  # legacy presentation copy without a connected source profile
        service=[r for r in full_records if r['dataset']=='officer_service_information.csv']
        promotion=self.promotion_acceptance.current(officer) if self.promotion_acceptance is not None else None
        datasets=self.dataset_acceptance.current(officer) if self.dataset_acceptance is not None and self.dataset_reports(officer) else None
        return current_state(service[0]['fields'] if len(service)==1 else {},promotion,datasets),promotion,datasets

    def promotion_reports(self,officer,known=None):
        if self.promotion_analysis is None:return []
        try:return self.promotion_analysis.reports(officer,known)
        except Exception:raise AccessError(503,'PROMOTION_ANALYSIS_UNAVAILABLE') from None

    def authorized(self, token, officer, *, csrf=None, review=False, charge=True):
        try: uid(officer)
        except Exception: raise AccessError(404, 'NOT_FOUND') from None
        # AccessStore supplies the current signed account and directory; HTTP
        # callers cannot choose a role, membership, classification or actor.
        with self.access.transaction() as c:
            user, session = self.access._session(c, token, csrf)
            directory = self.access._directory(c)
            found = next((o for o in directory['officers'] if o['officer_uid'] == officer and permitted(user, o)), None)
            if found is None: raise AccessError(404, 'NOT_FOUND')
            if charge: self.access._limit(c, 'SEARCH', session['user'], 60)
            disclosure = self.store.get_grant(user['user_id'], officer)
            if disclosure['account_version'] != user['version'] or disclosure['source_public_sha256'] != directory['source_public_sha256']:
                raise AccessError(403, 'DETAILS_WITHHELD')
            decision = required_protection(assignment=AssignmentProtection(disclosure['assignment']),
                record_classification=RecordClassification(disclosure['classification']), category=DisclosureCategory.PERSONNEL_DETAILS)
            if decision.level is ProtectionLevel.WITHHOLD or (decision.level is ProtectionLevel.RESTRICTED and not disclosure['restricted_clearance']):
                raise AccessError(403, 'DETAILS_WITHHELD')
            if review and not disclosure['request_reviews']: raise AccessError(403, 'REVIEW_REQUEST_FORBIDDEN')
            try:packet = self.store.get_packet(officer)
            except AccessError as error:
                if error.code != 'PRESENTATION_NOT_CONFIGURED':raise
                from app.access.full_source_profiles import profile
                packet = profile(self.store, officer, directory['source_public_sha256'])
            if packet['source_public_sha256'] != directory['source_public_sha256']: raise AccessError(503, 'PRESENTATION_SOURCE_DIFFERS')
            self.access._audit(c, 'RESEARCH_VIEW' if not review else 'REVIEW_REQUEST', session['user'])
            return user, disclosure, packet, projection(found)

    def available(self, token):
        """Bounded connected details within current scope; no global officer counts."""
        with self.access.transaction() as c:
            user, session = self.access._session(c, token)
            directory = self.access._directory(c)
            self.access._limit(c, 'SEARCH', session['user'], 60)
            officers = {o['officer_uid']: o for o in directory['officers'] if permitted(user, o)}
        with self.store.transaction() as c:
            rows = c.execute('SELECT id,value FROM presentations ORDER BY id').fetchall()
        items = []
        for ident, blob in rows:
            envelope = self.store.open('PACKET', ident, blob)
            officer = envelope['payload']['officer_uid']
            if officer not in officers: continue
            try:
                _, _, packet, identity = self.authorized(token, officer, charge=False)
            except AccessError as error:
                if error.status == 401: raise
                continue
            items.append(dict(**identity, expires_at=packet['expires_at']))
            if len(items) == 100: break
        # Expiration/revocation and directory replacement during enumeration deny return.
        with self.access.transaction() as c:
            current, _ = self.access._session(c, token)
            latest = self.access._directory(c)
            if current != user or latest != directory: raise AccessError(409, 'PRESENTATION_CHANGED')
        return dict(items=items, limit=100, detail_views_only=True,
                    scope_basis=('EXPLICIT_RESEARCH_SIMULATION' if directory['review_reference'] ==
                                 'GENERATED_RESEARCH_SCOPE_SIMULATION_V1' else 'SIGNED_CURRENT_MEMBERSHIP'))

    def browse(self, token, csrf, request):
        """Page the signed identity directory inside current account scope only."""
        from app.access.policy import LEVELS, name
        try:
            require(type(request) is dict and set(request) ==
                    {'kind','query','availability','level','scope_id','limit','offset'})
            kind, text = request['kind'], request['query']
            require(kind in ('NAME','NIC','REFERENCE') and type(text) is str and len(text) <= 200)
            require(not any(ord(v) < 32 for v in text))
            require(request['availability'] in ('ALL','AVAILABLE','UNAVAILABLE'))
            require(request['level'] in ('ALL', *LEVELS) and type(request['scope_id']) is str)
            require(len(request['scope_id']) <= 64)
            require(type(request['limit']) is int and 1 <= request['limit'] <= 50)
            require(type(request['offset']) is int and 0 <= request['offset'] <= 10000)
            require(request['level'] != 'ALL' or request['scope_id'] == '')
            needle = name(text) if kind == 'NAME' and text.strip() else text.strip()
        except Exception:
            raise AccessError(400, 'INVALID_QUERY') from None
        with self.access.transaction() as c:
            user, session = self.access._session(c, token, csrf)
            directory = self.access._directory(c)
            self.access._limit(c, 'SEARCH', session['user'], 60)
            officers = [o for o in directory['officers'] if permitted(user, o)]
            self.access._audit(c, 'IDENTITY_SEARCH', session['user'])
        options = {level: sorted({o['membership'][level] for o in officers
                                 if o['membership'][level] is not None}) for level in LEVELS}
        if request['level'] != 'ALL' and request['scope_id'] not in options[request['level']]:
            filtered = []
        else:
            filtered = [o for o in officers if
                (request['level'] == 'ALL' or o['membership'][request['level']] == request['scope_id']) and
                (not needle or
                 (kind == 'NAME' and any(needle in name(n) for n in o['names'])) or
                 (kind == 'NIC' and needle in o['nic']) or
                 (kind == 'REFERENCE' and needle == o['officer_uid']))]
        from app.access import full_source_profiles as F
        available=F.capabilities(self.store,user,directory,filtered)
        if request['availability'] != 'ALL':
            filtered = [o for o in filtered if
                (o['officer_uid'] in available) == (request['availability'] == 'AVAILABLE')]
        filtered.sort(key=lambda o: (name(o['names'][0]), o['nic'], o['officer_uid']))
        offset, limit = request['offset'], request['limit']
        with self.store.transaction() as c:
            recorded={row[0] for row in c.execute('SELECT id FROM presentations')}
        items=[]
        for o in filtered[offset:offset+limit]:
            reported=None
            if o['officer_uid'] in available:
                try:reported=F.profile(self.store,o['officer_uid'],directory['source_public_sha256'])['reported_posting']
                except AccessError:pass
            items.append(dict(**projection(o),membership=deepcopy(o['membership']),
                unit_type=o['membership'].get('UNIT'),details_available=o['officer_uid'] in available,reported_posting=reported,
                historical_workspace_available=o['officer_uid'] in available and self.store.index('OFFICER',o['officer_uid']) in recorded))
        with self.access.transaction() as c:
            current, _ = self.access._session(c, token, csrf)
            latest = self.access._directory(c)
            if current != user or latest != directory: raise AccessError(409, 'PRESENTATION_CHANGED')
        return dict(items=items, total=len(filtered), offset=offset, limit=limit,
                    scope_options=options, directory_generation=directory['generation'],
                    scope_basis=('EXPLICIT_RESEARCH_SIMULATION' if directory['review_reference'] ==
                                 'GENERATED_RESEARCH_SCOPE_SIMULATION_V1' else 'SIGNED_CURRENT_MEMBERSHIP'))

    def workspace(self, token, officer):
        user, grant, packet, identity = self.authorized(token, officer)
        from app.access.full_source_profiles import POLICY, source_workspace
        if packet.get('policy')==POLICY:
            result=source_workspace(packet,identity)
            result['current_state'],promotion,datasets=self.displayed_state(officer,packet['full_records'])
            if promotion is not None:result['current_assignment']=promotion
            if datasets is not None:result['dataset_acceptance']=datasets
            self.authorized(token,officer,charge=False)
            return result
        result = dict(identity=identity, generation=packet['generation'], observed_at=packet['observed_at'],
            expires_at=packet['expires_at'], coverage_start=packet['history']['coverage_start'],
            coverage_end=packet['history']['coverage_end'], findings=self.findings_projection(packet['findings']),
            authority=deepcopy(packet['authority']), anchoring=deepcopy(packet['anchoring']),
            can_request_review=grant['request_reviews'], accepted_state=None,
            full_records=deepcopy(packet.get('full_records', [])),
            display_lifecycle='RETAINED_LAST_VERIFIED_SNAPSHOT' if packet['expires_at'] is None else 'BOUNDED_OBSERVED_COPY',
            evidence_view='SIGNED_OBSERVED_COPY', coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',
            historical_workspace_available=True, history_baseline_only=packet['history']['coverage_start']==packet['history']['coverage_end'],
            priority2_available=True,
            live_research_ready=False, fresh_live_verification=False,
            public_finality_verified=False, independent_deployment_verified=False)
        if self.promotion_analysis is not None:
            reports=self.promotion_reports(officer)
            h=self.recording(packet,officer)
            result.update(coverage_end=h.coverage_end.isoformat(),history_baseline_only=h.coverage_start==h.coverage_end,
                promotion_analysis=self.promotion_analysis.summary(reports),
                evidence_updates=dict(baseline_observed_at=packet['observed_at'],
                    latest_analysis_at=max((r['analysis_recorded_at'] for r in reports),default=None),
                    latest_publication_verified_at=max((r['publication']['verification_observed_at'] for r in reports),default=None),
                    fresh_chain_reads=False))
            from app.access.evidence_display import rank_timeline
            observed=query(h,effective_on=datetime.fromtimestamp(self.store.clock(),timezone.utc).astimezone(ZoneInfo('Asia/Colombo')).date(),known_at=h.coverage_end)
            result['rank_timeline']=rank_timeline([dict(withdrawn=v.withdrawn,claim=P.claim_projection(v.claim)) for v in observed.visible_versions],datetime.fromtimestamp(self.store.clock(),timezone.utc).astimezone(ZoneInfo('Asia/Colombo')).date().isoformat())
            self.authorized(token,officer,charge=False)
        if self.dataset_analysis is not None and self.promotion_analysis is None:
            h=self.recording(packet,officer)
            result.update(coverage_end=h.coverage_end.isoformat(),history_baseline_only=h.coverage_start==h.coverage_end)
        result['current_state'],promotion,datasets=self.displayed_state(officer,packet.get('full_records',[]))
        if promotion is not None:result['current_assignment']=promotion
        if datasets is not None:result['dataset_acceptance']=datasets
        self.authorized(token,officer,charge=False)
        return result

    @staticmethod
    def findings_projection(findings):
        result=deepcopy(findings)
        explanations={'FINDING':'Reported comparison captured; no accepted contradiction established.',
                      'CORRECTION':'New finding evidence appended; earlier entries remain preserved.',
                      'REVIEW':'Temporally authorized review recorded. Its original explanation remains in protected storage.'}
        for finding in result:
            for version in finding['versions']: version['reason']=explanations[version['kind']]
        return result

    def history(self, token, csrf, officer, effective, known):
        _, _, packet, _ = self.authorized(token, officer, csrf=csrf)
        if packet.get('kind')=='SOURCE_PROFILE':raise AccessError(503,'HISTORICAL_WORKSPACE_NOT_CONNECTED')
        try:
            require(type(effective) is str and date.fromisoformat(effective).isoformat() == effective)
            h = P.history(packet['history'], officer); on = date.fromisoformat(effective); at = P.instant(known)
            reports=self.promotion_reports(officer)
            dataset_reports=self.dataset_reports(officer)
            h=self.recording(packet,officer)
            if not h.coverage_start <= at <= h.coverage_end: raise AccessError(422, 'KNOWN_DATE_OUTSIDE_COVERAGE')
            answer = query(h, effective_on=on, known_at=at)
            counts={d:sum(v.claim.dimension==d and not v.withdrawn for v in answer.visible_versions) for d in P.FIELDS}
            if sum(n*(n-1)//2 for n in counts.values())>20000:raise AccessError(422,'COMPARISON_LIMIT_EXCEEDED')
            comparisons = compare_history(h, effective_on=on, known_at=at)
        except AccessError: raise
        except Exception: raise AccessError(400, 'INVALID_QUERY') from None
        result = dict(effective_on=on.isoformat(), known_at=at.isoformat(), query_digest=answer.query_digest,
            accepted_state=None, evidence_view='SIGNED_OBSERVED_COPY', coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',
            earlier_knowledge_supported=False, source_change_completeness_established=False,
            observed_at=packet['observed_at'], generation=packet['generation'],
            projections=[dict(dimension=p.dimension, status=p.status, reasons=list(p.reasons),
                **{group: [P.claim_projection(c) for c in getattr(p, group)]
                   for group in ('candidates', 'supporting', 'review', 'future', 'expired')}) for p in answer.projections],
            versions=[dict(reference=P.fingerprint({'version_id':v.version_id}), recorded_at=v.recorded_at.isoformat(),
                withdrawn=v.withdrawn, supersedes=P.fingerprint({'version_id':v.supersedes}) if v.supersedes else None,
                claim=P.claim_projection(v.claim)) for v in answer.visible_versions],
            comparisons=[dict(dimension=p.dimension, status=p.status, reasons=list(p.reasons),
                evidence_references=[P.fingerprint({'claim_id':r}) for r in p.claim_ids], accepted_contradiction=False,
                comparison_reference=P.fingerprint({'digest':comparisons.comparison_digest,'versions':p.version_ids}),
                version_references=[P.fingerprint({'version_id':v}) for v in p.version_ids],
                destination_references=list(p.destination_digests),receipt_references=list(p.receipt_digests),
                cross_reported_source=p.cross_reported_source)
                for p in comparisons.comparisons], comparison_digest=comparisons.comparison_digest)
        result['excluded_versions']=[dict(reference=P.fingerprint({'version_id':v}),reason=reason) for v,reason in comparisons.exclusions]
        visible = {v.claim.claim_id: v.claim for v in answer.visible_versions}
        for projected, comparison in zip(result['comparisons'], comparisons.comparisons):
            projected['evidence'] = [P.claim_projection(visible[r]) for r in comparison.claim_ids if r in visible]
        # Revocation or directory changes during computation must stop return.
        _, _, current, _ = self.authorized(token, officer)
        if P.fingerprint(current) != P.fingerprint(packet): raise AccessError(409, 'PRESENTATION_CHANGED')
        if self.promotion_analysis is not None:
            relevant=[r for r in reports if P.instant(r['analysis_recorded_at'])<=at]
            if self.promotion_reports(officer,at)!=relevant:raise AccessError(409,'PROMOTION_ANALYSIS_CHANGED')
            result['promotion_analysis']=self.promotion_analysis.summary(relevant)
            result['promotion_evidence']=[{k:r[k] for k in ('raw_record_id','batch_id','received_at','analysis_recorded_at','activation_reference','publication')} for r in relevant]
            result['coverage_semantics']='ORIGINAL_JOURNAL_PLUS_PROMOTION_AVAILABILITY_OBSERVATIONS'
        if self.dataset_analysis is not None:
            relevant=[r for r in dataset_reports if P.instant(r['analysis_recorded_at'])<=at]
            if self.dataset_reports(officer,at)!=relevant:raise AccessError(409,'DATASET_ANALYSIS_CHANGED')
            result['dataset_evidence']=[{k:r[k] for k in ('dataset','raw_record_id','batch_id','received_at','analysis_recorded_at','activation_reference','publication')} for r in relevant]
            result['coverage_semantics']='ORIGINAL_JOURNAL_PLUS_VERIFIED_UPLOAD_AVAILABILITY_OBSERVATIONS'
        from app.access.evidence_display import rank_timeline
        result['rank_timeline']=rank_timeline(result['versions'],result['effective_on'])
        return result

    def request_review(self, token, csrf, body):
        user, grant, packet, _ = self.authorized(token, body['officer_uid'], csrf=csrf, review=True)
        try:
            uid(body['operation_id']); uid(body['finding_id']); P.sha(body['target_head_sha256'])
            require(body['kind'] in ('REVIEW', 'CORRECTION') and body['decision'] in P.DECISIONS)
            P.text(body['reason']); require(type(body['evidence_references']) is list and 1 <= len(body['evidence_references']) <= 20)
            for ref in body['evidence_references']: P.sha(ref)
            require(len(set(body['evidence_references'])) == len(body['evidence_references']))
            require(type(body['generation']) is int)
        except Exception: raise AccessError(400, 'INVALID_REVIEW_REQUEST') from None
        # Idempotent lost-ack replay is allowed only for exactly the same actor,
        # body, account version and officer. No algorithm is executed here.
        value = dict(**deepcopy(body), user_id=user['user_id'], account_version=user['version'], reviewer_uid=grant['reviewer_uid'], source_public_sha256=packet['source_public_sha256'])
        try:
            existing = self.store.get_request(body['operation_id'])
        except AccessError as exc:
            if exc.status != 404: raise
            existing = None
        if existing:
            if existing['request'] != value: raise AccessError(409, 'OPERATION_CONFLICT')
            return self.request_status(token, body['operation_id'])
        finding = next((f for f in packet['findings'] if f['finding_id'] == body['finding_id']), None)
        if finding is None: raise AccessError(404, 'NOT_FOUND')
        if body['generation'] != packet['generation'] or body['target_head_sha256'] != finding['head_sha256']:
            raise AccessError(409, 'FINDING_CHANGED')
        known_refs = {v['entry_sha256'] for f in packet['findings'] for v in f['versions']}
        known_refs |= {v['receipt_digest'] for v in packet['history']['versions']}
        if not set(body['evidence_references']) <= known_refs: raise AccessError(400, 'EVIDENCE_REFERENCE_UNKNOWN')
        self.store.append_request(value)
        return self.request_status(token, body['operation_id'])

    def request_status(self, token, operation):
        with self.access.transaction() as c: self.access._session(c,token)
        try: record = self.store.get_request(operation)
        except ValueError: raise AccessError(404, 'NOT_FOUND') from None
        value = record['request']
        user, _, _, _ = self.authorized(token, value['officer_uid'])
        if user['user_id'] != value['user_id'] or user['version'] != value['account_version']:
            raise AccessError(404, 'NOT_FOUND')
        return self.request_projection(record)

    @staticmethod
    def request_projection(record):
        value=record['request']
        return dict(operation_id=value['operation_id'], officer_uid=value['officer_uid'],
                    request_sha256=record['request_sha256'], status=record['status'],
                    recorded_at=record['recorded_at'], decision_recorded=record['status'] == 'REVIEW_RECORDED', chain_submitted=False,
                    explanation=('A protected operator run recorded this result. Refresh the evidence presentation for its appended journal entry.'
                        if record['status'] != 'PENDING_AUTHORITY' else
                        'Request retained. Temporal authority and a protected operator run are required before a decision is recorded.'))

    def recent_requests(self, token, officer):
        user,_,packet,_=self.authorized(token,officer)
        records=self.store.recent_requests(user['user_id'],officer,user['version'],packet['source_public_sha256'])
        current,_,latest,_=self.authorized(token,officer)
        if current!=user or P.fingerprint(latest)!=P.fingerprint(packet):raise AccessError(409,'PRESENTATION_CHANGED')
        return dict(items=[self.request_projection(r) for r in records],limit=20)
