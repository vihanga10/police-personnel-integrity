"""Scope first, disclosure second, then bounded read-only analysis of an observed copy."""
from copy import deepcopy
from datetime import date
from app.access.policy import AccessError, permitted, projection, require, uid
from app.access import research_policy as P
from app.identity.bitemporal_reconstruction import query
from app.identity.bitemporal_contradictions import compare_history
from app.security.record_protection import (
    AssignmentProtection, RecordClassification, DisclosureCategory, ProtectionLevel, required_protection)

class ResearchService:
    def __init__(self, store): self.store = store; self.access = store.access

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
            packet = self.store.get_packet(officer)
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

    def workspace(self, token, officer):
        user, grant, packet, identity = self.authorized(token, officer)
        return dict(identity=identity, generation=packet['generation'], observed_at=packet['observed_at'],
            expires_at=packet['expires_at'], coverage_start=packet['history']['coverage_start'],
            coverage_end=packet['history']['coverage_end'], findings=self.findings_projection(packet['findings']),
            authority=deepcopy(packet['authority']), anchoring=deepcopy(packet['anchoring']),
            can_request_review=grant['request_reviews'], accepted_state=None,
            evidence_view='SIGNED_OBSERVED_COPY', coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',
            live_research_ready=False, fresh_live_verification=False,
            public_finality_verified=False, independent_deployment_verified=False)

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
        try:
            require(type(effective) is str and date.fromisoformat(effective).isoformat() == effective)
            h = P.history(packet['history'], officer); on = date.fromisoformat(effective); at = P.instant(known)
            if not h.coverage_start <= at <= h.coverage_end: raise AccessError(422, 'KNOWN_DATE_OUTSIDE_COVERAGE')
            answer = query(h, effective_on=on, known_at=at)
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
                evidence_references=[P.fingerprint({'claim_id':r}) for r in p.claim_ids], accepted_contradiction=False)
                for p in comparisons.comparisons], comparison_digest=comparisons.comparison_digest)
        visible = {v.claim.claim_id: v.claim for v in answer.visible_versions}
        for projected, comparison in zip(result['comparisons'], comparisons.comparisons):
            projected['evidence'] = [P.claim_projection(visible[r]) for r in comparison.claim_ids if r in visible]
        # Revocation or directory changes during computation must stop return.
        _, _, current, _ = self.authorized(token, officer)
        if P.fingerprint(current) != P.fingerprint(packet): raise AccessError(409, 'PRESENTATION_CHANGED')
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
