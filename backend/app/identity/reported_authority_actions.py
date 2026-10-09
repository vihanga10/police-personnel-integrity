"""Preserve reported action actors/dates without inventing authority assignments."""
from dataclasses import dataclass,field
import re
from uuid import UUID
from app.identity.history_plan import ROUTES as HISTORY
from app.identity.srb_plan import ROUTES as SRB
from app.identity.remaining_plan import ROUTES as REMAINING
from app.identity.inspect_srb_activity_sources import HEADERS as ACTIVITY
from app.identity.historical_source_claims import reported_date
from app.identity.evidence_bundle_v2 import canonical
from app.identity.protected_commitment import digest
from app.identity.temporal_authority import Action, Fact, evaluate, require

POLICY='REPORTED_AUTHORITY_ACTION_REVIEW_V1'
# The role is the action reported by this field, not an accepted legal power.
# Missing action dates are preserved: no year-to-day or effective-to-signing guess.
ROUTES={
 'promotion_history.csv':(('AUTHORIZE_PROMOTION','promotion_authority','promotion_authority_signed_date'),),
 'transfer_history.csv':(('AUTHORIZE_TRANSFER','transfer_authority','transfer_signed_date'),),
 'officer_restrictions.csv':(('RECORD_RESTRICTION','restriction_recorded_officer_nic','restriction_record_date'),
     ('RECORD_RESTRICTION_REMOVAL','restriction_removed_officer_nic','restriction_removal_record_date')),
 'restriction_overrides.csv':(('AUTHORIZE_RESTRICTION_OVERRIDE','override_authority_nic','override_date'),),
 'operations.csv':(('COMMAND_OPERATION','commanding_officer_nic_no','operation_date'),),
 'officer_family_details.csv':(('ATTEST_FAMILY_RECORD','recorded_by_officer_nic','Certified_signed_date'),),
 'public_complaints.csv':(('INVESTIGATE_COMPLAINT','investigating_officer_nic','investigation_start_date'),
     ('REPORTED_NPC_DECISION',None,'npc_decision_date')),
 'officer_duty_periods.csv':(('RECORD_DUTY_PERIOD','period_recorded_by_authority_nic','date_of_entry'),),
 'officer_firearms_expertise.csv':(('SUPERVISE_FIREARMS_H1','h1_supervisor_nic','h1_practice_date'),
     ('SUPERVISE_FIREARMS_H2','h2_supervisor_nic','h2_practice_date'),
     ('ANNUAL_FIREARMS_ATTESTATION','annual_supervisor_nic',None)),
 'good_conduct_register.csv':(('RECOMMEND_REWARD','recommending_asp_nic',None),
     ('SANCTION_REWARD','sanctioning_authority_nic','sanction_date'),
     ('APPROVE_GOOD_CONDUCT_ENTRY','approving_authority','approving_order_date')),
 'bad_conduct_register.csv':(('AUTHORIZE_PUNISHMENT','approving_authority','date_of_punishment'),
     ('DECIDE_APPEAL','appeal_authority','appeal_decision_date')),
}
HEADERS={**{k:set(v) for k,v in HISTORY.items()},**{k:set(v) for k,v in SRB.items()},
    **{k:set(v) for k,v in REMAINING.items()},**{k:set(v) for k,v in ACTIVITY.items()}}


@dataclass(frozen=True)
class ActionReview:
    action_kind: str
    status: str
    reasons: tuple[str,...]
    raw_record_id: str = field(repr=False)
    actor_candidates: tuple[str,...] = field(repr=False)
    reported_date: str | None
    reported_date_text: str = field(repr=False)
    source_reference: str = field(repr=False)
    destination_digest: str = field(repr=False)
    policy: str = POLICY
    accepted_authority: bool = False


def review_actions(catalog,raw_bindings,*,on=None):
    """All relevant rows, including unresolved/unassigned actors, remain covered.

    Existing catalog NIC edges are candidate evidence only. Free-text authority
    titles are not resolved to an officer by rank/name matching. A quoted
    delegation reference is not an authenticated governing instrument.
    """
    from datetime import date
    require(on is None or type(on) is date,'Authority calendar date required.')
    results=[]
    for raw,item in sorted(catalog.items()):
        filename=item['filename']
        if filename not in ROUTES:continue
        require(raw==item['raw_record_id'] and re.fullmatch('[0-9a-f]{64}',raw),'Action source differs.')
        require(item['classification']=='UNASSESSED' and item['delivery']['complete'] is True,
            'Action source state differs.')
        original=item['original'];columns=original['columns'];values=original['values']
        require(len(columns)==len(set(columns))==len(values) and set(columns)==HEADERS[filename] and
            all(isinstance(v,str) for v in columns+values),'Action columns differ.')
        require(raw_bindings.get(raw),'Action destination versions missing.')
        row=dict(zip(columns,values));reference=canonical(dict(raw_record_id=raw,filename=filename,
            original=original,provenance=item['provenance'],assertion=item['assertion']))
        fingerprint=digest(raw_bindings[raw])
        for kind,actor_field,date_field in ROUTES[filename]:
            text=row[date_field] if date_field else ''
            actor_text=row[actor_field] if actor_field else ''
            # Optional, wholly absent action slots are not fabricated actions.
            if not actor_text.strip() and not text.strip():continue
            dt,issues=reported_date(text)
            if on is not None and dt is not None and dt>on:continue
            links=[l for l in item['candidate_links'] if actor_field is not None and l['role']==actor_field]
            require(all(l['state']=='CANDIDATE_NOT_ACCEPTED' for l in links),'Actor linkage state differs.')
            require(all(str(UUID(l['officer_uid']))==l['officer_uid'] for l in links),
                'Actor candidate identifier differs.')
            candidates=tuple(sorted({l['officer_uid'] for l in links}))
            reasons=set(issues)|{'ACTION_DATE_SEMANTICS_UNASSESSED','GOVERNING_RULE_UNASSESSED',
                'DELEGATION_EVIDENCE_UNASSESSED','ACTOR_STATE_AT_ACTION_DATE_UNASSESSED',
                'GEOGRAPHIC_AND_POWER_SCOPE_UNASSESSED','CLASSIFICATION_UNASSESSED'}
            if not actor_text.strip():reasons.add('ACTOR_CLAIM_MISSING')
            elif not candidates:reasons.add('ACTOR_IDENTITY_UNRESOLVED')
            elif len(candidates)>1:reasons.add('ACTOR_CANDIDATES_AMBIGUOUS')
            else:reasons.add('ACTOR_CANDIDATE_NOT_ACCEPTED_HISTORICAL_IDENTITY')
            if filename=='bad_conduct_register.csv' and row['delegation_instrument'].strip():
                reasons.add('REPORTED_DELEGATION_REFERENCE_NOT_AUTHENTICATED')
            if len(candidates)==1 and dt is not None:
                unknown=Fact(None,'UNASSESSED',(raw,))
                action=Action(candidates[0],dt,kind,'UNRESOLVED_REPORTED_SCOPE',unknown,unknown,(reference,))
                # The pure engine enforces unresolved identity/date, never guesses VALID.
                decision=evaluate(action,(),(),coverage=unknown)
                require(decision.status=='CANNOT_VERIFY','Reported facts cannot establish authority.')
                reasons.update(decision.reasons)
            results.append(ActionReview(kind,'CANNOT_VERIFY',tuple(sorted(reasons)),raw,candidates,
                dt.isoformat() if dt else None,text,reference,fingerprint))
    return tuple(results)
