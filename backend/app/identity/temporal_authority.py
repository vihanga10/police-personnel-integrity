"""Pure temporal authority evaluation over explicitly assessed evidence.

No rank-to-power law is invented here. An authenticated research adapter must
supply action-specific rules, accepted assessments and a fresh audit permit.
Reported CSV labels, historical candidate projections and signatures are not
accepted facts. This module neither reads databases nor grants human access.
"""
from dataclasses import dataclass, field
from datetime import date
from uuid import UUID
from functools import lru_cache

POLICY = 'TEMPORAL_AUTHORITY_EVALUATION_V1'
STATES = ('ASSESSED', 'UNASSESSED', 'CONFLICTING')


def require(test, message):
    if not test:
        raise ValueError(message)


def officer(value):
    require(isinstance(value, str) and str(UUID(value)) == value, 'Officer identity shape differs.')


def day(value):
    require(type(value) is date, 'Explicit calendar date required.')


def labels(values):
    require(isinstance(values, tuple) and len(set(values)) == len(values) and
        all(isinstance(v, str) and v.strip() for v in values), 'Evidence label set differs.')


@dataclass(frozen=True)
class Fact:
    """Assessment state is supplied by a verified adapter, not inferred from text."""
    value: str | bool | None = field(repr=False)
    assessment: str = 'UNASSESSED'
    evidence: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self):
        require(self.assessment in STATES, 'Unsupported fact assessment.')
        require(type(self.value) in (str, bool, type(None)), 'Fact value shape differs.')
        labels(self.evidence)
        require(self.assessment != 'ASSESSED' or (self.value is not None and self.evidence),
            'Assessed fact requires a value and evidence.')


@dataclass(frozen=True)
class ActorState:
    actor_uid: str = field(repr=False)
    on: date
    identity: Fact
    rank: Fact
    role: Fact
    active: Fact
    # Scope identifiers are accepted catalog IDs, never unverified station text.
    scope: Fact

    def __post_init__(self):
        officer(self.actor_uid); day(self.on)
        require(all(isinstance(v, Fact) for v in (self.identity,self.rank,self.role,self.active,self.scope)),
            'Typed actor facts required.')
        require(type(self.identity.value) in (bool,type(None)) and type(self.active.value) in (bool,type(None)),
            'Identity and service facts must be boolean.')
        require(all(type(v.value) in (str,type(None)) for v in (self.rank,self.role,self.scope)),
            'Rank, role and scope facts must be labels.')


@dataclass(frozen=True)
class Action:
    actor_uid: str = field(repr=False)
    on: date
    power: str = field(repr=False)
    target_scope: str = field(repr=False)
    identity: Fact
    date_semantics: Fact
    evidence: tuple[str, ...] = field(repr=False)

    def __post_init__(self):
        officer(self.actor_uid);day(self.on);labels((self.power,));labels((self.target_scope,));labels(self.evidence)
        require(self.evidence and isinstance(self.identity,Fact) and isinstance(self.date_semantics,Fact),
            'Action provenance and typed assessments required.')
        require(type(self.identity.value) in (bool,type(None)) and type(self.date_semantics.value) in (bool,type(None)),
            'Action assessment shape differs.')


@dataclass(frozen=True)
class Rule:
    """An action-specific governing rule; scopes are explicit resolved memberships.

    Interval endpoints have assessed half-open semantics: [start,end). None is
    an explicitly assessed open end, not an inference from an empty CSV field.
    """
    rule_id: str = field(repr=False)
    powers: tuple[str, ...] = field(repr=False)
    ranks: tuple[str, ...] = field(repr=False)
    roles: tuple[str, ...] = field(repr=False)
    actor_scopes: tuple[str, ...] = field(repr=False)
    target_scopes: tuple[str, ...] = field(repr=False)
    start: date
    end: date | None
    may_delegate: bool | None
    assessment: str
    evidence: tuple[str, ...] = field(repr=False)

    def __post_init__(self):
        labels((self.rule_id,))
        for v in (self.powers,self.ranks,self.roles,self.actor_scopes,self.target_scopes,self.evidence):labels(v)
        require(all((self.powers,self.ranks,self.roles,self.actor_scopes,self.target_scopes)), 'Rule scope must be explicit.')
        day(self.start)
        if self.end is not None:day(self.end);require(self.end>self.start,'Rule interval differs.')
        require(type(self.may_delegate) in (bool,type(None)) and self.assessment in STATES,'Rule assessment differs.')
        require(self.assessment!='ASSESSED' or self.evidence,'Assessed rule provenance required.')


@dataclass(frozen=True)
class Delegation:
    delegation_id: str = field(repr=False)
    parent_id: str = field(repr=False)
    issuer_uid: str = field(repr=False)
    recipient_uid: str = field(repr=False)
    powers: tuple[str, ...] = field(repr=False)
    target_scopes: tuple[str, ...] = field(repr=False)
    issued_on: date
    start: date
    end: date | None
    may_delegate: bool | None
    revoked_from: date | None
    assessment: str
    evidence: tuple[str, ...] = field(repr=False)

    def __post_init__(self):
        officer(self.issuer_uid);officer(self.recipient_uid)
        labels((self.delegation_id,));labels((self.parent_id,))
        labels(self.powers);labels(self.target_scopes);labels(self.evidence)
        require(self.powers and self.target_scopes,'Delegation scope must be explicit.')
        for v in (self.issued_on,self.start):day(v)
        if self.end is not None:day(self.end);require(self.end>self.start,'Delegation interval differs.')
        if self.revoked_from is not None:day(self.revoked_from)
        require(self.issued_on<=self.start,'Delegation cannot precede issuance.')
        require(type(self.may_delegate) in (bool,type(None)) and self.assessment in STATES,'Delegation assessment differs.')
        require(self.assessment!='ASSESSED' or self.evidence,'Assessed delegation provenance required.')


@dataclass(frozen=True)
class Decision:
    status: str
    reasons: tuple[str, ...]
    # Sensitive evidence references belong only in encrypted research artifacts.
    evidence: tuple[str, ...] = field(repr=False)
    successful_paths: tuple[str, ...] = field(repr=False)
    policy: str = POLICY


def evaluate(action, states, rules, delegations=(), *, coverage):
    """Evaluate sufficient direct/delegated authority without assuming completeness.

    A known false constraint refutes one route, not all possible authority.
    INVALID requires an assessed complete set of applicable rules/delegations.
    Otherwise exhausted routes are CANNOT_VERIFY. A successful route requires
    assessed identity, action date, actor state and every governing instrument.
    Delegator authority must hold both at issuance and at the action date in v1.
    This conservative continuing-authority convention is explicit and versioned.
    """
    require(isinstance(action,Action) and isinstance(coverage,Fact),'Typed action and coverage required.')
    require(type(coverage.value) in (bool,type(None)),'Coverage fact must be boolean.')
    states, rules, delegations = tuple(states),tuple(rules),tuple(delegations)
    require(all(isinstance(s,ActorState) for s in states) and all(isinstance(r,Rule) for r in rules) and
        all(isinstance(d,Delegation) for d in delegations),'Typed authority inputs required.')
    index={(s.actor_uid,s.on):s for s in states}
    require(len(index)==len(states),'Duplicate dated actor state.')
    instruments={r.rule_id:r for r in rules}
    for d in delegations:
        require(d.delegation_id not in instruments,'Repeated authority instrument.')
        instruments[d.delegation_id]=d
    require(len({r.rule_id for r in rules})==len(rules),'Repeated authority rule.')
    evidence=set(action.evidence)|set(coverage.evidence)
    reasons=set()
    def fact(f, expected, code):
        evidence.update(f.evidence)
        if f.assessment!='ASSESSED':reasons.add(code+'_UNASSESSED');return None
        if f.value != expected:reasons.add(code+'_REFUTED');return False
        return True
    # Unresolved action identity/date prevents evaluating a definite actor's act.
    action_checks=[fact(action.identity,True,'ACTION_IDENTITY'),fact(action.date_semantics,True,'ACTION_DATE')]
    if any(v is not True for v in action_checks):
        return Decision('CANNOT_VERIFY',tuple(sorted(reasons)),tuple(sorted(evidence)),())
    def combine(values):
        if False in values:return False
        return None if None in values else True
    def actor(uid,on,rule=None):
        s=index.get((uid,on))
        if s is None:reasons.add('ACTION_DATE_ACTOR_STATE_MISSING');return None
        identity = fact(s.identity,True,'ACTOR_IDENTITY')
        if identity is not True:return None
        checks=[fact(s.active,True,'ACTOR_ACTIVE')]
        if rule is not None:
            for f, allowed, code in [(s.rank,rule.ranks,'RANK'),(s.role,rule.roles,'ROLE'),(s.scope,rule.actor_scopes,'ACTOR_SCOPE')]:
                evidence.update(f.evidence)
                if f.assessment!='ASSESSED':checks.append(None);reasons.add(code+'_UNASSESSED')
                elif f.value not in allowed:checks.append(False);reasons.add(code+'_OUTSIDE_RULE')
                else:checks.append(True)
        return combine(checks)
    @lru_cache(maxsize=None)
    def path(identifier,uid,on,power,scope,visited=(),delegating=False):
        if identifier in visited or len(visited)>=16:
            reasons.add('DELEGATION_CYCLE_OR_DEPTH_UNRESOLVED');return None
        item=instruments.get(identifier)
        if item is None:reasons.add('GOVERNING_INSTRUMENT_MISSING');return None
        evidence.update(item.evidence)
        if item.assessment!='ASSESSED':reasons.add('GOVERNING_INSTRUMENT_UNASSESSED');return None
        if not (item.start<=on and (item.end is None or on<item.end)):
            reasons.add('INSTRUMENT_OUTSIDE_VALID_PERIOD');return False
        if power not in item.powers or scope not in item.target_scopes:
            reasons.add('POWER_OR_TARGET_SCOPE_OUTSIDE_INSTRUMENT');return False
        permission=True
        if delegating:
            if item.may_delegate is None:reasons.add('DELEGATION_POWER_UNASSESSED');permission=None
            elif not item.may_delegate:reasons.add('DELEGATION_NOT_PERMITTED');permission=False
        if isinstance(item,Rule):return combine([permission,actor(uid,on,item)])
        if item.recipient_uid!=uid:reasons.add('DELEGATION_RECIPIENT_DIFFERS');return False
        if item.revoked_from is not None and on>=item.revoked_from:
            reasons.add('DELEGATION_REVOKED');return False
        parent=instruments.get(item.parent_id)
        if parent is None:reasons.add('GOVERNING_INSTRUMENT_MISSING');return None
        if parent.assessment!='ASSESSED':reasons.add('GOVERNING_INSTRUMENT_UNASSESSED');return None
        # A signed instrument cannot grant powers or locations beyond its parent.
        if not set(item.powers)<=set(parent.powers) or not set(item.target_scopes)<=set(parent.target_scopes):
            reasons.add('DELEGATION_EXCEEDS_PARENT');return False
        chain=visited+(identifier,)
        return combine([permission,actor(uid,on),
            path(item.parent_id,item.issuer_uid,item.issued_on,power,scope,chain,True),
            path(item.parent_id,item.issuer_uid,on,power,scope,chain,True)])
    candidates=[r.rule_id for r in rules]+[d.delegation_id for d in delegations if d.recipient_uid==action.actor_uid]
    outcomes=[(identifier,path(identifier,action.actor_uid,action.on,action.power,action.target_scope))
        for identifier in sorted(candidates)]
    success=tuple(i for i,v in outcomes if v is True)
    if success:
        reasons.add('ASSESSED_AUTHORITY_PATH_SUPPORTED');status='VALID'
    elif any(v is None for _,v in outcomes):
        reasons.add('AUTHORITY_PATH_UNRESOLVED');status='CANNOT_VERIFY'
    elif coverage.assessment=='ASSESSED' and coverage.value is True:
        reasons.add('COMPLETE_AUTHORITY_PATH_SET_REFUTED');status='INVALID'
    else:
        reasons.add('AUTHORITY_COVERAGE_UNASSESSED');status='CANNOT_VERIFY'
    return Decision(status,tuple(sorted(reasons)),tuple(sorted(evidence)),success)
