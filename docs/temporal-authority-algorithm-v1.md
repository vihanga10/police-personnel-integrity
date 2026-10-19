# Temporal authority and delegation algorithm v1

Status: pure algorithm foundation, tested with controlled facts. No research authority audit has run. No authority/delegation source adapter, CLI, findings persistence or findings anchoring is included in this step.

## Inputs and trust boundary

`temporal_authority.evaluate` accepts a typed action (actor, action date, power, target scope), dated actor states, governing rules, delegation instruments and an explicit coverage assessment. Sensitive values and provenance references are hidden from object reprs but belong only in protected research memory and encrypted artifacts. Do not print dataclass dictionaries or persist plaintext decisions.

An external authenticated adapter must verify exact anchored source/destination bindings and a fresh audit permit before research execution. The adapter must establish which evidence and rule assessments are justified; a caller-supplied ASSESSED label is not cryptographic proof. This pure engine does not issue permits, validate chains, authorize human disclosure or load personnel data. It does not convert existing CANNOT_VERIFY historical projections into assessed actor facts.

`Fact` values are ASSESSED, UNASSESSED or CONFLICTING. ASSESSED values require provenance references. Actual research facts retain their unresolved assessments. Tests deliberately use invented rules and assessed fixture facts to exercise VALID and INVALID paths; those outcomes do not validate Sri Lanka legal powers.

No rank hierarchy or universal SP-and-above authority is hardcoded. Governing rules must specify the exact action power, eligible ranks/roles, actor scopes, target scopes and applicable dates. Scope sets contain explicit assessed catalog memberships, not inferred relationships between matching station names. Signature text or rank alone is insufficient authority evidence.

## Decisions

- VALID: at least one fully assessed direct or delegated route supports the action.
- INVALID: all available routes are refuted and the supplied applicable authority-rule/delegation coverage is explicitly assessed complete.
- CANNOT_VERIFY: identity/date/state/instrument is unresolved, or no successful route exists and coverage is not established complete. Absence of a delegation record alone is not invalidity.

Reasons retain failures from alternative routes as well as the successful route marker. `successful_paths` identifies which route actually supports VALID; a refuted alternative does not overturn a successful independent route. Evidence references are retained for encrypted explanation storage later.

## Temporal and delegation conventions

Assessed instrument dates use half-open intervals `[start,end)`. An open end is allowed only as an assessed instrument interpretation, never inferred from an empty reported CSV field. Source date assessment happens outside this engine. Issuance cannot follow the delegation start.

Every delegation must match its recipient, power and target scope; granted power/scope sets cannot exceed the parent. Parent delegation permission must be explicit. Revocation is effective from its assessed date inclusively. Subdelegation requires permission at every link. Missing parents, cycles and chains reaching 16 traversed instruments remain unresolved; memoization avoids repeated evaluation of identical paths.

V1 conservatively requires issuer authority both when the delegation was issued and at the action date. This is a versioned algorithm convention, not a universal legal assertion. A future authenticated rule model may distinguish continuing-authority and surviving-delegation semantics. Do not relax this convention for a research action without supporting rule evidence and versioned tests.

Actor state must match the exact requested date. A current snapshot is not automatically state on a historical action date. Inactive assessed service refutes a route. Unassessed actor identity prevents attributing a route failure to a definite person.

## Current research checkpoint

Operator-supplied selected-officer reconstruction `20695f7f-d45c-4693-89df-1c89d2894ed7` passed at revision `27783ef2213885a47029e5ba0cb8780bb979869f` for 2024-12-31. Its protected saved explanation review `5057d027-be31-4413-8523-f7458d9b39b9` passed. Rank, posting, police number and service status remained CANNOT_VERIFY; one restriction interval remained REPORTED_CANDIDATES. No accepted historical state or authority conclusion was established. The selected officer was not proven identical to the earlier v1 selection.

## Next integration

After tests and source commit, inspect the existing anchored actor/action fields and governing-rule/delegation coverage without displaying identifiers. Build an adapter that preserves unresolved candidates and explains missing action-date authority evidence. A fresh audit gate must precede actual research execution. Encrypted append-only findings storage and both-chain findings commitments follow separately. Original evidence and initial anchors stay preserved; Stage 3 remains in progress.
