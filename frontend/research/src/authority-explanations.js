// Presentation only: the server supplies the outcome and exact reason codes.
// Unassessed evidence is not necessarily absent; a failed route is not proof
// that every possible authority route failed.
export const authorityMeanings = Object.freeze({
  ACTION_DATE_SEMANTICS_UNASSESSED:'The reported date has not been checked as the date this action was authorized or performed.',
  ACTION_DATE_UNASSESSED:'The meaning of the action date has not been checked.',
  ACTION_DATE_REFUTED:'The supplied assessment does not support this date as the action date.',
  ACTION_IDENTITY_UNASSESSED:'The link between this action and the person who performed it has not been checked.',
  ACTION_IDENTITY_REFUTED:'The supplied assessment does not support the action’s claimed identity link.',
  ACTOR_CLAIM_MISSING:'The source record does not identify the person who performed this action.',
  ACTOR_IDENTITY_UNRESOLVED:'The reported approving or acting person has not been reliably linked to an officer.',
  ACTOR_HISTORY_IDENTITY_UNRESOLVED:'The system could not link the reported person to a historical officer record.',
  ACTOR_CANDIDATES_AMBIGUOUS:'More than one officer could match the reported person; no match has been accepted.',
  ACTOR_CANDIDATE_NOT_ACCEPTED_HISTORICAL_IDENTITY:'A possible officer match exists, but it has not been accepted as the person responsible on that date.',
  ACTOR_IDENTITY_UNASSESSED:'The acting officer’s identity has not been checked for this historical state.',
  ACTOR_IDENTITY_REFUTED:'The supplied assessment does not support this historical identity.',
  ACTOR_STATE_AT_ACTION_DATE_UNASSESSED:'The person’s rank, role, service status and responsibility on the action date have not been assessed.',
  ACTION_DATE_ACTOR_STATE_MISSING:'No required historical state was supplied for the person on a date needed by the authority check.',
  ACTOR_HISTORY_ACTION_DATE_MISSING_OR_INVALID:'The action date is missing or cannot be interpreted as a valid calendar date.',
  ACTOR_OUTSIDE_ANCHORED_UNIVERSE:'The required officer’s history is unavailable in the connected evidence used by this check.',
  CLASSIFICATION_UNASSESSED:'The reported record has not been assessed for historical use; storing it does not establish its authority.',
  GOVERNING_RULE_UNASSESSED:'The rule giving the person power to perform this action has not been assessed.',
  DELEGATION_EVIDENCE_UNASSESSED:'Any delegated authority has not been assessed. A delegation may not be needed if direct authority can be established.',
  REPORTED_DELEGATION_REFERENCE_NOT_AUTHENTICATED:'The source mentions a delegation, but that reference has not been checked against an authenticated instrument.',
  GEOGRAPHIC_AND_POWER_SCOPE_UNASSESSED:'It has not been checked whether the person’s powers covered this action and the relevant officers or area.',
  ACTOR_ACTIVE_UNASSESSED:'The person’s active service status on the required date has not been assessed.',
  ACTOR_ACTIVE_REFUTED:'The supplied assessment does not support active service on the required date for a tested route.',
  RANK_UNASSESSED:'The person’s rank on the required date has not been assessed.',
  ROLE_UNASSESSED:'The person’s role on the required date has not been assessed.',
  ACTOR_SCOPE_UNASSESSED:'The person’s area of responsibility on the required date has not been assessed.',
  RANK_OUTSIDE_RULE:'The assessed rank does not meet a tested rule. This rules out that route, but does not establish that every possible route fails.',
  ROLE_OUTSIDE_RULE:'The assessed role does not meet a tested rule. Other authority routes may still need checking.',
  ACTOR_SCOPE_OUTSIDE_RULE:'The assessed area of responsibility does not meet a tested rule. Other authority routes may still need checking.',
  GOVERNING_INSTRUMENT_MISSING:'A rule or parent delegation needed to trace an authority route was not supplied.',
  GOVERNING_INSTRUMENT_UNASSESSED:'A rule or delegation needed by an authority route has not been assessed.',
  INSTRUMENT_OUTSIDE_VALID_PERIOD:'A tested rule or delegation did not cover a date required by that route.',
  POWER_OR_TARGET_SCOPE_OUTSIDE_INSTRUMENT:'A tested rule or delegation does not cover the requested power or target scope.',
  DELEGATION_CYCLE_OR_DEPTH_UNRESOLVED:'The delegation chain loops or exceeds the checking limit, so that route could not be resolved.',
  DELEGATION_POWER_UNASSESSED:'It has not been assessed whether the person was allowed to pass this power to someone else.',
  DELEGATION_NOT_PERMITTED:'A tested instrument does not permit passing this power to another person.',
  DELEGATION_RECIPIENT_DIFFERS:'A tested delegation names a different recipient from the person being checked.',
  DELEGATION_REVOKED:'A tested delegation had been revoked by a date required by that route.',
  DELEGATION_EXCEEDS_PARENT:'A tested delegation grants powers or target scope beyond its parent instrument.',
  AUTHORITY_PATH_UNRESOLVED:'At least one tested authority route still depends on unresolved evidence.',
  AUTHORITY_COVERAGE_UNASSESSED:'It has not been established that all applicable rules and delegations were supplied. Failed supplied routes alone cannot prove invalid authority.',
  ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE:'Officer evidence used by an earlier assessment changed or is unavailable, so that earlier result cannot be reused as current.',
  ASSESSMENT_SOURCE_WORKSPACE_CHANGED:'The action’s retained source copy no longer matches the earlier assessment, so that assessment cannot be applied here.',
  FUTURE_ACTION_AUTHORITY_UNESTABLISHED_AT_KNOWLEDGE_TIME:'The action is later than the selected knowledge time; its authority cannot be established from evidence known by that time.',
  REPORTED_DATE_MISSING:'The source record has no date for this action.',
  REPORTED_DATE_INVALID:'The reported date cannot be interpreted as a valid calendar date.',
  REPORTED_DATE_PARTIAL:'The reported date is incomplete; an exact action date has not been established.'
});

export function explainAuthorityReasons(items){
  const codes=Array.isArray(items)?items.filter(code=>typeof code==='string'):[];
  const messages=[...new Set(codes.map(code=>authorityMeanings[code] ||
    'An additional evidence condition remains unresolved. Its exact server reason is available under Technical assessment reasons.'))];
  return messages.length?messages:['The server returned Cannot verify without a detailed reason. No specific missing evidence can be identified from this response.'];
}
