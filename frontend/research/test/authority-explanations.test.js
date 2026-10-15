import test from 'node:test';
import assert from 'node:assert/strict';
import {authorityMeanings,explainAuthorityReasons} from '../src/authority-explanations.js';
test('every currently emitted authority reason for uncertain outcomes has a simple explanation',()=>{
 const reported=['ACTION_DATE_SEMANTICS_UNASSESSED','GOVERNING_RULE_UNASSESSED','DELEGATION_EVIDENCE_UNASSESSED','ACTOR_STATE_AT_ACTION_DATE_UNASSESSED','GEOGRAPHIC_AND_POWER_SCOPE_UNASSESSED','CLASSIFICATION_UNASSESSED','ACTOR_CLAIM_MISSING','ACTOR_IDENTITY_UNRESOLVED','ACTOR_CANDIDATES_AMBIGUOUS','ACTOR_CANDIDATE_NOT_ACCEPTED_HISTORICAL_IDENTITY','REPORTED_DELEGATION_REFERENCE_NOT_AUTHENTICATED','REPORTED_DATE_MISSING','REPORTED_DATE_INVALID'];
 const history=['ACTOR_HISTORY_ACTION_DATE_MISSING_OR_INVALID','ACTOR_HISTORY_IDENTITY_UNRESOLVED','ACTOR_OUTSIDE_ANCHORED_UNIVERSE'];
 const typed=['ACTION_DATE_ACTOR_STATE_MISSING','DELEGATION_CYCLE_OR_DEPTH_UNRESOLVED','GOVERNING_INSTRUMENT_MISSING','GOVERNING_INSTRUMENT_UNASSESSED','INSTRUMENT_OUTSIDE_VALID_PERIOD','POWER_OR_TARGET_SCOPE_OUTSIDE_INSTRUMENT','DELEGATION_POWER_UNASSESSED','DELEGATION_NOT_PERMITTED','DELEGATION_RECIPIENT_DIFFERS','DELEGATION_REVOKED','DELEGATION_EXCEEDS_PARENT','AUTHORITY_PATH_UNRESOLVED','AUTHORITY_COVERAGE_UNASSESSED',...['ACTION_IDENTITY','ACTION_DATE','ACTOR_IDENTITY','ACTOR_ACTIVE'].flatMap(k=>[k+'_UNASSESSED',k+'_REFUTED']),...['RANK','ROLE','ACTOR_SCOPE'].flatMap(k=>[k+'_UNASSESSED',k+'_OUTSIDE_RULE'])];
 const retained=['ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE','FUTURE_ACTION_AUTHORITY_UNESTABLISHED_AT_KNOWLEDGE_TIME','ASSESSMENT_SOURCE_WORKSPACE_CHANGED'];
 for(const code of [...reported,...history,...typed,...retained])assert.ok(authorityMeanings[code],code);
});
test('unassessed data is not described as absent, and one failed route is not every route',()=>{
 assert.match(authorityMeanings.GOVERNING_RULE_UNASSESSED,/has not been assessed/);assert.match(authorityMeanings.ACTOR_SCOPE_OUTSIDE_RULE,/Other authority routes/);assert.match(authorityMeanings.AUTHORITY_COVERAGE_UNASSESSED,/cannot prove invalid/);assert.match(authorityMeanings.DELEGATION_EVIDENCE_UNASSESSED,/may not be needed/);assert.match(authorityMeanings.ASSESSMENT_ACTOR_EVIDENCE_CHANGED_OR_UNAVAILABLE,/cannot be reused/);
});
test('unknown or absent reason codes do not invent a cause or drop the uncertainty',()=>{
 assert.match(explainAuthorityReasons([])[0],/without a detailed reason/);assert.match(explainAuthorityReasons(['FUTURE_UNKNOWN_CODE'])[0],/exact server reason/);assert.equal(explainAuthorityReasons(['ACTOR_IDENTITY_UNASSESSED','ACTOR_IDENTITY_UNASSESSED']).length,1);
});
