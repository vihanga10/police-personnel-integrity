# Personnel security policy — version 1

Status: DRAFT — requirements recorded; enforcement not yet implemented.
Implementation baseline: 6ef032a.
Scope: PostgreSQL, MongoDB and application disclosure paths.

## 1. Purpose

Protect personnel information through encryption, role-based access control
(RBAC), attribute-based access control (ABAC), controlled approvals and
accountable access.

This policy defines research-system requirements. It does not claim to
represent an officially approved Sri Lanka Police policy.

## 2. Storage and identity

- Retain the permanent internal officer_uid as the cross-database identity.
- Retain existing encrypted NIC and other identifier storage.
- Name and NIC are exceptions to CID/CCIB restricted disclosure, not
  instructions to remove encryption.
- Name and NIC visibility still requires authenticated, authorized access.
- Protect remaining personnel information in both databases through the
  encryption design established during the model review.
- Keep encryption keys outside database records and source control.
- Do not put personnel values or encryption keys on a blockchain.

## 3. Current-assignment protection

- When an officer's current assignment is CID or CCIB, all personnel
  information except the permitted name/NIC display requires restricted access.
- Evaluate the current assignment using authoritative, traceable records.
- Do not treat missing or contradictory assignment evidence as ordinary access.
  Withhold affected information pending resolution.
- Apply these rules across PostgreSQL and MongoDB.

## 4. Historical protection and transfers

- Preserve record-level classification and the evidence supporting it.
- Record originating unit and relevant source references where supported.
- Do not guess historical classification from current assignment alone.
- A transfer out of CID/CCIB must not automatically declassify CID/CCIB history.
- A receiving Station OIC may view permitted ordinary current information
  for officers assigned to that OIC's station.
- A permitted summary may state that the officer previously served in
  CID/CCIB, without disclosing protected dates, duration or work.
- Restrict CID/CCIB operations, duties, service-period details and related
  documents after transfer.
- Review mixed records and derived outputs for indirect disclosure.
- Ordinary current information may be disclosed through an authorized view;
  this does not release all historical versions.
- Classification changes require authorized, recorded decisions.

## 5. Access rules

- Deny access unless a rule explicitly allows it.
- Evaluate authorization in the backend for every request.
- IGP: permitted restricted access under the configured application role.
- SDIG: eligible for restricted access, but the national-versus-assigned
  scope decision remains unresolved. Do not implement a blanket national
  grant until this decision is recorded.
- HQ Admin: ordinary administrative access; restricted CID/CCIB access
  requires a valid, scoped IGP approval.
- Station OIC: permitted ordinary information for the assigned station;
  no access to protected CID/CCIB history.
- Other roles: existing authorized scope only; no implicit restricted access.
- Evaluate current appointment and account status, not rank text alone.
- Treat view, add, amend, approve and export as separate permissions.
- Permission to view must not automatically permit editing or exporting.
- Application HQ Admin status must not imply database-superuser or key access.

## 6. ABAC inputs

Evaluate:
- User identity, role, active appointment and assigned scope.
- Target officer, current assignment and record classification.
- Requested action and relevant record fields.
- Approval scope, approver, validity period and revocation state.
- Required authentication and request context.

Use trusted backend attributes. Never trust a client-supplied role,
classification or approval claim.

## 7. HQ Admin approval

- Record the requester, purpose, requested records, actions and duration.
- Require approval by an authorized IGP account.
- Prohibit self-approval.
- Grant only the approved scope and actions.
- Require an expiry and support revocation.
- Check approval validity whenever restricted data is requested.
- Export requires explicit permission.
- Record requests, approvals, rejections, revocations and grant usage.

## 8. Disclosure paths

- Enforce the same policy for detail views, searches, reports and exports.
- Prevent restricted fields from leaking through errors, caches, logs,
  linked records or derived summaries.
- Restrict source/staging access and background processing accounts.
- Protect backups and retained copies.
- Frontend hiding alone is not authorization.

## 9. Accountability

Record:
- Event ID and timestamp.
- Stable actor ID and protected actor-name reference or snapshot.
- Role and scope used for the decision.
- Action, target officer and affected record references.
- Field names or categories disclosed, without copying sensitive values.
- Allowed, denied, failed or redacted outcome and reason.
- Approval ID when applicable.
- Policy version and request/session correlation ID.
- Source and destination version references for changes.

Log authentication, disclosures, denied requests, changes and approvals.
A disclosure log records what the system returned, not proof of human reading.
Exclude passwords, tokens, encryption keys and decrypted personnel payloads.
Restrict access to logs and record access to sensitive audit information.
Preserve audit events; introduce tamper-evident anchoring in the audit stage.
For restricted disclosure, require durable audit recording before release.

## 10. Verification requirements

Verify:
- Current CID/CCIB profile restrictions.
- Permitted name/NIC display with protected storage retained.
- Unauthorized and out-of-scope requests are denied.
- Restrictions persist after transfers.
- HQ Admin cannot bypass approval.
- Expired and revoked grants stop further access.
- Read permission does not imply write or export permission.
- Equivalent enforcement across both databases and all disclosure paths.
- Logs contain sufficient evidence without sensitive payloads.
- Missing or contradictory classification evidence does not grant access.

## 11. Open decisions and implementation status

- SDIG restricted-access scope requires an explicit decision.
- Detailed name/NIC visibility follows the ordinary authorized identity scope.
- Physical encryption layout and migration requirements require model review.
- Classification of existing historical rows requires source-based validation.
- Approval duration and audit retention remain configurable policy decisions.
- This document alone does not implement encryption, authorization or logging.
