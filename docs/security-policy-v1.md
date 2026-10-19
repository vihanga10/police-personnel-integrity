# Personnel security policy — version 2

The existing filename is retained for repository continuity. Updated by the
2026-10-07 decision: encrypted storage for all personal payloads and scoped
visibility of former CID/CCIB service periods.

Status: DRAFT — requirements recorded; enforcement not yet implemented.
Policy helper: CID_CCIB_PROTECTION_V2. Full human authorization remains pending.
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
- Encrypt all stored personal payloads for all officers in PostgreSQL and
  MongoDB, including ordinary officer profiles and service/history evidence.
- Ordinary authorized application views decrypt permitted details within scope;
  they do not require special IGP approval solely because storage is encrypted.
- Opaque IDs, source digests and required technical routing metadata may remain
  outside ciphertext; they remain internal and subject to database permissions.
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
- After a verified transfer to an ordinary unit, the receiving authority may
  view an authorized narrow summary of previous CID/CCIB unit and service-period
  start/end dates for officers currently within that authority's scope.
- Service-period dates require traceable historical evidence; unknown dates stay
  unknown. Reported dates must not be represented as verified periods.
- This exception does not expose source documents, operations, duties, reasons,
  linked participants, narratives or other CID/CCIB activities.
- Restrict CID/CCIB operations, duties, activities and related source documents
  after transfer. Current CID/CCIB personnel still require restricted access
  for their service-period details.
- Review mixed records and derived outputs for indirect disclosure.
- Ordinary current information may be disclosed through an authorized view;
  this does not release all historical versions.
- Classification changes require authorized, recorded decisions.

## 5. Access rules

- IGP may view restricted CID and CCIB details nationwide.
- HQ Admin requires valid IGP approval for restricted viewing.
- Station OIC and other designated receiving authorities may view ordinary
  current details and the narrow former-service summary only within their
  verified active responsibility; rank alone does not establish scope.

- SDIG responsible for CID: may view CID-restricted information.
- SDIG responsible for CCIB: may view CCIB-restricted information.
- Access requires a verified active appointment and explicitly assigned
  unit responsibility. Rank or Colombo location alone does not grant access.
- Responsibility for both units permits access to both.
- Unit-scoped access includes corresponding restricted historical records
  after personnel transfer out.
- Access through an appointment ends when that appointment ends.
- Other SDIGs receive no automatic CID/CCIB-restricted access.
- These rules grant viewing only; amendment and export require separately
  defined permissions.

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
- Protected operations and activities remain restricted after transfers.
- Only the narrow former-service period projection receives the approved
  ordinary-scope exception; full history records remain restricted.
- Transfer into CID/CCIB restricts personnel disclosure immediately once the
  assignment is established; storage remains encrypted throughout.
- HQ Admin cannot bypass approval.
- Expired and revoked grants stop further access.
- Read permission does not imply write or export permission.
- Equivalent enforcement across both databases and all disclosure paths.
- Logs contain sufficient evidence without sensitive payloads.
- Missing or contradictory classification evidence does not grant access.

## 11. Open decisions and implementation status

- SDIG viewing scope is limited to explicitly assigned CID/CCIB responsibility.
- Trusted appointment evidence and its validation remain to be implemented.
- Detailed name/NIC visibility follows the ordinary authorized identity scope.
- Encrypted profile/service storage is implemented; history storage foundation
  is verified separately. Full classification, authorization and logging are pending.
- No decryption/re-encryption migration is needed for this viewing-rule update.
- Classification of existing historical rows requires source-based validation.
- Approval duration and audit retention remain configurable policy decisions.
- This document alone does not implement encryption, authorization or logging.

## 12. Record entry and evidence preservation

- HQ Admin is the only human application role permitted to import source
  files and enter personnel records.
- The backend validates, encrypts and saves accepted submissions with
  source references and the submitting user's identity.
- Import permission does not grant permission to view restricted
  CID/CCIB information.
- Restricted viewing by HQ Admin requires a valid IGP approval.
- Existing evidence content must not be overwritten.
- Corrections create new versions linked to the previous evidence.
- Existing controlled version-closure rules remain applicable.
- Application users cannot delete personnel evidence, audit findings
  or access-log records.
- Automated audit processes may append findings with explanations,
  supporting evidence references and the algorithm/policy version.
- Resolutions and reassessments are appended and linked to the
  original finding; previous findings remain preserved.
- Database permissions and version controls enforce preservation.
  Blockchain commitments provide tamper evidence for anchored records.
- Correction approval, export, account administration and audit-log
  viewing permissions remain to be specified.
