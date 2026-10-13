# Priority 3: application research reviews and corrections

Stop the server with Ctrl+C. Extract into Downloads and run:

```bash
bash "$HOME/Downloads/application-priority3-review/run-priority3.sh"
```

Sign in at https://127.0.0.1:8443 and choose **Review & correction inbox**.
The dedicated page is `/reviews`. Search a permitted officer by name/NIC, select
them, choose an effective date, and use the exact last recorded knowledge boundary.
Give a reason and save a comparison as a finding. The backend runs the existing
history/contradiction algorithms; it does not accept client-computed conclusions.

Select the finding and submit a review request. Sign out and use a different
authorized account to inspect and approve, reject or request more evidence.
Approval of a correction appends a new comparison version; rejection/more evidence
does not advance the finding head. Every prior version and request is retained.
Unchanged corrections, changed source copies, changed heads and competing decisions
are refused. A needs-more-evidence request can be resubmitted once, by its original
requester, using its reference in the optional field.

| Account role | Requests | Scoped inspection | Approval |
|---|---|---|---|
| IGP | Yes | All permitted officers | Yes |
| SDIG | Yes | Assigned province | Yes |
| DIG/SSP/SP | Yes | Assigned district/division | Yes |
| HQ Admin | Yes | All permitted officers | No |
| Station OIC | No | Existing officer viewing unchanged | No |
| Inactive | No | No | No |

Self-review is always forbidden, including rejection and asking for more evidence.
Current signed accounts, disclosures and scope apply independently of the signed
research policy. Requester revocation/account version, reviewer session, source and
policy are checked again during the atomic commit. Browser role/scope fields are
not accepted. Existing fixed 30-minute sessions and privacy clearing remain active.

**These are generated research application approvals.** They are not legal police
authority decisions, accepted personnel state, independently witnessed findings or
blockchain receipts. The original protected police review runners remain unchanged
and still require separately assessed temporal authority and reviewer identity.
The original two officers' protected findings/requests are not silently migrated or
marked approved. New application findings are kept in separate encrypted append-only
tables linked to the workspace event chain. Whole-store rollback resistance requires
external witnesses/pins; this application step does not establish it.

Corrections here correct a finding using a changed supported query, not an officer's
underlying NIC/rank/posting. Source-fact corrections still require controlled intake/
recording. A one-point baseline does not support invented earlier system knowledge.
All 6,596 retained histories and original datasets/journals remain preserved.

## Recovery and accountability

Mutations have exact immutable operation UUIDs. Double clicks are blocked and there
are no automatic mutation retries. After a timeout, read the retained operation.
Manual retry preserves exact original content and UUID. A not-found check does not
rule out an in-flight commit. After reopening the page, load recent retained
operations. No personnel data or operation bodies are stored in browser storage.
Logout/backgrounding clears the screen, not stored entries/logs. Browser closure
does not establish an exact logout time. Existing server session lifecycle logs
remain active. HQ's separate log-reading grant is still required.

HQ can inspect retained request/decision events and operation IDs in Access logs.
Decision reasons distinguish research APPROVE/REJECT/NEEDS_MORE_EVIDENCE. Full human
explanations and comparisons are retained in the authorized review inbox. Passwords
and session tokens are excluded from logs.

## Change policy later

Only the private stopped-app operator command changes signed policy. Write an
owner-only JSON draft outside the repository with exactly:

```json
{"request_roles":["IGP","HQ_ADMIN","SDIG","DIG","SSP","SP"],
 "review_roles":["IGP","SDIG"],
 "inspect_roles":["IGP","HQ_ADMIN","SDIG","DIG","SSP","SP"],
 "reason":"Documented reason for changing reviewer permissions"}
```

```bash
cd "$HOME/Developer/police-personnel-integrity/backend"
uv run python scripts/manage_priority3.py policy-update \
  --repository "$HOME/Developer/police-personnel-integrity" \
  --app-root "$HOME/ResearchKeys/police-personnel-integrity/research-app-v1" \
  --policy-draft /absolute/path/to/private-reviewed-policy.json
```

Each signed policy version references the previous one and logs time, signer and
reason. Old approvals are not rewritten; pending decisions use current permissions.
Self-approval cannot be enabled. Scope changes still require signed account updates
and explicit policy rebinding. Initial setup is idempotent and will not reset a
subsequently changed policy. Encryption/signing keys remain private on your Mac.

## Acceptance

Test DIG save/request, IGP independent decision, self-review denial, HQ inspection,
out-of-scope denial, appended correction versions, recovery after restart, and
retained logs after logout. Automated tests use invented fixtures, actual crypto,
SQL, the existing algorithms, HTTPS and DOM execution. They do not establish
independent legal ground truth, research precision/recall/F1 or graphical rendering.
Installation and browser acceptance on your Mac remain required after delivery.
