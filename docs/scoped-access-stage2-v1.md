# Stage 2 — authentication and scoped identity access

Base: `d3953a6`, `feat/identity-resolution`. This stage adds a working configured
HTTPS backend for login, session lookup, logout, NIC/name search and direct
identity lookup. It uses the existing FastAPI/cryptography dependencies. There
is no public user registration, default account or automatic research provisioning.
No original source, database, evidence anchor or stage-1 runner is changed.

## Scope policy

| Approved current account role | Permitted officer membership |
| --- | --- |
| IGP | ALL |
| HQ_ADMIN | ALL |
| SDIG | One canonical province |
| DIG | One approved canonical district or division |
| SSP | One approved canonical district or division |
| SP | One approved canonical district or division |
| STATION_OIC | One canonical station, with administrator-reviewed appointment |
| Other roles, ranks below OIC, malformed or expired grants | Denied |

Scope IDs are exact backend-owned identifiers, not guessed station names. The
scope map explicitly covers every original anchored officer, including unknown
membership as NULL. Missing membership denies scoped accounts. Full-scope users
may see the identity projection for officers with unknown geographic membership.
A child scope cannot have contradictory parents in the directory.

A current signed ACCOUNT grant records role, scope, immutable account UUID,
canonical login, version, active status and appointment/review reference.
Administrators issue a new version for a password, scope or activation change.
Every authenticated request checks the current stored version and grant validity;
old sessions cannot retain revoked privileges. The role is an approved account
entitlement, not a client claim or an inference from an officer's reported rank.

These rules concern current web disclosure. They neither infer past authority nor
replace temporal authority/delegation verification at action time. Both grants
and directory attestations expire within 24 hours; refresh requires explicit
reviewed administrative action. Expiry is checked with server time, and sessions
also reject a backward clock relative to their creation/last-use time.

## Directory and original evidence

`export_access_directory.py` uses the unchanged `load_verified_snapshot` before
building a private signing draft. Both recovery keys, exact original public
commitments and a fresh audit permit remain mandatory. An independently reviewed
signed MEMBERSHIP map must reference the same original public digest and explicitly
cover all officers. Province/district/division/station values are not derived from
unresolved CSV text, historical transfer dates or request parameters.

The export preserves the original subject-role candidate linkage. It requires one
complete bound profile per anchored officer. It takes only the reported officer's
own NIC, full name/name with initials, officer UID and raw source reference.
It does not accept a candidate as established historical identity. A separate
configured directory administrator signs the draft before the access store imports
it. The whole envelope is authenticated and AES-GCM encrypted in the access DB.

A directory signature is an administrator attestation about search projection
and scope membership, not proof of external custody or source truth. The private
signing key stays outside the repository and web process. No HTTP endpoint can
import a directory, create an account, change a scope or sign a grant.

Current production directory export remains gated by original-source readiness.
RPC 1 is deferred. Disposable tests do not establish original-batch validity.

## Session and request enforcement

Passwords use salted scrypt (`N=2^17`, `r=8`, `p=1`, 32-byte output); the encrypted
account stores only the derived hash and salt. Hidden terminal input is required
for administrative password setup. New accounts require a privately set password
of 15–128 characters. User grants and authority keys are strictly schema-checked.

Login creates a new random 256-bit opaque session and independent random CSRF token.
The cookie is `__Host-ppi-session`, Secure, HttpOnly, SameSite=Strict, Path=/, with
no Domain. Session identifiers are stored as keyed hashes. Session payloads are
encrypted. Restart generates a new in-memory session-index key and invalidates old
sessions, including cookies from a restored DB. Absolute timeout is 30 minutes;
idle timeout is 10 minutes. Logout removes the server session. Login attempts are
bounded per canonical username and direct peer address, with persistent counters.
The server does not trust X-Forwarded-For or other proxy identity headers.

Only HTTPS with the configured Host is accepted. POST requires exact same Origin,
JSON, a body no larger than 4096 bytes, no duplicate JSON keys or extra fields.
Authenticated POST search/logout also require the session's CSRF token. Query
parameters, bearer/header identity claims, duplicate cookie/CSRF headers and
caller-supplied role/scope/date overrides are rejected. Errors never echo password,
NIC, name or request body. Responses have no-store and restrictive browser headers.
Search uses POST so NIC/name values do not enter URLs/access logs. The controlled
launcher disables request access logging and proxy-header trust.

## API contract

| Endpoint | Request/response |
| --- | --- |
| POST `/api/auth/login` | `{username,password}`; returns authenticated status/CSRF token, sets opaque secure cookie |
| GET `/api/auth/session` | Cookie required; returns current login role/scope, CSRF token and expiry |
| POST `/api/auth/logout` | `{}` plus cookie/CSRF; removes session and cookie |
| POST `/api/officers/search` | `{kind: "NIC" or "NAME", query, limit?:1..50, offset?:0..10000}` plus cookie/CSRF |
| GET `/api/officers/{officer_uid}` | Cookie required; identical 404 for absent or out-of-scope UID |

NIC follows existing `IDENTIFIER_EXACT_TEXT_V1`: outer whitespace is trimmed;
case, punctuation, leading zeros and old/new NIC formats are not guessed equivalent.
Name search uses Unicode NFKC/case folding and collapsed whitespace; Sinhala joiners
are supported. This matching aids candidate discovery only. At least three
normalized characters are required for name search. SQL wildcard text has no
special meaning. Scope filtering occurs before matching, counting, ordering and
pagination. Duplicate names can produce multiple permitted candidates; no identity
is silently merged. Ambiguity outside a user's scope is not exposed through counts.

Only `officer_uid`, own `names`, own `nic`, `source_raw_id`, projection and reported
candidate status are returned. CID/CCIB name/NIC still requires this base scope,
consistent with existing `record_protection.py`. Personnel details, family data,
operations, narratives, findings and arbitrary histories have no route here.
A future detail route must combine officer scope with record/category disclosure
policy; a successful name/NIC search is not blanket authorization.

Login/search never creates findings approvals, audit permits, wallet access or
chain submissions. Stage 1's original protected runners remain unchanged.

## Private state and provisioning

Access SQLite is a separate owner-only store outside the repository and original
research directories/databases. Original PostgreSQL/MongoDB credentials are not
loaded. Auth/session/projection payloads are encrypted under a dedicated raw
32-byte storage key; lookup indexes and audit subjects use domain-separated HMACs.
Private files reject symlinks, hardlinks, unsafe modes and foreign ownership.
Administration strictly advances account/directory versions. A locally authenticated
append-only access-event chain records coarse event codes and opaque subjects,
never search terms. Its SQLite update/delete triggers protect against ordinary
accidental edits; it is not an independently witnessed research findings journal.

A privileged restore of the entire access DB could restore an earlier still-valid
administrative grant; this is not claimed to be independently rollback-proof.
Restore requires reapplying current reviewed account/directory grants before
service activation. Previously issued web sessions remain invalid after restart.
Operating-system/database/key custody and trustworthy server time remain deployment
requirements. This version uses one ASGI worker with a bounded 16-connection
controlled launcher; it is not a distributed session service. MFA/SSO and AWS
provisioning are outside the requested password-login stage and not enabled.

Private config schema:

```json
{
  "policy": "SCOPED_ACCESS_CONFIG_V1",
  "repository": "/Users/YOUR_USER/Developer/police-personnel-integrity",
  "state_directory": "/PRIVATE_ACCESS_STATE_DIRECTORY",
  "key_file": "/PRIVATE_DEDICATED_RAW_32_BYTE_KEY_FILE",
  "authority_keys": {"ADMIN_KEY_ID": "BASE64_RAW_ED25519_PUBLIC_KEY"},
  "origin": "https://127.0.0.1:9443"
}
```

Place config/key/certificates and state outside the repository, files mode 600,
state/private parent directories mode 700. Paths above are schema placeholders,
not working credentials. Trusted administrators supply and review real settings;
this package generates no production keys. Offline `sign_access_grant.py` signs
only ACCOUNT/MEMBERSHIP/DIRECTORY domains. It cannot sign research/chain grants.
`manage_scoped_access.py init` explicitly initializes only this access DB. Account
import with `--set-password` prompts privately; changes without a new password
retain its existing hash. Directory import verifies signature, schema and generation.
Detailed command templates are in the package's `PROVISIONING.md`.

## Validation and sign-off

Tests cover every role's positive/negative scope, forged scopes, direct-ID bypass,
unknown membership, private projection, grant/ciphertext tampering, CSRF/Origin,
session fixation/revocation/logout/timeouts, Unicode and exact NIC matching,
count/pagination isolation, injection-shaped input, encrypted state and private
path restrictions. The directory exporter uses real AEAD/audit-permit fixtures;
its full original source loader is substituted explicitly in tests.

The real-HTTPS acceptance suite runs the actual ASGI backend in a subprocess and
uses a genuine TLS 1.3 socket, encrypted SQLite, signed grants and password KDF.
It exercises seven roles plus anonymous/CSRF/cross-origin/forgery/URL denial,
Sinhala search, live scope update and logout replay. All credentials and identity
records are disposable test fixtures. No original CSV or research database is used.
It removes its own server and temporary state/keys. There is no mock authentication
or HTTP transport in that suite.

Stage 2 implementation is accepted after focused tests and all 16 real-HTTPS
scenarios pass on the Mac and changes are reviewed/committed. Real account
provisioning, current approved membership, original directory export and AWS
activation remain explicit deployment work. The next application stage is the UI;
no production accounts, witness deployment or live research readiness is claimed.
