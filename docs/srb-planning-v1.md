# SRB police-number, restriction and override planning

Policy: SRB_PLAN_V1. This step assesses encrypted staged claims in a read-only
PostgreSQL transaction; it creates no SRB source-system row and connects to no Mongo.

## Coverage and preservation

- officer_police_numbers.csv: 15,123 rows and nine columns.
- officer_restrictions.csv: 10,971 rows and 24 columns.
- restriction_overrides.csv: 150 rows and ten columns.
- Every original string is retained, including leading zeros and whitespace.
- Field routes must match docs/field-routing.json exactly, with no missing or
  duplicated source columns and protected staging preservation enabled.
- Only strict ISO calendar dates and observed TRUE/FALSE flags are parsed.
  Unsupported text is preserved and flagged. Categories without an approved
  dictionary remain reported labels with null structured codes.

## Candidate and consistency checks

The read-only command verifies archive membership, source confirmation, exact
headers, row binding, registered counts and primary/backup recovery. Each subject
requires exact encrypted NIC candidate evidence. Actor NICs are checked separately;
missing or ambiguous actors remain review issues, never guessed from rank.

Restriction and transfer references are indexed from recovered, source-qualified
rows. An override reference must have one matching source row and the same subject
candidate. Missing, ambiguous, wrong-source or wrong-subject links are flagged.
The transfer index contains 33,316 original PF transfer rows, preserving cancelled
claims. Matching a cancelled transfer does not establish that an override applies.

Reported override_recorded flags are compared with supplied override subject
candidates. These observations do not establish valid authority or legal effect.
Restriction station names/codes use source-scoped station-master matches;
historical hierarchy and scope meanings remain unassessed. Partial station or
removal evidence is flagged without manufacturing absent fields.

Date ordering issues are flagged without rewriting dates. Number-period comparisons
count positive intersections among explicitly bounded dates for the same subject
and reported number type. Missing ends are not treated as infinity, and touching
boundaries are not called overlaps without a boundary policy. Intersections are
observations, not final contradiction findings or proof that concurrent numbers
are prohibited. Duplicate reported source keys are counted for subsequent review.

## Encrypted recovery and limits

Every row plan is sealed and reopened with primary and backup keys in memory.
Authenticated context binds the filename, officer UUID, raw-row digest and policy
versions. Source text, actor/reference candidates and station provenance remain
inside the encrypted payload. No plaintext plan is saved or personnel value printed.

The envelope retains classification UNASSESSED, authority assessment NOT_RUN,
null authority result, null accepted valid_from/valid_to and null reconstructed
state. Parsed reported dates are field claims, not accepted historical periods.
An ASP or other rank label does not approve an override. A verifiable source flag
does not replace our verification result. Missing removal does not prove an active
restriction; missing number end does not prove current eligibility. A transfer
specific override does not automatically remove an entire restriction.

Planning success is not import readiness. Review findings and semantic uncertainties
must be assessed before normalized import or reconstruction. Human RBAC/ABAC and
source independence remain pending. Stage 2 remains in progress.
