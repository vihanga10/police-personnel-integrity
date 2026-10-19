# Read-only SRB source inspection

Inspect officer_police_numbers.csv, officer_restrictions.csv and
restriction_overrides.csv from the registered BATCH-RAW-001 archive. These are
reported SRB sources under the existing pinned source confirmation.

The command checks application database identity, archive membership, exact
headers, row sequence and registered counts. It recovers each staged row with
both primary and backup keys, and reports aggregate exact-NIC evidence candidates,
missing fields, repeated reported keys, date shapes, ISO endpoint ordering,
recognized rank labels and boolean text shapes. Unknown labels are never printed.

No new source system, assertions, identifier versions, normalized records or
classifications are created. No Mongo connection is made. Candidate linkage is
not accepted historical eligibility. A repeated police number may describe a
version or reuse. A verifiable flag is a source claim, not completed verification.
Endpoint comparisons do not establish interval inclusion or open-ended semantics.
Restriction effects, override applicability, authority and cross-file references
remain for later planners. No personnel values or plaintext plans are saved.

The broader remaining-source inventory also includes duty periods, conduct,
firearms, education, family, operations, complaints, court, demotion and Sinhala
station evidence. Their transformations are not declared complete by this step.
