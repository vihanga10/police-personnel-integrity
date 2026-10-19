# Remaining source planning v1

Sources: HR education (6,596) and family (6,596); PF operations (19,554),
courts (9,538), complaints (998) and demotions (8). Total: 43,290 rows.

Every original cell is preserved inside an authenticated encrypted planning
envelope. Coverage, source column order and existing routing are checked.
Routes are preparation targets, not a claim that destination schemas/importers
are ready. Family fields retain their existing SQL routing; other files retain
Mongo routing. This step changes no routing or destination storage.

Dates are parsed as reported dates; valid periods stay unknown. Times carry no
inferred timezone/day boundary. Counts reject fractions and negative values;
Decimals preserve precision and reject nonfinite values. GPA, durations and
monetary plausibility/unit policy remain unassessed. Known full ranks and the
observed family recorder abbreviations are source claims, not authority.

Subject and actor NIC candidates use the shared dual-key encrypted verifier.
Alternate complaint subject NICs remain separate; missing optional senior NICs
are preserved as missing. Unresolved alternate identifiers are flagged without
repair. Operations/courts have no invented single-officer subject. Participant
and child list lengths are observations, never accepted positional linkage.
Nested court participant schemas remain unassessed. Demotions and complaint
outcomes are preserved and never automatically applied.

Source archive/confirmation, registered file count/header/row provenance, SQL
application target and separate primary/backup keys are checked in one read-only
snapshot. All six expected row counts are pinned. Each plan is encrypted and
opened with both keys in memory; no plaintext plans are saved. Reference-key
observations are repeated separately, with linked_case_no comparison provisional.
Authority, source independence, classification and historical applicability
remain unassessed. No Mongo connection, database write or human disclosure.
Planning success does not imply import readiness. Stage 2 remains in progress.
