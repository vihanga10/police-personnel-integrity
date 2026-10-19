# Read-only remaining HR/PF source inspection v1

Built on clean committed checkpoint `486e1a0`, after verified SRB activity import.
No new models, migrations, Mongo collections, imports or permissions are added.

| File | Reported supplying source | Inspection focus |
| --- | --- | --- |
| officer_education.csv | POLICE_HR_IS | Qualification years/numeric shapes; subject/grade container shapes |
| officer_family_details.csv | POLICE_HR_IS | Date/signature/reference presence; recorder NIC candidates; child-text shapes |
| operations.csv | PF_REGISTRY | Dates, numeric/boolean shapes, commander NIC candidates, participant-text shapes |
| court_details.csv | PF_REGISTRY | Dates, source IDs/references and participant-text shapes |
| public_complaints.csv | PF_REGISTRY | Subject/actor NIC candidates, dates/flags and cross-source reference presence |
| _demotions_enacted.csv | PF_REGISTRY | Subject NIC candidates, reported punishment date/rank and source key repetition |

The source assignment follows the pinned intake-source-confirmation.json.
NPC references inside PF complaints do not establish direct receipt from NPC or
independent corroboration. Original supplying-source declarations remain separate
from authenticity/independence/source-truth assessments.

The inspector recovers every selected staged row using primary and backup keys
inside one repeatable-read, read-only PostgreSQL transaction. It verifies pinned
batch/archive/confirmation membership, exact header order, file/row provenance,
source row sequence and the registered row counts. Counts are read from verified
staging contracts rather than guessed for these previously uninspected files.

Only aggregate output is emitted: missing fields, source-key repetition, exact
NIC evidence candidate states, recognized rank labels, fixed boolean/date/numeric
shapes, and reference/signature/container presence. Unknown labels/free text,
identifiers, names, source keys, parsed nested contents and actual dates are not
printed. Education and family files have no declared source record ID; NIC is
not promoted into a unique immutable record key. Operations/court rows have no
single subject NIC field; participant blocks are not treated as accepted links.

Nested text is observed as JSON_LIST/JSON_OBJECT/JSON_SCALAR, malformed JSON-like
text, delimiter-containing text or other text. No delimiter schema, officer list,
family relationship, legal effect, historical authority or accepted period is
inferred. Parsed contents stay in memory and are never saved as plaintext.

Run focused tests, then `python -m app.identity.inspect_remaining_sources` with
separate existing primary/backup identity key files. The inspector performs no
Mongo connection, database writes, classification changes or user disclosure.
Results guide the next targeted format review and planners/imports. Source-scoped
station/Sinhala reference data still needs its own applicability/completion review.
Stage 2 remains in progress.
