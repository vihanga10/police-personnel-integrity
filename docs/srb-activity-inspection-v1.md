# Read-only SRB activity source inspection v1

## Scope

Inspect registered encrypted staging for officer_duty_periods.csv (17 columns),
officer_firearms_expertise.csv (41), good_conduct_register.csv (33), and
bad_conduct_register.csv (31). Header order is pinned to the received routing
inventory; mismatch stops rather than silently adapting the source.

The inspector requires the reviewed BATCH-RAW-001 archive and confirmation,
reported SRB supplying source, exact headers, contiguous source row sequence,
file/row provenance, primary and backup decryption recovery, and registered
row coverage. It reads using the PostgreSQL application account in a repeatable
read, read-only transaction. There is no Mongo connection or import operation.

## Aggregate observations

Missing fields; source-key repeats/missing keys; subject and explicitly supplied
actor NIC candidate states; recognized rank labels; strict ISO date shapes;
reported duty/interdiction date ordering; finite numeric text shapes; reference
and signature presence; explicit CID/CCIB label counts. Missing ends are not
inferred as infinity. Numeric shapes do not establish money units, firearm
competency, scoring policy or conduct validity. Unknown ranks/boolean labels
and all arbitrary text are reduced to fixed labels, never printed.

Source references and signatures are not authenticated by being populated.
No historic role, delegation, accepted assignment, legal effect, complaint or
court linkage is established. Good/bad conduct source contents remain reported
claims and may require later contextual protection beyond unit restrictions.
No personnel-level output or plaintext files are saved. Only exception types,
not dependency messages or local values, are emitted on failure.

## Operator commands

After installation and focused tests, run from backend:

```bash
uv run python -m app.identity.inspect_srb_activity_sources \
    --key-file .secrets/identity-keys.json \
    --backup-key-file "$HOME/ResearchKeys/police-personnel-integrity/identity-keys-initial.json"
```

Send aggregate output for planner design. This inspector does not require a
clean Git tree and does not alter records or source classification. Save the
reviewed source/checkpoint in Git after inspecting the result. Stage 2 remains
in progress; human RBAC/ABAC, decryption endpoints and access logs remain pending.

## Validation

52 focused unit tests passed locally covering conservative shapes, exact field
contracts and prior SRB inspection/import behavior. Actual new source inspection
must still run against the operator's staged batch; no local research database
connection or batch inspection has been claimed.
