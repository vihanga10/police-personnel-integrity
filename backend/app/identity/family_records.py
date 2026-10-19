"""Route encrypted family claims without inventing people, dates or authority."""
from dataclasses import dataclass, field
import json
from uuid import UUID
from app.identity.inspect_remaining_sources import HEADERS
from app.identity.remaining_plan import REMAINING_PLAN_POLICY, ROUTES

POLICY = "HR_FAMILY_WRITER_V1"
FILENAME = "officer_family_details.csv"


def check_payload(payload):
    """Only the reviewed family envelope may reach the writer."""
    if (payload.get("filename"), payload.get("policy_version"), payload.get("record_classification")) != (FILENAME, REMAINING_PLAN_POLICY, "UNASSESSED"):
        raise ValueError("Family plan policy differs.")
    UUID(payload["officer_uid"])
    fields = payload.get("fields", [])
    if tuple(f["source_column"] for f in fields) != HEADERS[FILENAME]:
        raise ValueError("Family field coverage differs.")
    if any((f["destination"], f["target_field"]) != ROUTES[FILENAME][f["source_column"]] or not isinstance(f["source_value"], str) for f in fields):
        raise ValueError("Family field routing differs.")
    subject = fields[0]
    if subject["value"] != dict(type="uuid", value=payload["officer_uid"]):
        raise ValueError("Family subject differs.")
    if payload.get("effects_applied") is not False or payload.get("authority_assessment") != "NOT_RUN" or any(payload.get(k) is not None for k in ("authority_result", "valid_from", "valid_to", "reconstructed_state")):
        raise ValueError("Unapproved family determination.")
    return payload


@dataclass(frozen=True)
class FamilyRecord:
    table: str
    kind: str
    fields: tuple = field(repr=False)
    relation_kind: str | None = None

    def payload(self):
        return dict(writer_policy=POLICY, kind=self.kind, fields=list(self.fields),
            valid_from=None, valid_to=None, effects_applied=False,
            person_identity="UNASSESSED", positional_pairing_accepted=False,
            authority_result=None, reference_linkage="UNASSESSED")


def logical_records(payload):
    """A CHILD row is an aggregate list claim, never an identified child.

    Equal list lengths do not authorize pairing names with ages. Death fields
    remain assertion-only because the deceased person's identity is unspecified.
    """
    check_payload(payload)
    cells = {f["source_column"]: f for f in payload["fields"]}
    def present(names): return any(cells[n]["source_value"].strip() for n in names)
    def record(table, kind, names, relation=None):
        return FamilyRecord(table, kind, tuple(cells[n] for n in names), relation)
    spouse = ("spouse_name", "spouse_sex", "spouse_date_of_birth", "spouse_place_of_birth")
    marriage = ("date_of_marriage", "reference_Marriage_certificate")
    divorce = ("date_of_divorce", "reference_divorce_certificate")
    children = ("children_no", "childern_fullname", "children_age")
    kin = ("next_of_near_relative_name", "next_of_relative_relationship", "next_of_relative_address")
    actor = ("recorded_by_signature", "recorded_by_officer_name", "recorded_by_officer_nic", "recorded_by_officer_rank", "datails_entry_date", "Certified_signed_date")
    records = []
    # A reported civil event needs a source-scoped spouse claim as its FK anchor,
    # even if no spouse name is supplied. This does not resolve spouse identity.
    if present(spouse + marriage + divorce):
        records.append(record("officer_family_relation", "SPOUSE", spouse + marriage + divorce))
    if present(marriage): records.append(record("officer_family_civil_event_version", "MARRIAGE", marriage, "SPOUSE"))
    if present(divorce): records.append(record("officer_family_civil_event_version", "DIVORCE", divorce, "SPOUSE"))
    # Preserve zero/missing/count-only claims in the full assertion. Create an
    # aggregate relationship only where names or ages have actually been reported.
    if present(children[1:]): records.append(record("officer_family_relation", "CHILD", children))
    if present(kin): records.append(record("officer_next_of_kin_version", "NEXT_OF_KIN", kin))
    if present(actor): records.append(record("source_attestation", "RECORDED_BY", actor))
    return tuple(records)


def context(purpose, *, raw_id, officer, assertion, record_id, table, chain=None, relation=None):
    # Authenticate destination IDs, chains and relationship ownership together.
    return json.dumps([POLICY, purpose, str(raw_id), str(officer), str(assertion),
        str(record_id), table, str(chain) if chain else None, str(relation) if relation else None], separators=(",", ":"))
