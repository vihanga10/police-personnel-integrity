"""Source-scoped station reference plans; original text and uncertainty preserved."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
from app.identity.station_vocabulary import HEADERS, MASTER, SINHALA, LABEL, MODES, comparison
from app.identity.station_bilingual import components
from app.identity.source_coverage import coordinate_shape

POLICY = "STATION_REFERENCE_PLAN_V1"
ROUTES = {'sri_lanka_police_stations_sinhala.csv': {'Province ': ('mongodb.station_sinhala_reference_records', 'reported_province_si'), 'Division': ('mongodb.station_sinhala_reference_records', 'reported_division_si'), 'Police Station (පොලිස් ස්ථානය)': ('mongodb.station_sinhala_reference_records', 'reported_station_name_si'), 'Latitude': ('mongodb.station_sinhala_reference_records', 'reported_latitude'), 'Longitude': ('mongodb.station_sinhala_reference_records', 'reported_longitude')}, 'station_master.csv': {'station_code': ('mongodb.station_reference_records', 'station_code'), 'station_name': ('mongodb.station_reference_records', 'reported_station_name'), 'station_name_si': ('mongodb.station_reference_records', 'reported_station_name_si'), 'town': ('mongodb.station_reference_records', 'reported_town'), 'division': ('mongodb.station_reference_records', 'reported_division'), 'district': ('mongodb.station_reference_records', 'reported_district'), 'province': ('mongodb.station_reference_records', 'reported_province'), 'province_of_district': ('mongodb.station_reference_records', 'reported_province_of_district'), 'province_matches_district': ('mongodb.station_reference_records', 'reported_province_matches_district'), 'district_source': ('mongodb.station_reference_records', 'reported_district_source'), 'district_confidence': ('mongodb.station_reference_records', 'reported_district_confidence'), 'latitude': ('mongodb.station_reference_records', 'reported_latitude'), 'longitude': ('mongodb.station_reference_records', 'reported_longitude')}}
UNCERTAINTIES = ("CLASSIFICATION_UNASSESSED", "STATION_IDENTITY_AND_CODE_STABILITY_UNASSESSED",
    "HISTORICAL_HIERARCHY_AND_VALID_PERIODS_UNKNOWN", "SOURCE_INDEPENDENCE_UNVERIFIED",
    "COORDINATE_REFERENCE_SYSTEM_AND_ACCURACY_UNASSESSED", "SOURCE_FLAGS_AND_CONFIDENCE_UNASSESSED")


@dataclass(frozen=True)
class ReferencePlan:
    payload: dict = field(repr=False)


def require(condition):
    if not condition:
        raise ValueError("Reference plan contract differs.")


def raw_id(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None)


def validate_routing(document):
    for filename in HEADERS:
        entries = [f for f in document["files"] if f["filename"] == filename]
        require(len(entries) == 1)
        fields = entries[0]["fields"]
        require(len(fields) == len(HEADERS[filename]) and {f["source_column"] for f in fields} == set(HEADERS[filename]))
        require(all(f.get("preserve_in_protected_staging") is True and
            (f["destination"], f["target_field"]) == ROUTES[filename][f["source_column"]] for f in fields))


def field_plans(filename, row):
    require(filename in HEADERS and set(row) == set(HEADERS[filename]) and all(isinstance(v, str) for v in row.values()))
    fields = []
    mandatory = {"station_code", "station_name", "station_name_si"} if filename == MASTER else {LABEL}
    for name in HEADERS[filename]:
        source = row[name]
        issues = []
        status = "PRESERVED" if source.strip() else "MISSING"
        if name in mandatory and not source.strip():
            issues.append("REQUIRED_SOURCE_REFERENCE_MISSING")
        if "\x00" in source:
            issues.append("NUL_TEXT_REQUIRES_REVIEW")
        if name.lower() in {"latitude", "longitude"}:
            bounds = (-90, 90) if name.lower() == "latitude" else (-180, 180)
            shape = coordinate_shape(source, *bounds)
            if source.strip() and shape != "WITHIN_DECIMAL_DEGREE_RANGE":
                issues.append("COORDINATE_FORMAT_OR_RANGE_REVIEW")
        if issues:
            status = "REVIEW_REQUIRED"
        destination, target = ROUTES[filename][name]
        # No numeric code conversion, automatic translation, confidence threshold
        # or flag-to-verification conversion. All cell text is preserved exactly.
        fields.append(dict(source_column=name, source_value=source, value=source, destination=destination,
                           target_field=target, status=status, issues=issues))
    return fields


class ReferenceCandidates:
    """One recovered master snapshot, with opaque raw IDs as candidate provenance."""
    def __init__(self, rows):
        require(bool(rows))
        self.rows, self.indices = {}, {m: {f: defaultdict(set) for f in ("station_name", "station_name_si")} for m in MODES}
        self.codes, self.names = Counter(), Counter()
        for rid, row in rows:
            raw_id(rid); require(rid not in self.rows)
            field_plans(MASTER, row)
            self.rows[rid] = dict(row)
            if row["station_code"].strip(): self.codes[row["station_code"].strip()] += 1
            if row["station_name_si"].strip(): self.names[row["station_name_si"].strip()] += 1
            for mode in MODES:
                for name, index in self.indices[mode].items():
                    key = comparison(row[name], mode)
                    if key: index[key].add(rid)

    def master_observations(self, rid, row):
        require(rid in self.rows and self.rows[rid] == row)
        return dict(repeated_source_code=self.codes[row["station_code"].strip()] > 1 if row["station_code"].strip() else False,
                    repeated_sinhala_label=self.names[row["station_name_si"].strip()] > 1 if row["station_name_si"].strip() else False)

    def sinhala_candidates(self, row):
        shape, pair = components(row[LABEL])
        results = []
        for mode in MODES:
            latin = sorted(self.indices[mode]["station_name"].get(comparison(pair["LATIN"], mode), set())) if pair else []
            sinhala = sorted(self.indices[mode]["station_name_si"].get(comparison(pair["SINHALA"], mode), set())) if pair else []
            joint = sorted(set(latin) & set(sinhala))
            context = {}
            if len(joint) == 1:
                target = self.rows[joint[0]]
                for name, column in (("Division", "division"), ("Province ", "province")):
                    _, context_pair = components(row[name])
                    right = comparison(target[column], mode)
                    context[name] = "NO_COMPONENT_PAIR" if context_pair is None else "MASTER_MISSING" if not right else "SAME_REPORTED_TEXT" if comparison(context_pair["LATIN"], mode) == right else "DIFFERENT_REPORTED_TEXT"
            results.append(dict(mode=mode, structure=shape, latin_raw_ids=latin, sinhala_raw_ids=sinhala,
                joint_raw_ids=joint, state=candidate_state(shape, latin, sinhala, joint), reported_context=context))
        return results


def candidate_state(shape, latin, sinhala, joint):
    if components_supported(shape) is False: return "STRUCTURE_REVIEW_REQUIRED"
    return "SINGLE_JOINT_CANDIDATE" if len(joint) == 1 else "MULTIPLE_JOINT_CANDIDATES" if joint else "DISJOINT_CANDIDATES" if latin and sinhala else "ONE_SIDED_CANDIDATES" if latin or sinhala else "NO_CANDIDATE"


def components_supported(shape):
    return shape.endswith((":LATIN_FIRST", ":SINHALA_FIRST"))


def review_issues(filename, fields, observations, candidates):
    issues = [f["source_column"] + ":" + issue for f in fields for issue in f["issues"]]
    if filename == MASTER:
        if observations["repeated_source_code"]: issues.append("REPEATED_SOURCE_CODE")
        if observations["repeated_sinhala_label"]: issues.append("REPEATED_SINHALA_LABEL")
    else:
        if any(c["state"] != "SINGLE_JOINT_CANDIDATE" for c in candidates): issues.append("STATION_CANDIDATE_REQUIRES_REVIEW")
        if any(v in {"DIFFERENT_REPORTED_TEXT", "MASTER_MISSING", "NO_COMPONENT_PAIR"} for c in candidates for v in c["reported_context"].values()):
            issues.append("REPORTED_HIERARCHY_CONTEXT_REQUIRES_REVIEW")
    return issues


def plan_reference(filename, row, *, raw_record_id, candidates):
    raw_id(raw_record_id)
    fields = field_plans(filename, row)
    observations = candidates.master_observations(raw_record_id, row) if filename == MASTER else {}
    links = candidates.sinhala_candidates(row) if filename == SINHALA else []
    issues = review_issues(filename, fields, observations, links)
    plan = ReferencePlan(dict(schema_version="1.0", policy_version=POLICY, filename=filename, raw_record_id=raw_record_id,
        record_classification="UNASSESSED", accepted_station_uid=None, valid_from=None, valid_to=None,
        linkage_accepted=False, authority_result=None, fields=fields, source_observations=observations,
        candidate_evidence=links, review_issues=issues, needs_review=bool(issues), uncertainties=list(UNCERTAINTIES)))
    validate_payload(plan.payload)
    return plan


def validate_payload(payload):
    require(set(payload) == {"schema_version", "policy_version", "filename", "raw_record_id", "record_classification",
        "accepted_station_uid", "valid_from", "valid_to", "linkage_accepted", "authority_result", "fields",
        "source_observations", "candidate_evidence", "review_issues", "needs_review", "uncertainties"})
    require(payload["schema_version"] == "1.0" and payload["policy_version"] == POLICY and payload["record_classification"] == "UNASSESSED")
    require(payload["linkage_accepted"] is False and all(payload[k] is None for k in ("accepted_station_uid", "valid_from", "valid_to", "authority_result")))
    filename = payload["filename"]; raw_id(payload["raw_record_id"])
    require(filename in HEADERS)
    fields = payload["fields"]
    require(tuple(f["source_column"] for f in fields) == HEADERS[filename])
    row = {f["source_column"]: f["source_value"] for f in fields}
    require(fields == field_plans(filename, row) and payload["uncertainties"] == list(UNCERTAINTIES))
    observations, candidates = payload["source_observations"], payload["candidate_evidence"]
    if filename == MASTER:
        require(set(observations) == {"repeated_source_code", "repeated_sinhala_label"} and all(type(v) is bool for v in observations.values()) and not candidates)
    else:
        require(not observations and len(candidates) == len(MODES))
        for mode, c in zip(MODES, candidates, strict=True):
            require(set(c) == {"mode", "structure", "latin_raw_ids", "sinhala_raw_ids", "joint_raw_ids", "state", "reported_context"})
            shape, pair = components(row[LABEL]); require(c["mode"] == mode and c["structure"] == shape)
            for name in ("latin_raw_ids", "sinhala_raw_ids", "joint_raw_ids"):
                for rid in c[name]: raw_id(rid)
                require(c[name] == sorted(set(c[name])))
            require(c["joint_raw_ids"] == sorted(set(c["latin_raw_ids"]) & set(c["sinhala_raw_ids"])))
            require(pair is not None or not (c["latin_raw_ids"] or c["sinhala_raw_ids"]))
            require(c["state"] == candidate_state(shape, c["latin_raw_ids"], c["sinhala_raw_ids"], c["joint_raw_ids"]))
            require(set(c["reported_context"]) == ({"Division", "Province "} if len(c["joint_raw_ids"]) == 1 else set()))
            require(all(v in {"NO_COMPONENT_PAIR", "MASTER_MISSING", "SAME_REPORTED_TEXT", "DIFFERENT_REPORTED_TEXT"} for v in c["reported_context"].values()))
    expected = review_issues(filename, fields, observations, candidates)
    require(payload["review_issues"] == expected and type(payload["needs_review"]) is bool and payload["needs_review"] == bool(expected))
