"""Read-only row coverage and protected reported-reference observations.

Receipt coverage is not encrypted destination reconciliation, accepted linkage,
source independence, historical applicability or human disclosure authorization.
"""
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
import json
from app.identity.normalization import normalize_identifier, IdentifierInputError

POLICY = "SOURCE_REFERENCE_COVERAGE_V1"
REFERENCES = ("station_master.csv", "sri_lanka_police_stations_sinhala.csv")
ROWS = {
    "officer_personal_information.csv": 6596, "officer_service_information.csv": 6596,
    "promotion_history.csv": 13974, "transfer_history.csv": 33316,
    "officer_police_numbers.csv": 15123, "officer_restrictions.csv": 10971, "restriction_overrides.csv": 150,
    "officer_duty_periods.csv": 3138, "officer_firearms_expertise.csv": 30348,
    "good_conduct_register.csv": 2779, "bad_conduct_register.csv": 370,
    "officer_education.csv": 6596, "officer_family_details.csv": 6596,
    "operations.csv": 19554, "court_details.csv": 9538, "public_complaints.csv": 998, "_demotions_enacted.csv": 8,
}
ASSERTIONS = {
    "officer_personal_information.csv": "PF_PERSONAL_PROFILE", "officer_service_information.csv": "HR_SERVICE_EVIDENCE",
    "promotion_history.csv": "PF_PROMOTION_EVIDENCE", "transfer_history.csv": "PF_TRANSFER_EVIDENCE",
    "officer_police_numbers.csv": "SRB_POLICE_NUMBER_EVIDENCE", "officer_restrictions.csv": "SRB_RESTRICTION_EVIDENCE",
    "restriction_overrides.csv": "SRB_OVERRIDE_EVIDENCE", "officer_duty_periods.csv": "SRB_DUTY_EVIDENCE",
    "officer_firearms_expertise.csv": "SRB_FIREARMS_EVIDENCE", "good_conduct_register.csv": "SRB_GOOD_CONDUCT_EVIDENCE",
    "bad_conduct_register.csv": "SRB_BAD_CONDUCT_EVIDENCE", "officer_education.csv": "HR_EDUCATION_EVIDENCE",
    "officer_family_details.csv": "HR_FAMILY_EVIDENCE", "operations.csv": "PF_OPERATION_EVIDENCE",
    "court_details.csv": "PF_COURT_EVIDENCE", "public_complaints.csv": "PF_COMPLAINT_EVIDENCE", "_demotions_enacted.csv": "PF_DEMOTION_EVIDENCE",
}
SOURCES = {name: "POLICE_HR_IS" if name in {"officer_service_information.csv", "officer_education.csv", "officer_family_details.csv", *REFERENCES}
    else "SRB" if name in {"officer_police_numbers.csv", "officer_restrictions.csv", "restriction_overrides.csv", "officer_duty_periods.csv", "officer_firearms_expertise.csv", "good_conduct_register.csv", "bad_conduct_register.csv"}
    else "PF_REGISTRY" for name in (*ROWS, *REFERENCES)}
TARGETS = {
    "operations.csv": ("operation_no",), "public_complaints.csv": ("complaint_id",), "court_details.csv": ("court_no",),
    "transfer_history.csv": ("transfer_id",), "officer_restrictions.csv": ("restriction_id",),
    "bad_conduct_register.csv": ("punishment_id",), "_demotions_enacted.csv": ("punishment_id",),
    "station_master.csv": ("station_code", "station_name_si"),
}
# Candidate key comparisons only. In particular, linked_case_no's target is provisional.
LINKS = {
    "operations.csv": {"complaint_number": ("public_complaints.csv", "complaint_id")},
    "court_details.csv": {"operation_no": ("operations.csv", "operation_no"), "complaint_no": ("public_complaints.csv", "complaint_id")},
    "public_complaints.csv": {"linked_case_no": ("operations.csv", "operation_no"), "linked_court_case_no": ("court_details.csv", "court_no"),
        "linked_transfer_id": ("transfer_history.csv", "transfer_id"), "linked_punishment_id": ("bad_conduct_register.csv", "punishment_id")},
    "transfer_history.csv": {"originating_complaint_id": ("public_complaints.csv", "complaint_id")},
    "restriction_overrides.csv": {"restriction_id": ("officer_restrictions.csv", "restriction_id"), "transfer_id": ("transfer_history.csv", "transfer_id")},
    "good_conduct_register.csv": {"operation_no": ("operations.csv", "operation_no"), "court_no": ("court_details.csv", "court_no")},
    "bad_conduct_register.csv": {"originating_complaint_id": ("public_complaints.csv", "complaint_id"), "hardship_transfer_id": ("transfer_history.csv", "transfer_id")},
    "_demotions_enacted.csv": {"punishment_id": ("bad_conduct_register.csv", "punishment_id")},
    "sri_lanka_police_stations_sinhala.csv": {"Police Station (පොලිස් ස්ථානය)": ("station_master.csv", "station_name_si")},
}
EXTERNAL = {"public_complaints.csv": ("npc_reference_no", "linked_hrc_reference")}
STATION_COLUMNS = {
    "officer_service_information.csv": ("current_station_code", "first_posted_police_station_code"),
    "transfer_history.csv": ("from_station_code", "to_station_code"),
    "officer_restrictions.csv": ("restricted_station_code",),
    "officer_duty_periods.csv": ("period_station_code", "current_station_code"),
    "officer_firearms_expertise.csv": ("gun_performance_station_code", "current_station_code"),
    "operations.csv": ("operation_handle_station_code",), "public_complaints.csv": ("station_code",),
}


def receipt_coverage(raw_ids, receipts):
    """Compare exact row IDs; equal counts cannot hide one missing and one extra row."""
    expected = set(raw_ids)
    seen = Counter(r["raw_record_id"] for r in receipts)
    complete = {r["raw_record_id"] for r in receipts if r["complete"]}
    return dict(staged_rows=len(expected), receipt_rows=sum(seen.values()),
        complete_rows=len(expected & complete), missing_rows=len(expected - set(seen)),
        incomplete_rows=len(expected & set(seen) - complete),
        unexpected_rows=len(set(seen) - expected), duplicate_rows=sum(n - 1 for n in seen.values() if n > 1))


def coordinate_shape(value, lower, upper):
    """Observe numeric ranges only; coordinate reference system is unconfirmed."""
    if not value.strip(): return "MISSING"
    try: number = Decimal(value.strip())
    except InvalidOperation: return "NONNUMERIC"
    if not number.is_finite(): return "NONFINITE"
    return "WITHIN_DECIMAL_DEGREE_RANGE" if lower <= number <= upper else "OUTSIDE_DECIMAL_DEGREE_RANGE"


class ReferenceInventory:
    """Keep only keyed lookup tokens, counters and subject tokens in memory."""
    def __init__(self, crypto):
        self.crypto = crypto
        self.keys = defaultdict(lambda: defaultdict(list))
        self.pending, self.external, self.coordinates = [], Counter(), Counter()
        self.key_observations = Counter()

    def token(self, source, column, value):
        # Exact trim only: never cast IDs to integers or remove leading zeroes.
        return self.crypto.lookup_hmac(json.dumps([POLICY, source, column, value.strip()], ensure_ascii=False, separators=(",", ":")), identifier_type=POLICY)[0]

    def subject(self, row):
        value = row.get("officer_nic_no", "")
        try: normalized = normalize_identifier(value, identifier_type="NIC")
        except IdentifierInputError: return None
        return self.token("SUBJECT_CLAIM", "NIC", normalized.value)

    def add(self, filename, row):
        subject = self.subject(row)
        for column in TARGETS.get(filename, ()):
            value = row[column]
            if not value.strip(): self.key_observations[(filename, column, "MISSING_REPORTED_KEY")] += 1
            else: self.keys[(filename, column)][self.token(filename, column, value)].append(subject)
        links = dict(LINKS.get(filename, {}))
        links.update({c: ("station_master.csv", "station_code") for c in STATION_COLUMNS.get(filename, ())})
        for column, target in links.items():
            value = row[column]
            digest = self.token(*target, value) if value.strip() else None
            self.pending.append((filename, column, target, digest, subject))
        for column in EXTERNAL.get(filename, ()):
            self.external[(filename, column, "NO_RECEIVED_TARGET_CATALOG" if row[column].strip() else "MISSING")] += 1
        if filename == "sri_lanka_police_stations_sinhala.csv":
            for column, limits in (("Latitude", (-90, 90)), ("Longitude", (-180, 180))):
                self.coordinates[(filename, column, coordinate_shape(row[column], *limits))] += 1

    def report(self):
        counts = Counter()
        for filename, column, target, digest, subject in self.pending:
            candidates = self.keys[target].get(digest, []) if digest is not None else []
            state = "MISSING" if digest is None else "NO_REPORTED_KEY_MATCH" if not candidates else "SINGLE_REPORTED_KEY_MATCH" if len(candidates) == 1 else "MULTIPLE_REPORTED_KEY_ROWS"
            counts[(filename, column, state)] += 1
            # Compare reported subject claims only where the target has one subject.
            if len(candidates) == 1 and subject is not None and candidates[0] is not None:
                counts[(filename, column, "SAME_REPORTED_SUBJECT" if subject == candidates[0] else "DIFFERENT_REPORTED_SUBJECT")] += 1
        keys = Counter(self.key_observations)
        for (filename, column), values in self.keys.items():
            keys[(filename, column, "DISTINCT_NONEMPTY_KEYS")] = len(values)
            keys[(filename, column, "REPEATED_KEY_ROWS")] = sum(len(v) - 1 for v in values.values())
        def serialize(counter):
            return [{"filename": f, "field": c, "observation": state, "count": n} for (f, c, state), n in sorted(counter.items())]
        return dict(reference_observations=serialize(counts), key_observations=serialize(keys),
            external_reference_observations=serialize(self.external), coordinate_observations=serialize(self.coordinates))
