"""Aggregate station-label observations; no accepted mapping or source edits."""
from collections import Counter, defaultdict
import unicodedata

from app.identity.source_coverage import coordinate_shape

MASTER = "station_master.csv"
SINHALA = "sri_lanka_police_stations_sinhala.csv"
HEADERS = {
    MASTER: ("station_code", "station_name", "station_name_si", "town", "division", "district", "province",
             "province_of_district", "province_matches_district", "district_source", "district_confidence", "latitude", "longitude"),
    SINHALA: ("Province ", "Division", "Police Station (පොලිස් ස්ථානය)", "Latitude", "Longitude"),
}
LABEL = "Police Station (පොලිස් ස්ථානය)"
MODES = ("EXACT_TRIM", "NFC_TRIM", "NFC_WHITESPACE")


def comparison(value, mode):
    """Derived comparison text stays in memory; original evidence is untouched.

    Never remove punctuation, change case, transliterate, or fuzzy-match labels.
    Even a unique normalized match remains a candidate requiring assessment.
    """
    if mode not in MODES:
        raise ValueError("Unknown station comparison mode.")
    value = value.strip()
    if mode != "EXACT_TRIM":
        value = unicodedata.normalize("NFC", value)
    return " ".join(value.split()) if mode == "NFC_WHITESPACE" else value


def script_shape(value):
    letters = {"SINHALA" if "SINHALA" in unicodedata.name(c, "") else
               "LATIN" if "LATIN" in unicodedata.name(c, "") else "OTHER"
               for c in value if unicodedata.category(c).startswith("L")}
    if not value.strip():
        return "MISSING"
    return "NO_LETTERS" if not letters else next(iter(letters)) if len(letters) == 1 else "MIXED_SCRIPTS"


def label_shapes(values):
    counts = Counter()
    for value in values:
        counts["script:" + script_shape(value)] += 1
        counts["outer_whitespace:" + str(value != value.strip()).upper()] += 1
        counts["nfc_changes:" + str(value != unicodedata.normalize("NFC", value)).upper()] += 1
        counts["internal_whitespace_changes:" + str(value.strip() != " ".join(value.split())).upper()] += 1
        # Control/format characters can explain visually similar labels; never strip them automatically.
        counts["control_or_format:" + str(any(unicodedata.category(c) in {"Cc", "Cf"} for c in value)).upper()] += 1
    return dict(sorted(counts.items()))


def validate_recovered(file, raw, number, original, recovered_backup):
    """Reject gaps, changed provenance, headers or unequal backup recovery."""
    if raw["source_row_number"] != number or any(raw[k] != file[k] for k in
            ("batch_id", "archive_path", "source_file_sha256", "import_file_id")):
        raise ValueError("Station staged sequence/provenance differs.")
    if original != recovered_backup or original["columns"] != file["columns"]:
        raise ValueError("Station staged header/backup recovery differs.")
    row = dict(zip(original["columns"], original["values"], strict=True))
    if not all(isinstance(v, str) for v in row.values()):
        raise ValueError("Station original values must remain text.")
    return row


def review(master, sinhala):
    """Return fixed field names and counts only, never labels, codes or row IDs."""
    for filename, rows in ((MASTER, master), (SINHALA, sinhala)):
        if not rows or any(set(row) != set(HEADERS[filename]) for row in rows):
            raise ValueError("Station review field coverage differs.")
    shapes, coordinates, keys, matches = [], [], [], []
    for filename, rows, fields, coords in (
        (MASTER, master, ("station_name", "station_name_si", "division", "province"), ("latitude", "longitude")),
        (SINHALA, sinhala, (LABEL, "Division", "Province "), ("Latitude", "Longitude")),
    ):
        for field in fields:
            shapes.append(dict(filename=filename, field=field, observations=label_shapes([r[field] for r in rows])))
        for field, bounds in zip(coords, ((-90, 90), (-180, 180)), strict=True):
            coordinates.append(dict(filename=filename, field=field,
                observations=dict(sorted(Counter(coordinate_shape(r[field], *bounds) for r in rows).items()))))
        for field in (("station_code", "station_name", "station_name_si") if filename == MASTER else (LABEL,)):
            for mode in MODES:
                values = Counter(comparison(r[field], mode) for r in rows if r[field].strip())
                keys.append(dict(filename=filename, field=field, mode=mode, distinct_nonempty=len(values),
                    missing=sum(not r[field].strip() for r in rows), repeated_rows=sum(n - 1 for n in values.values())))
    for field in ("station_name_si", "station_name"):
        for mode in MODES:
            index = defaultdict(list)
            for row in master:
                key = comparison(row[field], mode)
                if key:
                    index[key].append(row)
            counts, contexts = Counter(), Counter()
            for row in sinhala:
                key = comparison(row[LABEL], mode)
                candidates = index.get(key, []) if key else []
                state = "MISSING" if not key else "NO_CANDIDATE" if not candidates else "SINGLE_CANDIDATE" if len(candidates) == 1 else "MULTIPLE_CANDIDATES"
                counts[state] += 1
                if len(candidates) == 1:
                    # Context agrees only as reported text, not as an accepted historical hierarchy.
                    for source_field, target_field in (("Division", "division"), ("Province ", "province")):
                        left, right = comparison(row[source_field], mode), comparison(candidates[0][target_field], mode)
                        context = "MISSING_CONTEXT" if not left or not right else "SAME_REPORTED_TEXT" if left == right else "DIFFERENT_REPORTED_TEXT"
                        contexts[source_field + ":" + context] += 1
            matches.append(dict(target_field=field, mode=mode, observations=dict(sorted(counts.items())),
                unique_candidate_context=dict(sorted(contexts.items()))))
    return dict(rows={MASTER: len(master), SINHALA: len(sinhala)}, label_shapes=shapes,
        key_shapes=keys, comparison_candidates=matches, coordinate_shapes=coordinates)
