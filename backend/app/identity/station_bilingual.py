"""Conservative bilingual label components; candidates only, no evidence edits."""
from collections import Counter, defaultdict
import re
from app.identity.station_vocabulary import MASTER, SINHALA, HEADERS, LABEL, MODES, comparison, script_shape


def components(value):
    """Accept exactly two Latin/Sinhala components separated by clear syntax.

    Returned text is in-memory only. Embedded punctuation and format characters
    stay intact. Nested brackets, several separators and inseparable mixed text
    require review rather than guessed splitting or transliteration.
    """
    value = value.strip()
    if not value:
        return "MISSING", None
    parts, structure = None, None
    if any(c in value for c in "()[]{}"):
        match = re.fullmatch(r"([^()\[\]{}]+)\(([^()\[\]{}]+)\)", value)
        if not match:
            return "BRACKET_STRUCTURE_REVIEW", None
        parts, structure = match.groups(), "PARENTHESIZED"
    else:
        # A hyphen qualifies only when surrounded by whitespace; ordinary name
        # hyphens are not silently treated as language delimiters.
        separators = list(re.finditer(r"[/|]|\s+[-–—]\s+", value))
        if len(separators) > 1:
            return "MULTIPLE_SEPARATORS_REVIEW", None
        if separators:
            separator = separators[0]
            parts = value[:separator.start()], value[separator.end():]
            structure = "SLASH" if separator.group() == "/" else "PIPE" if separator.group() == "|" else "SPACED_DASH"
    if parts is None:
        return "UNSEPARATED_" + script_shape(value), None
    left, right = (part.strip() for part in parts)
    scripts = script_shape(left), script_shape(right)
    if set(scripts) != {"LATIN", "SINHALA"}:
        return "COMPONENT_SCRIPTS_REVIEW", None
    latin, sinhala = (left, right) if scripts[0] == "LATIN" else (right, left)
    return structure + ":" + scripts[0] + "_FIRST", {"LATIN": latin, "SINHALA": sinhala}


def bilingual_review(master, sinhala):
    """Report only fixed labels/counts; never original or extracted values."""
    for filename, rows in ((MASTER, master), (SINHALA, sinhala)):
        if not rows or any(set(row) != set(HEADERS[filename]) or
                           not all(isinstance(v, str) for v in row.values()) for row in rows):
            raise ValueError("Bilingual review field coverage differs.")
    shapes = []
    for field in (LABEL, "Division", "Province "):
        shapes.append(dict(field=field, observations=dict(sorted(Counter(components(row[field])[0] for row in sinhala).items()))))
    reports = []
    for mode in MODES:
        latin_index, sinhala_index = defaultdict(set), defaultdict(set)
        for number, row in enumerate(master):
            for index, field in ((latin_index, "station_name"), (sinhala_index, "station_name_si")):
                key = comparison(row[field], mode)
                if key:
                    index[key].add(number)
        counts, context = Counter(), Counter()
        for row in sinhala:
            _, pair = components(row[LABEL])
            if pair is None:
                counts["NO_REVIEWABLE_COMPONENT_PAIR"] += 1
                continue
            latin = latin_index.get(comparison(pair["LATIN"], mode), set())
            sinhala_matches = sinhala_index.get(comparison(pair["SINHALA"], mode), set())
            for language, candidates in (("LATIN", latin), ("SINHALA", sinhala_matches)):
                counts[language + ":" + ("NO_CANDIDATE" if not candidates else "SINGLE_CANDIDATE" if len(candidates) == 1 else "MULTIPLE_CANDIDATES")] += 1
            joint = latin & sinhala_matches
            state = "SINGLE_JOINT_CANDIDATE" if len(joint) == 1 else "MULTIPLE_JOINT_CANDIDATES" if joint else "DISJOINT_CANDIDATES" if latin and sinhala_matches else "ONE_COMPONENT_HAS_CANDIDATES" if latin or sinhala_matches else "NEITHER_COMPONENT_HAS_CANDIDATES"
            counts["joint:" + state] += 1
            if len(joint) == 1:
                target = master[next(iter(joint))]
                # Context is another source-text observation, never a way to
                # override disjoint or ambiguous station-name candidates.
                for field, master_field in (("Division", "division"), ("Province ", "province")):
                    _, context_pair = components(row[field])
                    if context_pair is None:
                        outcome = "NO_REVIEWABLE_COMPONENT_PAIR"
                    else:
                        left, right = comparison(context_pair["LATIN"], mode), comparison(target[master_field], mode)
                        outcome = "MASTER_CONTEXT_MISSING" if not right else "SAME_REPORTED_LATIN_TEXT" if left == right else "DIFFERENT_REPORTED_LATIN_TEXT"
                    context[field + ":" + outcome] += 1
        reports.append(dict(mode=mode, observations=dict(sorted(counts.items())), unique_joint_context=dict(sorted(context.items()))))
    return dict(rows={MASTER: len(master), SINHALA: len(sinhala)}, component_structures=shapes, candidate_comparisons=reports)
