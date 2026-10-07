"""Read-only balanced-parenthesis observations; no accepted station mapping."""
from collections import Counter, defaultdict
from app.identity.station_bilingual import components
from app.identity.station_vocabulary import MASTER, SINHALA, HEADERS, LABEL, MODES, comparison, script_shape


def bracket_structure(value):
    """Inspect a terminal top-level parenthesis group without deleting qualifiers.

    A stack-free scan handles nesting without recursion. The entire prefix and
    terminal group's contents are retained, including their internal brackets.
    This is a structural hypothesis, not a claim about which language is where.
    """
    value = value.strip()
    depth = maximum = groups = 0
    start = None
    final = None
    for position, char in enumerate(value):
        if char == "(":
            if depth == 0:
                start = position
                groups += 1
            depth += 1
            maximum = max(maximum, depth)
        elif char == ")":
            depth -= 1
            if depth < 0:
                return dict(state="UNBALANCED_CLOSE", maximum_depth=maximum, top_level_groups=groups), None
            if depth == 0:
                final = (start, position)
    metadata = dict(maximum_depth=maximum, top_level_groups=groups)
    if depth:
        return dict(metadata, state="UNBALANCED_OPEN"), None
    if any(char in value for char in "[]{}"):
        return dict(metadata, state="OTHER_BRACKETS_REVIEW"), None
    if final is None:
        return dict(metadata, state="NO_PARENTHESIS_GROUP"), None
    if final[1] != len(value) - 1:
        return dict(metadata, state="TEXT_AFTER_FINAL_GROUP"), None
    prefix, terminal = value[:final[0]].strip(), value[final[0]+1:final[1]].strip()
    if not prefix or not terminal:
        return dict(metadata, state="EMPTY_COMPONENT"), None
    # Mixed-script qualifiers are allowed as preserved comparison text. No
    # character, annotation or inner group is dropped to manufacture a match.
    return dict(metadata, state="BALANCED_TERMINAL_GROUP",
        prefix_script=script_shape(prefix), terminal_script=script_shape(terminal)), (prefix, terminal)


def bracket_review(master, sinhala):
    for filename, rows in ((MASTER, master), (SINHALA, sinhala)):
        if not rows or any(set(row) != set(HEADERS[filename]) or not all(isinstance(v, str) for v in row.values()) for row in rows):
            raise ValueError("Bracket review field coverage differs.")
    selected = [row for row in sinhala if components(row[LABEL])[0] == "BRACKET_STRUCTURE_REVIEW"]
    structures = Counter()
    parsed = []
    for row in selected:
        metadata, pair = bracket_structure(row[LABEL])
        for field, value in metadata.items():
            structures[field + ":" + str(value)] += 1
        parsed.append((row, pair))
    reports = []
    for mode in MODES:
        indices = {field: defaultdict(set) for field in ("station_name", "station_name_si")}
        for number, row in enumerate(master):
            for field, index in indices.items():
                key = comparison(row[field], mode)
                if key:
                    index[key].add(number)
        for orientation, fields in (("PREFIX_NAME_TERMINAL_SI", ("station_name", "station_name_si")),
                                    ("PREFIX_SI_TERMINAL_NAME", ("station_name_si", "station_name"))):
            counts, contexts = Counter(), Counter()
            for row, pair in parsed:
                if pair is None:
                    counts["NO_STRUCTURAL_PAIR"] += 1
                    continue
                candidates = [indices[field].get(comparison(value, mode), set()) for field, value in zip(fields, pair, strict=True)]
                for component, matches in zip(("PREFIX", "TERMINAL"), candidates, strict=True):
                    counts[component + ":" + ("NO_CANDIDATE" if not matches else "SINGLE_CANDIDATE" if len(matches) == 1 else "MULTIPLE_CANDIDATES")] += 1
                joint = candidates[0] & candidates[1]
                state = "SINGLE_JOINT_CANDIDATE" if len(joint) == 1 else "MULTIPLE_JOINT_CANDIDATES" if joint else "DISJOINT_CANDIDATES" if all(candidates) else "ONE_COMPONENT_HAS_CANDIDATES" if any(candidates) else "NEITHER_COMPONENT_HAS_CANDIDATES"
                counts["joint:" + state] += 1
                if len(joint) == 1:
                    target = master[next(iter(joint))]
                    for field, target_field in (("Division", "division"), ("Province ", "province")):
                        _, context = components(row[field])
                        if context is None:
                            outcome = "NO_REVIEWABLE_CONTEXT_PAIR"
                        else:
                            left, right = comparison(context["LATIN"], mode), comparison(target[target_field], mode)
                            outcome = "MASTER_CONTEXT_MISSING" if not right else "SAME_REPORTED_LATIN_TEXT" if left == right else "DIFFERENT_REPORTED_LATIN_TEXT"
                        contexts[field + ":" + outcome] += 1
            reports.append(dict(mode=mode, orientation=orientation, observations=dict(sorted(counts.items())),
                unique_joint_context=dict(sorted(contexts.items()))))
    return dict(rows={MASTER: len(master), SINHALA: len(sinhala)}, bracket_review_rows=len(selected),
        other_rows=len(sinhala)-len(selected), structure_observations=dict(sorted(structures.items())), candidate_comparisons=reports)
