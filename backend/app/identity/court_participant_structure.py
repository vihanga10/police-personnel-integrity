"""Aggregate court participant grammar observations; no identity acceptance."""
from collections import Counter
import re

POLICY = "COURT_PARTICIPANT_STRUCTURE_REVIEW_V1"
# Syntax observation only. These tokens are not extracted as accepted identities.
NIC = re.compile(r"(?<![A-Za-z0-9])(?:[0-9]{9}[VvXx]|[0-9]{12})(?![A-Za-z0-9])")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z_ ]{0,40}\s*[:=]")
LABELS = {"nic", "nic_no", "officer_nic_no", "rank", "role", "name", "officer_name", "police_no"}


def structure(value):
    """Return only bounded aggregate categories, never cells, NICs or names."""
    if not isinstance(value, str):
        raise ValueError("Participant cells must remain text.")
    if len(value) > 1048576:
        return dict(state="OVERSIZED_REVIEW", signatures=[], observations={})
    if not value.strip():
        return dict(state="MISSING", signatures=[], observations={})
    observations = Counter()
    # Track quoted and bracketed regions: internal separators are not flat lists.
    pairs = {')':'(', ']':'[', '}':'{'}
    stack, quote, escape, start = [], None, False, 0
    segments, separators = [], Counter()
    for index, char in enumerate(value):
        if quote:
            if escape: escape=False
            elif char == '\\': escape=True
            elif char == quote: quote=None
            continue
        if char in ('"', "'"):
            quote=char
        elif char in '([{':
            stack.append(char)
        elif char in ')]}':
            if not stack or stack.pop() != pairs[char]:
                return dict(state="UNBALANCED_REVIEW", signatures=[], observations={})
        elif char in ';|,\n' and not stack:
            separators[{';':'SEMICOLON','|':'PIPE',',':'COMMA','\n':'NEWLINE'}[char]] += 1
            segments.append(value[start:index]);start=index+1
    if stack or quote:
        return dict(state="UNBALANCED_REVIEW", signatures=[], observations={})
    segments.append(value[start:])
    observations.update({'TOP_SEPARATOR:'+k:n for k,n in separators.items()})
    observations['SEGMENTS'] = len(segments)
    signatures = []
    for segment in segments:
        if not segment.strip():
            observations['EMPTY_SEGMENT'] += 1
        tokens = list(NIC.finditer(segment))
        observations['SEGMENT_NIC_COUNT:'+str(min(len(tokens),3))] += 1
        if tokens:
            observations['NIC_POSITION:' + ('FIRST' if not segment[:tokens[0].start()].strip() else 'LATER')] += 1
        for match in TOKEN.finditer(segment):
            label=match.group().rstrip(' :=').strip().lower().replace(' ','_')
            observations['LABEL:'+(label.upper() if label in LABELS else 'OTHER_LABEL')] += 1
        # Emit a tiny approved grammar vocabulary. All content becomes categories.
        masked=NIC.sub('§',segment)
        parts=[];cursor=0
        for match in re.finditer(r'§|[()\[\]{}:=/]',masked):
            if masked[cursor:match.start()].strip():parts.append('TEXT')
            parts.append('NIC' if match.group()=='§' else match.group());cursor=match.end()
        if masked[cursor:].strip():parts.append('TEXT')
        signatures.append(' '.join(parts) if len(parts)<=20 else 'COMPLEX_REVIEW')
    state='MIXED_TOP_SEPARATORS_REVIEW' if len(separators)>1 else 'BALANCED_STRUCTURE_OBSERVED'
    return dict(state=state, signatures=signatures, observations=dict(observations))


class CourtStructureReport:
    def __init__(self):
        self.rows=0;self.states=Counter();self.signatures=Counter();self.observations=Counter()

    def add(self, text):
        result=structure(text);self.rows+=1;self.states[result['state']]+=1
        self.signatures.update(result['signatures']);self.observations.update(result['observations'])

    def report(self):
        return dict(policy=POLICY, rows=self.rows, structure_states=dict(sorted(self.states.items())),
            grammar_signatures=dict(sorted(self.signatures.items())), observations=dict(sorted(self.observations.items())))
