"""Authenticate and replay a completed algorithm run, never issue audit readiness."""
from collections import Counter
from dataclasses import asdict
from datetime import date
import hashlib
import json
import re

from app.identity.audit_gate import binding as validate_context
from app.identity.bind_evidence_destinations import private_path
from app.identity.evidence_bundle_v2 import open_artifact
from app.identity.historical_officer_selection import Selection
from app.identity.historical_reconstruction import POLICY as HISTORY, reconstruct, require
from app.identity.historical_source_claims import source_claims
from app.identity.public_anchor_authorization import PUBLIC_SHA
from app.identity.reconstruct_history import subject_index
from app.identity.reported_authority_actions import POLICY as ACTIONS, ROUTES, review_actions
from app.identity.run_research_algorithms import POLICY as RUN, json_value
from app.identity.temporal_authority import POLICY as AUTHORITY
from app.identity.temporal_contradictions import POLICY as COMPARISONS, compare_claims

POLICY = 'SAVED_RESEARCH_ALGORITHM_REPLAY_V1'
BASE_KEYS = ('policy', 'policies', 'context', 'on', 'public_payload_sha256', 'selection_mode')
POLICIES = dict(history=HISTORY, contradictions=COMPARISONS, authority=AUTHORITY, reported_actions=ACTIONS)
REPORT_KEYS = set(BASE_KEYS) | {
    'status', 'code_revision', 'officers', 'source_claims', 'history_status_counts',
    'comparison_counts', 'authority_action_counts', 'reason_counts', 'authority_action_records',
    'officer_artifacts', 'action_artifacts', 'action_inventory_rows', 'authority_route_files',
    'classification', 'accepted_state_claim', 'accepted_authority_claim', 'accepted_contradiction_claim',
    'governing_instruments_assessed', 'findings_database_written', 'findings_anchored',
}


def safe_failure(error):
    # Only these fixed, value-free messages may cross the private boundary.
    messages = {
        'Audit permit expired or time differs.', 'Audit permit scope differs.',
        'Commit reviewed source first.', 'Saved snapshot version differs.',
        'Missing or unexpected saved artifact.', 'Saved artifact fingerprint differs.',
        'Plaintext completion differs.', 'Supported saved algorithm run required.',
        'Stopped saved algorithm run refused.', 'Saved officer result differs from source replay.',
        'Saved action differs from source replay.', 'Saved aggregate differs from source replay.',
        'Complete saved replay verification required.',
        'Saved replay receipt differs from this completed run.',
        'Saved replay plaintext receipt differs.', 'Private artifact path missing.',
        'Private artifact permissions differ.', 'Private path traverses symlink.',
        'Original anchored snapshot differs.', 'Captured evidence differs from anchored commitments.',
    }
    return str(error) if str(error) in messages else 'Unclassified validation failure; private details withheld.'


def read_json_bytes(value):
    """Ambiguous duplicate JSON fields must never be silently accepted."""
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, 'Repeated saved JSON field.')
            result[k] = v
        return result
    return json.loads(value, object_pairs_hook=unique)


def both_keys(crypto, backup, envelope, binding):
    result = open_artifact(crypto, envelope, binding)
    require(open_artifact(backup, envelope, binding) == result, 'Saved algorithm recovery differs.')
    return result


class SavedRun:
    """The completion inventory is authenticated before any routing hint is trusted.

    Every later read checks that file's original fingerprint again. Plaintext
    PASSED fields, filenames and counts cannot authorize or replace encrypted data.
    """
    def __init__(self, directory, snapshot):
        self.directory = private_path(directory, True)
        self.snapshot = snapshot
        require(not (directory / 'STOPPED.json').exists(), 'Stopped saved algorithm run refused.')
        path = private_path(directory / 'completion.encrypted.json')
        completion_bytes = path.read_bytes()
        self.completion_sha = hashlib.sha256(completion_bytes).hexdigest()
        envelope = read_json_bytes(completion_bytes)
        completion = both_keys(snapshot['crypto'], snapshot['backup'], envelope, envelope['binding'])
        require(set(completion) == {'report', 'artifacts'}, 'Saved completion shape differs.')
        self.report = report = completion['report']
        require(set(report) == REPORT_KEYS and report['policy'] == RUN and report['status'] == 'PASSED' and
            report['policies'] == POLICIES and report['public_payload_sha256'] == PUBLIC_SHA and
            report['classification'] == 'UNASSESSED', 'Supported saved algorithm run required.')
        for flag in ('accepted_state_claim', 'accepted_authority_claim', 'accepted_contradiction_claim',
                     'governing_instruments_assessed', 'findings_database_written', 'findings_anchored'):
            require(report[flag] is False, 'Saved research claim differs.')
        context = report['context']; validate_context(context)
        require(context['code_revision'] == report['code_revision'] and
            {k: v for k, v in context.items() if k != 'code_revision'} ==
            {k: v for k, v in snapshot['context'].items() if k != 'code_revision'},
            'Saved snapshot version differs.')
        on = date.fromisoformat(report['on'])
        require(on.isoformat() == report['on'], 'Saved cutoff date differs.')
        self.on = on
        self.base = {k: report[k] for k in BASE_KEYS}
        require(envelope['binding'] == dict(self.base, artifact='ALGORITHM_COMPLETION'),
            'Saved completion binding differs.')
        require(report['selection_mode'] in {'ALL_OFFICERS', 'SINGLE_NIC_CANDIDATE'}, 'Saved selection mode differs.')
        expected_officers = 6596 if report['selection_mode'] == 'ALL_OFFICERS' else 1
        for field in ('officers', 'source_claims', 'officer_artifacts', 'action_artifacts', 'authority_action_records'):
            require(type(report[field]) is int and report[field] >= 0, 'Saved count type differs.')
        require(report['officers'] == expected_officers and report['officer_artifacts'] == (expected_officers+99)//100 and
            report['action_artifacts'] == (report['authority_action_records']+99)//100 and
            report['action_artifacts'] <= 9999, 'Saved chunk coverage differs.')
        self.officer_names = ['officers-%03d.encrypted.json' % i for i in range(report['officer_artifacts'])]
        self.action_names = ['actions-%04d.encrypted.json' % i for i in range(report['action_artifacts'])]
        self.inventory = completion['artifacts']
        require(isinstance(self.inventory, dict) and set(self.inventory) == set(self.officer_names+self.action_names) and
            all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in self.inventory.values()),
            'Saved artifact inventory differs.')
        require(set(p.name for p in directory.iterdir()) ==
            set(self.inventory) | {'PASSED.json', 'completion.encrypted.json'}, 'Missing or unexpected saved artifact.')
        for name in self.inventory:
            self.read_bytes(name)
        hint = read_json_bytes(private_path(directory / 'PASSED.json').read_bytes())
        require(hint == dict(report, completion_artifact_sha256=self.completion_sha), 'Plaintext completion differs.')

    def read_bytes(self, name):
        # Names come only from the exact generated inventory, never supplied paths.
        require(name in self.inventory, 'Unknown saved artifact.')
        value = private_path(self.directory / name).read_bytes()
        require(hashlib.sha256(value).hexdigest() == self.inventory[name], 'Saved artifact fingerprint differs.')
        return value

    def chunks(self, kind):
        require(kind in {'officers', 'actions'}, 'Saved chunk kind differs.')
        names = self.officer_names if kind == 'officers' else self.action_names
        artifact = 'OFFICER_ALGORITHM_RESULTS' if kind == 'officers' else 'REPORTED_AUTHORITY_ACTIONS'
        for index, name in enumerate(names):
            envelope = read_json_bytes(self.read_bytes(name))
            value = both_keys(self.snapshot['crypto'], self.snapshot['backup'], envelope,
                dict(self.base, artifact=artifact, chunk=index))
            keys = set(BASE_KEYS) | {'results'} | ({'selection'} if kind == 'officers' else set())
            require(set(value) == keys and all(value[k] == self.base[k] for k in BASE_KEYS),
                'Saved chunk context differs.')
            count = self.report['officers'] if kind == 'officers' else self.report['authority_action_records']
            require(isinstance(value['results'], list) and len(value['results']) == min(100, count-100*index),
                'Saved chunk record coverage differs.')
            yield value

    def selected_uid(self, buckets):
        if self.report['selection_mode'] == 'ALL_OFFICERS':
            return None
        chunk = next(self.chunks('officers'))
        selection = chunk['selection']
        require(isinstance(selection, dict), 'Saved candidate selection missing.')
        uid = selection.get('officer_uid')
        profiles = sorted(raw for raw, item in self.snapshot['catalog'].items()
            if item['filename'] == 'officer_personal_information.csv' and any(
                l['officer_uid'] == uid and l['role'] == 'officer_nic_no' and
                l['state'] == 'CANDIDATE_NOT_ACCEPTED' for l in item['candidate_links']))
        require(uid in buckets and len(profiles) == 1 and
            selection == json_value(asdict(Selection(uid, tuple(profiles)))), 'Saved anchored candidate selection differs.')
        return uid

    def action_catalog(self, uid):
        catalog = self.snapshot['catalog']
        return catalog if uid is None else {raw: item for raw, item in catalog.items()
            if any(l['officer_uid'] == uid for l in item['candidate_links'])}


def iter_actions(catalog, raw_bindings, on):
    """Same order/rules as the original adapter, with at most one source row in memory."""
    for raw, item in sorted(catalog.items()):
        yield from review_actions({raw: item}, raw_bindings, on=on)


def matched_actions(saved, catalog):
    """Each original action is matched to its exact anchored-source replay."""
    expected = iter(iter_actions(catalog, saved.snapshot['bindings']['raw_bindings'], saved.on))
    for chunk in saved.chunks('actions'):
        for result in chunk['results']:
            action = next(expected, None)
            require(action is not None and result == json_value(asdict(action)),
                'Saved action differs from source replay.')
            yield action
    require(next(expected, None) is None, 'Saved action coverage incomplete.')


def replay(saved, *, progress=None):
    """Reproduce the recorded officer/date/action scope, never a new historical query."""
    snapshot = saved.snapshot
    buckets = subject_index(snapshot['manifest'], snapshot['catalog'])
    require(len(buckets) == 6596, 'Complete saved officer universe required.')
    uid = saved.selected_uid(buckets)
    selected = {uid: buckets[uid]} if uid else buckets
    order = iter(sorted(selected)); seen = 0; claims_count = 0
    statuses, comparisons, reasons, actions = (Counter() for _ in range(4))
    for chunk in saved.chunks('officers'):
        require(chunk['selection'] is None if uid is None else chunk['selection']['officer_uid'] == uid,
            'Saved chunk selection differs.')
        for result in chunk['results']:
            officer = next(order, None)
            require(officer is not None and result.get('officer_uid') == officer, 'Saved officer order differs.')
            claims = source_claims(officer, selected[officer], snapshot['bindings']['raw_bindings'])
            claims_count += len(claims)
            projections = reconstruct(officer, claims, on=saved.on, captured_at=snapshot['captured_at'], policy=HISTORY)
            findings = compare_claims(officer, claims, on=saved.on)
            require(result == json_value(dict(officer_uid=officer, history=[asdict(p) for p in projections],
                comparisons=[asdict(f) for f in findings])), 'Saved officer result differs from source replay.')
            statuses.update(p.dimension+':'+p.status for p in projections)
            comparisons.update(f.dimension+':'+f.status for f in findings)
            reasons.update('contradiction:'+r for f in findings for r in f.reasons)
            seen += 1
            if progress and (seen % 500 == 0 or seen == len(selected)):progress('officers', seen, len(selected))
    require(next(order, None) is None, 'Saved officer coverage incomplete.')
    catalog = saved.action_catalog(uid); total = 0
    for action in matched_actions(saved, catalog):
        total += 1
        actions.update((action.action_kind+':'+action.status,))
        reasons.update('authority:'+r for r in action.reasons)
        if progress and total % 10000 == 0:progress('actions', total, saved.report['authority_action_records'])
    expected = dict(source_claims=claims_count, history_status_counts=dict(sorted(statuses.items())),
        comparison_counts=dict(sorted(comparisons.items())), authority_action_counts=dict(sorted(actions.items())),
        reason_counts=dict(sorted(reasons.items())), authority_action_records=total,
        action_inventory_rows=dict(sorted(Counter(v['filename'] for v in catalog.values()).items())),
        authority_route_files=sorted(ROUTES))
    require(all(saved.report[k] == v for k, v in expected.items()), 'Saved aggregate differs from source replay.')
    return dict(policy=POLICY, status='PASSED', mode='SAVED_RESULT_REPLAY', new_audit_executed=False,
        live_readiness_claim=False, algorithm_attempt_id=saved.directory.name,
        completion_artifact_sha256=saved.completion_sha, source_context=saved.report['context'],
        policies=saved.report['policies'], on=saved.report['on'], officers=seen,
        authority_action_records=total, artifact_count=len(saved.inventory), public_payload_sha256=PUBLIC_SHA,
        classification='UNASSESSED', accepted_state_claim=False, accepted_authority_claim=False,
        accepted_contradiction_claim=False)
