"""Replay a completed encrypted result against its exact authenticated snapshot."""
from collections import Counter
from dataclasses import asdict, fields
from datetime import date, datetime
import json
from app.identity.audit_gate import binding as validate_context
from app.identity.historical_reconstruction import POLICY as HISTORY_POLICY, reconstruct, require
from app.identity.historical_source_claims import source_claims
from app.identity.historical_officer_selection import Selection
from app.identity.historical_explanation import explain
from app.identity.reconstruct_history import subject_index


def json_value(value):
    # Exactly the date encoding used by the completed reconstruction runner.
    return json.loads(json.dumps(value, default=lambda v:v.isoformat()))


def replay_saved(summary, payloads, manifest, catalog, bindings, *, evidence_context, public_sha):
    """No new date, new officer choice, live check or audit authorization is issued.

    Callers must authenticate encrypted artifacts with both keys and reproduce
    the original anchored commitments first. This function verifies result content.
    """
    require(set(summary) == {'policy','status','code_revision','officers','on','aggregate',
        'encrypted_artifacts','selection_mode','accepted_state_claim','classification',
        'public_payload_sha256','context'}, 'Saved summary fields differ.')
    require(summary['policy'] == HISTORY_POLICY and summary['status'] == 'PASSED' and
        summary['accepted_state_claim'] is False and summary['classification'] == 'UNASSESSED' and
        summary['public_payload_sha256'] == public_sha, 'Completed unaccepted saved result required.')
    context = summary['context']; validate_context(context)
    require(context['code_revision'] == summary['code_revision'] and
        {k:v for k,v in context.items() if k!='code_revision'} == evidence_context,
        'Saved evidence version differs.')
    mode = summary['selection_mode']
    require(mode in {'SINGLE_NIC_CANDIDATE','ALL_OFFICERS'}, 'Saved selection mode differs.')
    expected_count = 1 if mode == 'SINGLE_NIC_CANDIDATE' else 6596
    require(type(summary['officers']) is int and summary['officers'] == expected_count and
        type(summary['encrypted_artifacts']) is int and summary['encrypted_artifacts'] == (expected_count+99)//100,
        'Saved officer/artifact coverage differs.')
    require(len(payloads) == summary['encrypted_artifacts'], 'Saved encrypted chunks missing.')
    require(isinstance(summary['aggregate'],dict) and all(isinstance(k,str) and type(v) is int and v>0
        for k,v in summary['aggregate'].items()), 'Saved aggregate types differ.')
    on = date.fromisoformat(summary['on'])
    require(on.isoformat() == summary['on'], 'Saved query date differs.')
    captured_at = datetime.fromisoformat(manifest['snapshot']['collection_started_at'])
    buckets = subject_index(manifest,catalog)
    aggregate, seen, explanations, seen_set = Counter(), [], [], set()
    for chunk_index, payload in enumerate(payloads):
        require(set(payload) == {'policy','on','known_snapshot_capture','context','selection','results'} and
            payload['policy'] == HISTORY_POLICY and payload['on'] == on.isoformat() and
            payload['known_snapshot_capture'] == captured_at.isoformat() and payload['context'] == context,
            'Saved result payload context differs.')
        selection = payload['selection']
        if mode == 'SINGLE_NIC_CANDIDATE':
            require(isinstance(selection,dict) and set(selection)=={f.name for f in fields(Selection)},
                'Saved selection fields differ.')
            officer = selection['officer_uid']
            profiles = sorted(raw for raw,row in catalog.items()
                if row['filename']=='officer_personal_information.csv' and any(
                    link['officer_uid']==officer and link['role']=='officer_nic_no' and
                    link['state']=='CANDIDATE_NOT_ACCEPTED' for link in row['candidate_links']))
            require(officer in buckets and len(profiles)==1 and
                selection == json_value(asdict(Selection(officer,tuple(profiles)))),
                'Saved anchored candidate profile differs.')
        else:
            require(selection is None, 'Unexpected selection in full-universe result.')
        expected_size = min(100,expected_count-100*chunk_index)
        require(isinstance(payload['results'],list) and len(payload['results'])==expected_size,
            'Saved chunk coverage differs.')
        for result in payload['results']:
            require(set(result)=={'officer_uid','projections'} and result['officer_uid'] in buckets,
                'Saved result officer differs.')
            officer = result['officer_uid']
            require(officer not in seen_set and (selection is None or officer == selection['officer_uid']),
                'Repeated or wrong selected officer.')
            seen.append(officer); seen_set.add(officer)
            # Replay from authenticated originals, not from potentially changed saved claims.
            values = reconstruct(officer,source_claims(officer,buckets[officer],bindings['raw_bindings']),
                on=on,captured_at=captured_at)
            require(result['projections']==json_value([asdict(v) for v in values]),
                'Saved reconstruction differs from anchored source replay.')
            aggregate.update(v.dimension+':'+v.status for v in values)
            explanations.append(dict(officer_uid=officer,dimensions=[explain(v) for v in values]))
    require(seen==sorted(seen) and len(seen)==expected_count and
        (mode!='ALL_OFFICERS' or set(seen)==set(buckets)) and dict(sorted(aggregate.items()))==summary['aggregate'],
        'Saved result sequence or aggregate differs.')
    return explanations
