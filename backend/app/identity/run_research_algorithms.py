"""Fresh-permit research algorithms; protected candidate outputs, no ledger writes."""
import argparse
from collections import Counter
from dataclasses import asdict
from datetime import date
import json
import hashlib
import os
from pathlib import Path
import subprocess
from uuid import uuid4
from app.identity.algorithm_snapshot import load_verified_snapshot
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.audit_gate import require_audit_permit
from app.identity.evidence_bundle_v2 import seal_artifact
from app.identity.generate_protected_commitments import private_output
from app.identity.historical_officer_selection import read_private_nic,select_from_sql
from app.identity.historical_reconstruction import POLICY as HISTORY_POLICY,require,reconstruct
from app.identity.historical_source_claims import source_claims
from app.identity.reconstruct_history import subject_index
from app.identity.temporal_contradictions import compare_claims,POLICY as COMPARISON_POLICY
from app.identity.reported_authority_actions import review_actions,POLICY as ACTION_POLICY,ROUTES
from app.identity.temporal_authority import POLICY as AUTHORITY_POLICY
from app.intake.registration_receipt import save_receipt
from app.identity.public_anchor_authorization import PUBLIC_SHA

POLICY='ANCHORED_RESEARCH_ALGORITHM_RUN_V1'


def arguments(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('key-file','backup-key-file','commitment-key-file','backup-commitment-key-file',
        'bundle-attempt','binding-attempt','commitment-attempt','audit-gate-attempt','output-root'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--on',type=date.fromisoformat,required=True)
    p.add_argument('--select-nic',action='store_true')
    return p.parse_args(argv)


def guard(snapshot, *, full=False):
    if not full and 'permit_session' in snapshot:
        return snapshot['permit_session'].check(snapshot)
    return require_audit_permit(snapshot['envelope'],snapshot['crypto'],snapshot['backup'],
        snapshot['public'],snapshot['context'])


def json_value(value):
    return json.loads(json.dumps(value,default=lambda v:v.isoformat()))


def protected_result(snapshot, payload, binding):
    # A result cannot be published after the gate expires, including during sealing.
    guard(snapshot)
    result=seal_artifact(snapshot['crypto'],snapshot['backup'],json_value(payload),binding)
    guard(snapshot)
    return result


def main(argv=None):
    args=arguments(argv);attempt=None
    os.umask(0o077)
    try:
        repo=Path(__file__).resolve().parents[3]
        require(not subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip(),
            'Commit reviewed source first.')
        revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
        snapshot=load_verified_snapshot(args,repo,revision);guard(snapshot)
        snapshot['permit_session']=AlgorithmPermit(snapshot)
        catalog=snapshot['catalog'];bindings=snapshot['bindings'];manifest=snapshot['manifest']
        buckets=subject_index(manifest,catalog)
        require(len(buckets)==6596,'Complete anchored officer universe required.')
        selection=None
        if args.select_nic:
            guard(snapshot);nic=read_private_nic()
            try:
                guard(snapshot)
                selection=select_from_sql(snapshot['crypto'],snapshot['backup'],nic,manifest,catalog)
            finally:del nic
            guard(snapshot)
            buckets={selection.officer_uid:buckets[selection.officer_uid]}
            action_catalog={raw:item for raw,item in catalog.items() if any(
                l['officer_uid']==selection.officer_uid for l in item['candidate_links'])}
        else:action_catalog=catalog
        attempt=private_output(args.output_root,repo)/str(uuid4());attempt.mkdir(mode=0o700)
        print('Research algorithm attempt directory:',attempt,flush=True)
        policies=dict(history=HISTORY_POLICY,contradictions=COMPARISON_POLICY,
            authority=AUTHORITY_POLICY,reported_actions=ACTION_POLICY)
        base=dict(policy=POLICY,policies=policies,context=snapshot['context'],on=args.on.isoformat(),
            public_payload_sha256=PUBLIC_SHA,
            selection_mode='SINGLE_NIC_CANDIDATE' if selection else 'ALL_OFFICERS')
        statuses,comparisons,reasons,action_counts=Counter(),Counter(),Counter(),Counter()
        files=0;chunk=[];claims_count=0
        for number,(uid,rows) in enumerate(sorted(buckets.items()),1):
            guard(snapshot)
            claims=source_claims(uid,rows,bindings['raw_bindings']);claims_count+=len(claims)
            # The session checks the exact permit/publication before and after
            # projection. Dates and values remain reports, never accepted state.
            projections=reconstruct(uid,claims,on=args.on,captured_at=snapshot['captured_at'])
            findings=compare_claims(uid,claims,on=args.on);guard(snapshot)
            statuses.update(v.dimension+':'+v.status for v in projections)
            comparisons.update(f.dimension+':'+f.status for f in findings)
            reasons.update('contradiction:'+r for f in findings for r in f.reasons)
            chunk.append(dict(officer_uid=uid,history=[asdict(p) for p in projections],
                comparisons=[asdict(f) for f in findings]))
            if len(chunk)==100 or number==len(buckets):
                binding=dict(base,artifact='OFFICER_ALGORITHM_RESULTS',chunk=files)
                payload=dict(base,selection=asdict(selection) if selection else None,results=chunk)
                save_receipt(protected_result(snapshot,payload,binding),attempt/('officers-%03d.encrypted.json'%files))
                files+=1;chunk=[]
            if number%500==0 or number==len(buckets):print('Algorithm officer progress:',number,'/',len(buckets),flush=True)
        guard(snapshot)
        actions=review_actions(action_catalog,bindings['raw_bindings'],on=args.on);guard(snapshot)
        action_files=0
        for offset in range(0,len(actions),100):
            selected=actions[offset:offset+100]
            action_counts.update(a.action_kind+':'+a.status for a in selected)
            reasons.update('authority:'+r for a in selected for r in a.reasons)
            binding=dict(base,artifact='REPORTED_AUTHORITY_ACTIONS',chunk=action_files)
            payload=dict(base,results=[asdict(a) for a in selected])
            save_receipt(protected_result(snapshot,payload,binding),attempt/('actions-%04d.encrypted.json'%action_files))
            action_files+=1
        guard(snapshot,full=True)
        coverage=Counter(item['filename'] for item in action_catalog.values())
        report=dict(base,status='PASSED',code_revision=revision,officers=len(buckets),source_claims=claims_count,
            history_status_counts=dict(sorted(statuses.items())),comparison_counts=dict(sorted(comparisons.items())),
            authority_action_counts=dict(sorted(action_counts.items())),reason_counts=dict(sorted(reasons.items())),
            authority_action_records=len(actions),officer_artifacts=files,action_artifacts=action_files,
            action_inventory_rows=dict(sorted(coverage.items())),
            authority_route_files=sorted(ROUTES),classification='UNASSESSED',
            accepted_state_claim=False,accepted_authority_claim=False,accepted_contradiction_claim=False,
            governing_instruments_assessed=False,findings_database_written=False,findings_anchored=False)
        # Authenticate the complete output inventory, so later reviewers can
        # detect a removed/replaced chunk rather than trusting a plaintext count.
        inventory={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(attempt.glob('*.encrypted.json'))}
        completion=protected_result(snapshot,dict(report=report,artifacts=inventory),
            dict(base,artifact='ALGORITHM_COMPLETION'))
        completion_path=attempt/'completion.encrypted.json'
        save_receipt(completion,completion_path)
        report['completion_artifact_sha256']=hashlib.sha256(completion_path.read_bytes()).hexdigest()
        guard(snapshot)
        save_receipt(report,attempt/'PASSED.json')
        print('Anchored research algorithm processing: PASSED')
        print(json.dumps(report,sort_keys=True))
        print('Reported evidence and uncertainty preserved. No accepted authority/state, findings database, correction or blockchain writes.')
        return 0
    except Exception as error:
        if attempt is not None:
            save_receipt(dict(policy=POLICY,status='STOPPED',error_type=type(error).__name__,completed=False),attempt/'STOPPED.json')
        print('Research algorithm run stopped:',type(error).__name__)
        print('No completed result issued. Original evidence and private partial artifacts preserved.')
        return 1


if __name__=='__main__':raise SystemExit(main())
